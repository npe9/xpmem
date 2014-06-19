/*
 * XPMEM extensions for Palacios virtual machines
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>
#include <xpmem_iface.h>

#define XPMEM_VENDOR_ID     0xfff0
#define XPMEM_SUBVENDOR_ID  0xfff0
#define XPMEM_DEVICE_ID     0x100d


/* TODO: what about AMD? */
#define VMCALL      ".byte 0x0F,0x01,0xC1\r\n"
#define MAX_DEVICES     16

struct xpmem_bar_state {
    /* Hypercall ids */
    u32 xpmem_hcall_id;
    u32 xpmem_detach_hcall_id;
    u32 xpmem_irq_clear_hcall_id;
    u32 xpmem_read_cmd_hcall_id;

    /* interrupt status */
    u8 irq_handled;

    /* size of command to read from device */
    u64 xpmem_cmd_size;

    /* size of pfn list to read from device */
    u64 xpmem_pfn_size;
};


struct xpmem_palacios_state {
    void __iomem                 * xpmem_bar;   /* Bar memory */
    struct xpmem_bar_state         bar_state;   /* Bar state */
    struct mutex                   mutex;       /* mutex for BAR hypercall access */

    unsigned int                   irq;         /* device irq number */
    struct work_struct             work;        /* work struct */

    int                            connected;   /* device connectivity */
    atomic_t                       num_cmds;    /* number of cmd deliveries being processed */ 

    /* XPMEM kernel interface */
    xpmem_link_t                   link;        /* XPMEM connection link */
    struct xpmem_partition_state * part;        /* pointer to XPMEM partition */
};


static struct xpmem_palacios_state palacios_devs[MAX_DEVICES];
atomic_t dev_off = ATOMIC_INIT(0);




static void
xpmem_hcall(u32                   hcall_id, 
            struct xpmem_cmd_ex * cmd)
{
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(hcall_id), "b"(cmd)
    );
}

static void
xpmem_detach_hcall(u32 hcall_id,
                   u64 vaddr)
{
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(hcall_id), "b"(vaddr)
    );
}


static void
xpmem_irq_clear_hcall(u32 hcall_id)
{
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(hcall_id)
    );
}

static void
xpmem_read_cmd_hcall(u32 hcall_id,
                     u64 cmd_va,
                     u64 pfn_va)
{
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(hcall_id), "b"(cmd_va), "c"(pfn_va)
    );
}



static void
read_bar(void __iomem * xpmem_bar, 
         void         * dst, 
         u64            len)
{
    u32 i = 0;
    for (i = 0; i < len; i++) {
        *((u8 *)(dst + i)) = ioread8(xpmem_bar + i);
    }
}


/* 
 * Work queue for interrupt processing.
 *
 * xpmem_cmd_deliver could sleep, so we can't do this directly from the
 * interrupt handler
 */
void
__xpmem_work_fn(struct xpmem_palacios_state * state)
{
    struct xpmem_cmd_ex         * cmd      = NULL;
    u64                           cmd_size = 0;
    u64                           pfn_size = 0;
    void                        * pfn_buf  = NULL;

    /* Read BAR header */
    read_bar(state->xpmem_bar, 
             (void *)&(state->bar_state), 
             sizeof(state->bar_state));

    /* Grab size fields */
    cmd_size = state->bar_state.xpmem_cmd_size;
    pfn_size = state->bar_state.xpmem_pfn_size;

    /* Could be a spurious IRQ */
    if (cmd_size != sizeof(struct xpmem_cmd_ex)) {
        return;
    }

    cmd = kmalloc(sizeof(struct xpmem_cmd_ex), GFP_KERNEL);
    if (!cmd) {
        return;
    }

    if (pfn_size > 0) {
        pfn_buf = kmalloc(pfn_size, GFP_KERNEL);
        if (!pfn_buf) {
            kfree(cmd);
            return;
        }
    }

    /* Read command from BAR */
    xpmem_read_cmd_hcall(
        state->bar_state.xpmem_read_cmd_hcall_id, 
        (u64)(void *)cmd,
        (u64)pfn_buf
    );

    /* Save the pfn list */
    if (pfn_size > 0) {
        cmd->attach.pfns = kmalloc(pfn_size, GFP_KERNEL);
        if (!cmd->attach.pfns) {
            kfree(pfn_buf);
            kfree(cmd);
            return;
        }

        memcpy(cmd->attach.pfns, pfn_buf, pfn_size);
        kfree(pfn_buf);
    }

    /* Clear device interrupt flag */
    xpmem_irq_clear_hcall(state->bar_state.xpmem_irq_clear_hcall_id);

    /* Deliver the command */
    xpmem_cmd_deliver(state->part, state->link, cmd);

    /* Free up */
    kfree(cmd);

    if (pfn_size > 0) {
        kfree(cmd->attach.pfns);
    }

}

void 
xpmem_work_fn(struct work_struct * work)
{
    struct xpmem_palacios_state * state = NULL;

    state = container_of(work, struct xpmem_palacios_state, work);

    atomic_inc(&(state->num_cmds));
    {
        if (state->connected) {
            __xpmem_work_fn(state);
        }
    }
    atomic_dec(&(state->num_cmds));
}


/*
 * Interrupt handler for Palacios XPMEM device.
 */
static irqreturn_t 
irq_handler(int    irq, 
            void * data)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)data;

    if (!state->connected) {
        return IRQ_HANDLED;
    }

    /* Schedule work */
    schedule_work(&(state->work));

    return IRQ_HANDLED;
}




/* Callback for commands being issued by the XPMEM name/forwarding service */
static int
xpmem_cmd_fn(struct xpmem_cmd_ex * cmd, 
             void                * priv_data)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)priv_data;

    if (!state->connected) {
        return -1;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        xpmem_hcall(state->bar_state.xpmem_hcall_id, cmd);
    }

    mutex_unlock(&(state->mutex));

    return 0;
}



static const struct pci_device_id 
xpmem_ids[] =
{
    { PCI_DEVICE(XPMEM_VENDOR_ID, XPMEM_DEVICE_ID) },
    { },
};

static int 
xpmem_probe_driver(struct pci_dev             * dev, 
                   const struct pci_device_id * id)                   
{
    struct xpmem_palacios_state * palacios_state = NULL;

    unsigned long bar_size = 0;
    int           dev_no   = 0;

    /* Index into global list */
    dev_no = atomic_read(&dev_off);

    /* Remember the state with the driver's private data field */
    palacios_state = &(palacios_devs[dev_no]);
    pci_set_drvdata(dev, (void *)palacios_state);

    if (dev->vendor != XPMEM_VENDOR_ID) {
        return -1;
    }

    if (dev->device != XPMEM_DEVICE_ID) {
        return -1;
    }

    /* Enable PCI device */
    if (pci_enable_device(dev)) {
        printk("Failed to enable Palacios XPMEM PCI device\n");
        goto err;
    }

    /* Check if interrupts are enabled */
    if (dev->irq <= 0) {
        printk("Palacios XPMEM device is not interrupt-enabled\n");
        goto err;
    }

    /* Map BAR 0 */
    bar_size                  = pci_resource_len(dev, 0);
    palacios_state->xpmem_bar = pci_iomap(dev, 0, bar_size); 

    if (!palacios_state->xpmem_bar) {
        printk("Failed to map Palacios XPMEM BAR 0 memory\n");
        goto err;
    }

    /* Read Palacios hypercall ids from BAR 0 */
    read_bar(palacios_state->xpmem_bar, 
             (void *)&(palacios_state->bar_state), 
             sizeof(palacios_state->bar_state));

    if ( (palacios_state->bar_state.xpmem_hcall_id           == 0) ||
         (palacios_state->bar_state.xpmem_detach_hcall_id    == 0) ||
         (palacios_state->bar_state.xpmem_irq_clear_hcall_id == 0) ||
         (palacios_state->bar_state.xpmem_read_cmd_hcall_id  == 0))
    {
        printk("Palacios XPMEM hypercall(s) not available\n");
        goto err_unmap;
    }


    /* Initialize the rest of the state */
    atomic_set(&(palacios_state->num_cmds), 0);
    mutex_init(&(palacios_state->mutex));
    INIT_WORK(&(palacios_state->work), xpmem_work_fn);

    atomic_inc(&dev_off);
    palacios_state->connected = 1;

    /* Add connection to name/forwarding service */
    palacios_state->link = xpmem_add_connection(
            palacios_state->part, 
            XPMEM_CONN_REMOTE,
            xpmem_cmd_fn, 
            (void *)palacios_state);

    if (palacios_state->link <= 0) {
        printk(KERN_ERR "Failed to register Palacios XPMEM interface with"
            " name/forwarding service\n");
        goto err_unmap;
    }

    {
        char buf[16];

        memset(buf, 0, 16);
        snprintf(buf, 16, "xpmem_%d", dev_no);

        /* Register IRQ handler */
        if (request_irq(dev->irq, irq_handler, IRQF_SHARED, buf, palacios_state) != 0) {
            printk("Failed to request IRQ for Palacios XPMEM device (irq = %d)\n", dev->irq);
            goto err_remove;
        }

        palacios_state->irq = dev->irq;
    }

    /* Signal device initialization by clearing irq status */
    xpmem_irq_clear_hcall(palacios_state->bar_state.xpmem_irq_clear_hcall_id);

    printk("XPMEM Palacios PCI device enabled\n");
    return 0;

err_remove:
    xpmem_remove_connection(palacios_state->part, palacios_state->link);

err_unmap:
    pci_iounmap(dev, palacios_state->xpmem_bar);

err:
    printk("XPMEM: Palacios PCI device initialization failed\n");
    return -1;
}


static void 
xpmem_remove_driver(struct pci_dev * dev)
{
    struct xpmem_palacios_state * state = NULL;

    /* Get the index with the driver's private data field */
    state = (struct xpmem_palacios_state *)pci_get_drvdata(dev);

    /* No longer connected */
    state->connected = 0;

    /* Wait until all ongoing deliveries finish */
    while (atomic_read(&(state->num_cmds)) > 0) {
        schedule();
        mb();
    }

    /* Free the irq */
    free_irq(state->irq, state);

    /* Remove the xpmem connection */
    xpmem_remove_connection(state->part, state->link);

    printk("XPMEM Palacios PCI device disabled\n");
}


static struct pci_driver
xpmem_driver =
{
    .name       = "pci_xpmem",
    .id_table   = xpmem_ids,
    .probe      = xpmem_probe_driver,
    .remove     = xpmem_remove_driver,
};



int
xpmem_palacios_init(struct xpmem_partition_state * part) {
    struct xpmem_palacios_state * state  = NULL;
    int                           ret    = 0;
    int                           dev_no = 0;

    /* Index into global list */
    dev_no = atomic_read(&dev_off);

    /* Clear the state */
    state = &(palacios_devs[dev_no]);
    memset(state, 0, sizeof(struct xpmem_palacios_state));

    state->part         = part;
    part->palacios_priv = state;

    /* Register PCI driver */
    ret = pci_register_driver(&xpmem_driver);

    if (ret != 0) {
        printk(KERN_ERR "Failed to register Palacios XPMEM driver\n");
    }

    return ret;
}

int
xpmem_palacios_deinit(struct xpmem_partition_state * part)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)part->palacios_priv;

    if (!state) {
        return 0;
    }

    pci_unregister_driver(&xpmem_driver);

    part->palacios_priv = NULL;

    return 0;
}


int
xpmem_palacios_detach_paddr(struct xpmem_partition_state * part, 
                            u64                            paddr)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)part->palacios_priv;

    if (!state) {
        return -1;
    }

    /* If we're not in a VM */
    if (state->connected == 0) {
        return 0;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        xpmem_detach_hcall(state->bar_state.xpmem_detach_hcall_id, paddr);
    }

    mutex_unlock(&(state->mutex));

    return 0;

}

MODULE_DEVICE_TABLE(pci, xpmem_ids);
