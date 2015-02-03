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
#include <linux/kref.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_partition.h>
#include <xpmem_extended.h>
#include <xpmem_iface.h>

#define XPMEM_VENDOR_ID     0xfff0
#define XPMEM_SUBVENDOR_ID  0xfff0
#define XPMEM_DEVICE_ID     0x100d


#define VMCALL      ".byte 0x0F,0x01,0xC1\r"
#define VMMCALL     ".byte 0x0F,0x01,0xD9\r"
#define MAX_DEVICES     16

static int vmcall = 0;

struct xpmem_bar_state {
    /* Hypercall ids */
    u32 xpmem_hcall_id;
    u32 xpmem_detach_hcall_id;
    u32 xpmem_irq_clear_hcall_id;
    u32 xpmem_read_cmd_hcall_id;

    /* vmx capable */
    u8 vmx_capable;

    /* svm capable */
    u8 svm_capable;

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

    unsigned int                   irq;         /* device irq number */
    struct work_struct             work;        /* work struct */

    xpmem_link_t                   link;        /* xpmem connection link */
    struct xpmem_partition       * partition;   /* pointer to partition */ 
};


static struct xpmem_palacios_state palacios_devs[MAX_DEVICES];
atomic_t dev_off = ATOMIC_INIT(0);


static void
xpmem_hcall(u32                   hcall_id, 
            struct xpmem_cmd_ex * cmd)
{
    unsigned long long ret = 0;

    if (vmcall) {
        __asm__ volatile(
            VMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(cmd)
        );
    } else {
        __asm__ volatile(
            VMMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(cmd)
        );
    }
}

static void
xpmem_detach_hcall(u32 hcall_id,
                   u64 vaddr)
{
    unsigned long long ret = 0;

    if (vmcall) {
        __asm__ volatile(
            VMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(vaddr)
        );
    } else {
        __asm__ volatile(
            VMMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(vaddr)
        );
    }
}


static void
xpmem_irq_clear_hcall(u32 hcall_id)
{
    unsigned long long ret = 0;

    if (vmcall) {
        __asm__ volatile(
            VMCALL
            : "=a"(ret)
            : "a"(hcall_id)
        );
    } else {
        __asm__ volatile(
            VMMCALL
            : "=a"(ret)
            : "a"(hcall_id)
        );
    }
}

static void
xpmem_read_cmd_hcall(u32 hcall_id,
                     u64 cmd_va,
                     u64 pfn_va)
{
    unsigned long long ret = 0;

    if (vmcall) {
        __asm__ volatile(
            VMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(cmd_va), "c"(pfn_va)
        );
    } else {
        __asm__ volatile(
            VMMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(cmd_va), "c"(pfn_va)
        );
    }
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
    u64   cmd_size = 0;
    u64   pfn_size = 0;
    u32 * pfn_buf  = NULL;

    struct xpmem_cmd_ex cmd;

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

    if (pfn_size > 0) {
        pfn_buf = kmalloc(pfn_size, GFP_KERNEL);
        if (!pfn_buf) {
            return;
        }
    }

    /* Read command from BAR */
    xpmem_read_cmd_hcall(
        state->bar_state.xpmem_read_cmd_hcall_id, 
        (u64)(void *)&cmd,
        (u64)__pa(pfn_buf)
    );

    /* Save pointer to pfn list */
    if (pfn_size > 0) {
        cmd.attach.pfn_pa = (u64)__pa(pfn_buf);
    }

    /* Clear device interrupt flag */
    xpmem_irq_clear_hcall(state->bar_state.xpmem_irq_clear_hcall_id);

    /* Deliver the command */
    xpmem_cmd_deliver(state->link, &cmd);
}

void 
xpmem_work_fn(struct work_struct * work)
{
    struct xpmem_palacios_state * state = NULL;

    state = container_of(work, struct xpmem_palacios_state, work);

    __xpmem_work_fn(state);

    xpmem_put_link_data(state->link);
}


/*
 * Interrupt handler for Palacios XPMEM device.
 */
static irqreturn_t 
irq_handler(int    irq, 
            void * data)
{
    /* We can access the state directly, because the conn will not go away as long as the
     * irq handler is still active. However, we need an additional ref to protect the work
     * queue which we are about to schedule
     */
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)data; 

    (void)xpmem_get_link_data(state->link);

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
    u32                         * pfns  = NULL;

    xpmem_hcall(
        state->bar_state.xpmem_hcall_id, 
        cmd
    );

    /* Free list allocated on attachment interrupt */
    if (cmd->type == XPMEM_ATTACH_COMPLETE) {
        pfns = __va(cmd->attach.pfn_pa);
        kfree(pfns);
    }

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

    if (dev->vendor != XPMEM_VENDOR_ID) {
        return -1;
    }

    if (dev->device != XPMEM_DEVICE_ID) {
        return -1;
    }

    /* Index into global list */
    dev_no         = atomic_read(&dev_off);
    palacios_state = &(palacios_devs[dev_no]);

    /* Remember the state with the driver's private data field */
    pci_set_drvdata(dev, (void *)palacios_state);

    /* Enable PCI device */
    if (pci_enable_device(dev)) {
        XPMEM_ERR("Failed to enable Palacios XPMEM PCI device");
        goto err;
    }

    /* Check if interrupts are enabled */
    if (dev->irq <= 0) {
        XPMEM_ERR("Palacios device is not interrupt-enabled");
        goto err;
    }

    /* Map BAR 0 */
    bar_size                  = pci_resource_len(dev, 0);
    palacios_state->xpmem_bar = pci_iomap(dev, 0, bar_size); 

    if (!palacios_state->xpmem_bar) {
        XPMEM_ERR("Failed to map Palacios device BAR 0 memory");
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
        XPMEM_ERR("Palacios hypercall(s) not available");
        goto err_unmap;
    }

    if ( (palacios_state->bar_state.vmx_capable == 0) &&
         (palacios_state->bar_state.svm_capable == 0))
    {
        XPMEM_ERR("Palacios hypercall(s) not functional");
        goto err_unmap;
    }

    if (palacios_state->bar_state.vmx_capable > 0) {
        vmcall = 1;
    } else {
        vmcall = 0;
    }

    /* Initialize the rest of the state */
    INIT_WORK(&(palacios_state->work), xpmem_work_fn);
    atomic_inc(&dev_off);

    /* Add connection to name/forwarding service */
    palacios_state->link = xpmem_add_connection(
            XPMEM_CONN_REMOTE,
            (void *)palacios_state,
            xpmem_cmd_fn, 
            NULL,
            NULL);

    if (palacios_state->link <= 0) {
        XPMEM_ERR("Failed to register Palacios interface with name/forwarding service");
        goto err_unmap;
    }

    /* Save vmm link */
    palacios_state->partition->vmm_link = palacios_state->link;

    {
        char buf[16];

        memset(buf, 0, 16);
        snprintf(buf, 16, "xpmem_%d", dev_no);

        /* Register IRQ handler */
        if (request_irq(dev->irq, irq_handler, IRQF_SHARED, buf, (void *)palacios_state) != 0) {
            XPMEM_ERR("Failed to request IRQ for Palacios device (irq = %d)", dev->irq);
            goto err_remove;
        }

        palacios_state->irq = dev->irq;
    }

    /* Signal device initialization by clearing irq status */
    xpmem_irq_clear_hcall(palacios_state->bar_state.xpmem_irq_clear_hcall_id);

    printk("XPMEM: Palacios PCI device enabled\n");
    return 0;

err_remove:
    xpmem_remove_connection(palacios_state->link);

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

    /* Free irq */
    free_irq(state->irq, (void *)state);
    
    /* Disable the pci device */
    pci_disable_device(dev);

    printk("XPMEM: Palacios PCI device disabled\n");
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
xpmem_palacios_detach_paddr(xpmem_link_t link, 
                            u64          paddr)
{
    struct xpmem_palacios_state * state = xpmem_get_link_data(link);
    if (state == NULL) {
        return -1;
    }

    xpmem_detach_hcall(state->bar_state.xpmem_detach_hcall_id, paddr);

    xpmem_put_link_data(state->link);

    return 0;

}


int
xpmem_request_irq(irqreturn_t (*callback)(int, void *),
                  void      *  priv_data)
{
    int lirq  = 0;
//    int                           hirq  = 0;

    lirq = xpmem_request_local_irq(callback, priv_data);
    if (lirq <= 0) {
        return -1;
    }

    /* TODO: store lirq somewhere */

    return lirq;
}

int
xpmem_release_irq(int                            irq,
                  void                         * priv_data)
{
    return 0;
}


int
xpmem_palacios_init(struct xpmem_partition * partition) {
    struct xpmem_palacios_state * state  = NULL;
    int                           ret    = 0;
    int                           dev_no = 0;

    /* Index into global list */
    dev_no = atomic_read(&dev_off);

    /* Clear the state */
    state = &(palacios_devs[dev_no]);
    memset(state, 0, sizeof(struct xpmem_palacios_state));

    state->partition = partition;

    /* Register PCI driver */
    ret = pci_register_driver(&xpmem_driver);

    if (ret != 0) {
        XPMEM_ERR("Failed to register Palacios PCI device driver");
    }

    return ret;
}

int
xpmem_palacios_deinit(xpmem_link_t link)
{
    pci_unregister_driver(&xpmem_driver);

    /* Remove the xpmem connection */
    if (link > 0) {
        xpmem_remove_connection(link);
    }

    return 0;
}



MODULE_DEVICE_TABLE(pci, xpmem_ids);
