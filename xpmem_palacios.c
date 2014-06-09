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

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>
#include <xpmem_ns.h>

#define XPMEM_VENDOR_ID     0xfff0
#define XPMEM_SUBVENDOR_ID  0xfff0
#define XPMEM_DEVICE_ID     0x100d


/* TODO: what about AMD? */
#define VMCALL      ".byte 0x0F,0x01,0xC1\r\n"
#define MAX_DEVICES     16

struct xpmem_bar_state {
    /* Hypercall ids */
    u32 xpmem_hcall_id;
    u32 xpmem_irq_clear_hcall_id;
    u32 xpmem_read_cmd_hcall_id;

    /* interrupt status */
    u8 irq_handled;

    /* size of command to read from device */
    u64 xpmem_cmd_size;
};


struct xpmem_palacios_state {
    int                       initialized; /* device initialization */
    spinlock_t                lock;        /* state lock */
    unsigned int              irq;         /* irq number */
    xpmem_link_t              link;        /* XPMEM connection link */
    struct xpmem_partition  * part;        /* pointer to XPMEM partition */

    void __iomem            * xpmem_bar;   /* Bar memory */
    struct xpmem_bar_state    bar_state;   /* Bar state */

    struct workqueue_struct * workq;       /* Workq for handling interrupts */
    struct work_struct        worker;      /* Worker struct */
};


static struct xpmem_palacios_state palacios_devs[MAX_DEVICES];
static int dev_off = 0;
DEFINE_SPINLOCK(palacios_lock);




static void
xpmem_hcall(u32                   hcall_id, 
            struct xpmem_cmd_ex * cmd)
{
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(hcall_id), "b"(cmd->type), "c"(cmd)
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
                     u64 buf_size,
                     u64 buffer_pa)
                     
{
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(hcall_id), "b"(buf_size), "c"(buffer_pa)
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
xpmem_work_fn(struct work_struct * work)
{
    struct xpmem_palacios_state * state    = NULL;
    struct xpmem_cmd_ex         * cmd      = NULL;
    u64                           cmd_size = 0;

    state = container_of(work, struct xpmem_palacios_state, worker);
    if (!state->initialized) {
        return;
    }

    /* Read BAR header */
    read_bar(state->xpmem_bar, 
             (void *)&(state->bar_state), 
             sizeof(state->bar_state));

    /* Grab command size */
    cmd_size = state->bar_state.xpmem_cmd_size;

    printk("cmd size: %llu\n", cmd_size);

    cmd = kmalloc(cmd_size, GFP_KERNEL);
    if (!cmd) {
        return;
    }

    /* Read command from BAR */
    xpmem_read_cmd_hcall(
        state->bar_state.xpmem_read_cmd_hcall_id, 
        cmd_size,
        __pa(cmd)
    );

    /* Clear device interrupt flag */
    xpmem_irq_clear_hcall(state->bar_state.xpmem_irq_clear_hcall_id);

    /* Deliver the command */
    xpmem_cmd_deliver(state->part, state->link, cmd);

    kfree(cmd);
}


/*
 * Interrupt handler for Palacios XPMEM device.
 */
static irqreturn_t 
irq_handler(int    irq, 
            void * data)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)data;

    /* Queue work for worker thread */
    queue_work(state->workq, &(state->worker));

    return IRQ_HANDLED;
}




/* Callback for commands being issued by the XPMEM name/forwarding service */
static int
xpmem_cmd_fn(struct xpmem_cmd_ex * cmd, 
             void                * priv_data)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)priv_data;
    unsigned long                 flags = 0;

    if (!state->initialized) {
        return -1;
    }

    spin_lock_irqsave(&(state->lock), flags);
    {
        xpmem_hcall(state->bar_state.xpmem_hcall_id, cmd);
    }
    spin_unlock_irqrestore(&(state->lock), flags);

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
    unsigned long flags    = 0;
    int           ret      = -1;
    int           dev_no   = 0;

    spin_lock_irqsave(&(palacios_lock), flags);
    {
        dev_no = dev_off;
    }
    spin_unlock_irqrestore(&(palacios_lock), flags);

    palacios_state = &(palacios_devs[dev_no]);

    if (dev->vendor != XPMEM_VENDOR_ID) {
        return ret;
    }

    if (dev->device != XPMEM_DEVICE_ID) {
        return ret;
    }

    /* Enable PCI device */
    if ((ret = pci_enable_device(dev))) {
        printk("Failed to enable Palacios XPMEM PCI device\n");
        goto err;
    }

    /* Check if interrupts are enabled */
    if (dev->irq <= 0) {
        printk("Palacios XPMEM device is not interrupt-enabled\n");
        ret = -1;
        goto err;
    }

    /* Map BAR 0 */
    bar_size                  = pci_resource_len(dev, 0);
    palacios_state->xpmem_bar = pci_iomap(dev, 0, bar_size); 

    if (!palacios_state->xpmem_bar) {
        printk("Failed to map Palacios XPMEM BAR 0 memory\n");
        ret = -1;
        goto err;
    }

    /* Read Palacios hypercall id from BAR 0 */
    read_bar(palacios_state->xpmem_bar, 
             (void *)&(palacios_state->bar_state), 
             sizeof(palacios_state->bar_state));

    if ( (palacios_state->bar_state.xpmem_hcall_id           == 0) ||
         (palacios_state->bar_state.xpmem_irq_clear_hcall_id == 0) ||
         (palacios_state->bar_state.xpmem_read_cmd_hcall_id  == 0))
    {
        printk("Palacios XPMEM hypercall(s) not available\n");
        ret = -1;
        goto err_unmap;
    }

    {
        char buf[16];

        memset(buf, 0, 16);
        snprintf(buf, 16, "xpmem_%d", dev_no);

        /* Register IRQ handler */
        if ((palacios_state->irq = request_irq(dev->irq, irq_handler, IRQF_SHARED, buf, palacios_state))) {
            printk("Failed to request IRQ for Palacios XPMEM device (irq = %d)\n", dev->irq);
            goto err_unmap;
        }
    }

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


    spin_lock_init(&(palacios_state->lock));
    palacios_state->workq = create_singlethread_workqueue("xpmem-work");
    INIT_WORK(&(palacios_state->worker), xpmem_work_fn);

    palacios_state->initialized = 1;
    spin_lock_irqsave(&(palacios_lock), flags);
    {
        ++dev_off;
    }
    spin_unlock_irqrestore(&(palacios_lock), flags);

    printk("Palacios XPMEM PCI device enabled\n");
    return 0;

err_unmap:
    pci_iounmap(dev, palacios_state->xpmem_bar);
err:
    printk("Palacios XPMEM device initialization failed\n");
    return ret;
}


static void 
xpmem_remove_driver(struct pci_dev * dev)
{
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
xpmem_palacios_init(struct xpmem_partition * part) {
    struct xpmem_palacios_state * state  = NULL;
    unsigned long                 flags  = 0;
    int                           ret    = 0;
    int                           dev_no = 0;

    spin_lock_irqsave(&(palacios_lock), flags);
    {
        dev_no = dev_off;
        state = &(palacios_devs[dev_no]);
    }
    spin_unlock_irqrestore(&(palacios_lock), flags);

    memset(state, 0, sizeof(struct xpmem_palacios_state));

    /* Save partition pointer */
    state->part = part;

    /* Save pointer to this state */
    part->palacios_state = state;


    /* Register PCI driver */
    ret = pci_register_driver(&xpmem_driver);

    if (ret != 0) {
        printk(KERN_ERR "Failed to register Palacios XPMEM driver\n");
    }

    return ret;
}

int
xpmem_palacios_deinit(struct xpmem_partition * part)
{
    pci_unregister_driver(&xpmem_driver);

    {
        unsigned long flags  = 0;
        int           dev_no = 0;
        int           i      = 0;

        spin_lock_irqsave(&palacios_lock, flags);
        {
            dev_no = dev_off;
        }
        spin_unlock_irqrestore(&palacios_lock, flags);

        for (i = 0; i < dev_no; i++) {
            struct xpmem_palacios_state * state = &(palacios_devs[i]);
            if (!state)
                continue;

            free_irq(state->irq, state);
        }
    }

    printk("XPMEM palacios deinited\n");

    return 0;
}



MODULE_DEVICE_TABLE(pci, xpmem_ids);
