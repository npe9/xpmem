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
    u32 xpmem_read_apicid_hcall_id;
    u32 xpmem_request_irq_hcall_id;
    u32 xpmem_release_irq_hcall_id;
    u32 xpmem_deliver_irq_hcall_id;

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
    void __iomem         * xpmem_bar;   /* Bar memory */
    struct xpmem_bar_state bar_state;   /* Bar state */

    unsigned int           irq;         /* device irq number */
    struct work_struct     work;        /* work struct */

    xpmem_link_t           link;        /* xpmem connection link */
};

static xpmem_link_t vmm_link = 0;
static DEFINE_SPINLOCK(vmm_link_lock);

xpmem_link_t
xpmem_get_host_link(void)
{
    xpmem_link_t link;

    spin_lock(&vmm_link_lock);
    link = vmm_link;
    spin_unlock(&vmm_link_lock);

    return link;
}


static unsigned long long
do_xpmem_hcall(u32       hcall_id,
               uintptr_t arg1,
               uintptr_t arg2,
               uintptr_t arg3)
{
    unsigned long long ret = 0;

    if (vmcall) {
        __asm__ volatile(
            VMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(arg1), "c"(arg2), "d"(arg3)
        );
    } else {
        __asm__ volatile(
            VMMCALL
            : "=a"(ret)
            : "a"(hcall_id), "b"(arg1), "c"(arg2), "d"(arg3)
        );
    }

    return ret;
}

static void
xpmem_cmd_hcall(struct xpmem_palacios_state * state, 
                struct xpmem_cmd_ex         * cmd)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_hcall_id, (uintptr_t)cmd, 0, 0);
}

static void
xpmem_detach_hcall(struct xpmem_palacios_state * state,
                   u64                           paddr)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_detach_hcall_id, (uintptr_t)paddr, 0, 0);
}

static void
xpmem_irq_clear_hcall(struct xpmem_palacios_state * state)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_irq_clear_hcall_id, 0, 0, 0);
}

static void
xpmem_read_cmd_hcall(struct xpmem_palacios_state * state,
                     u64 cmd_va,
                     u64 pfn_va)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_read_cmd_hcall_id, (uintptr_t)cmd_va, (uintptr_t)pfn_va, 0);
}

static void
xpmem_read_apicid_hcall(struct xpmem_palacios_state * state,
                        unsigned int                  logical_cpu,
                        int                         * host_apicid_va)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_read_apicid_hcall_id, (uintptr_t)logical_cpu, (uintptr_t)host_apicid_va, 0);
}

static void
xpmem_request_irq_hcall(struct xpmem_palacios_state * state,
                        int                           guest_vector,
                        int                         * host_vector_va)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_request_irq_hcall_id, (uintptr_t)guest_vector, (uintptr_t)host_vector_va, 0);
}

static void
xpmem_release_irq_hcall(struct xpmem_palacios_state * state,
                        int                           host_vector)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_release_irq_hcall_id, host_vector, 0, 0);
}

static void
xpmem_deliver_irq_hcall(struct xpmem_palacios_state * state,
                        xpmem_domid_t                 segid,
                        xpmem_sigid_t                 sigid,
                        xpmem_domid_t                 domid)
{
    (void)do_xpmem_hcall(state->bar_state.xpmem_deliver_irq_hcall_id, (uintptr_t)segid, (uintptr_t)sigid, (uintptr_t)domid);
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
        state, 
        (u64)(void *)&cmd,
        (u64)__pa(pfn_buf)
    );

    /* Save pointer to pfn list */
    if (pfn_size > 0) {
        cmd.attach.pfn_pa = (u64)__pa(pfn_buf);
    }

    /* Clear device interrupt flag */
    xpmem_irq_clear_hcall(state);

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

    /* Invoke hypercall */
    xpmem_cmd_hcall(state, cmd);

    /* Free list allocated on attachment interrupt */
    if (cmd->type == XPMEM_ATTACH_COMPLETE) {
        pfns = __va(cmd->attach.pfn_pa);
        kfree(pfns);
    }

    return 0;
}

/* Callback for signals issued to a segid */
static int
xpmem_segid_fn(xpmem_segid_t segid,
               xpmem_sigid_t sigid,
               xpmem_domid_t domid,
               void        * priv_data)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)priv_data;

    /* Invoke hypercall */
    xpmem_deliver_irq_hcall(state, segid, sigid, domid);

    return 0;
}

static void
xpmem_kill_fn(void * priv_data)
{
    struct xpmem_palacios_state * state = (struct xpmem_palacios_state *)priv_data;

    /* Remove vmm link */
    spin_lock(&vmm_link_lock);
    vmm_link = 0;
    spin_unlock(&vmm_link_lock);

    kfree(state);
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
    struct xpmem_palacios_state * state    = NULL;
    unsigned long                 bar_size = 0;

    if (dev->vendor != XPMEM_VENDOR_ID)
        return -1;

    if (dev->device != XPMEM_DEVICE_ID)
        return -1;

    state = kzalloc(sizeof(struct xpmem_palacios_state), GFP_KERNEL);
    if (state == NULL)
        return -ENOMEM;

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
    bar_size         = pci_resource_len(dev, 0);
    state->xpmem_bar = pci_iomap(dev, 0, bar_size); 

    if (state->xpmem_bar == NULL) {
        XPMEM_ERR("Failed to map Palacios device BAR 0 memory");
        goto err;
    }

    /* Read Palacios hypercall ids from BAR 0 */
    read_bar(state->xpmem_bar, 
             (void *)&(state->bar_state), 
             sizeof(state->bar_state));

    if ( (state->bar_state.xpmem_hcall_id              == 0) ||
         (state->bar_state.xpmem_detach_hcall_id       == 0) ||
         (state->bar_state.xpmem_irq_clear_hcall_id    == 0) ||
         (state->bar_state.xpmem_read_cmd_hcall_id     == 0) ||
         (state->bar_state.xpmem_read_apicid_hcall_id  == 0) ||
         (state->bar_state.xpmem_request_irq_hcall_id  == 0) ||
         (state->bar_state.xpmem_release_irq_hcall_id  == 0) ||
         (state->bar_state.xpmem_deliver_irq_hcall_id  == 0)
       )
    {
        XPMEM_ERR("Palacios hypercall(s) not available");
        goto err_unmap;
    }

    if ( (state->bar_state.vmx_capable == 0) &&
         (state->bar_state.svm_capable == 0))
    {
        XPMEM_ERR("Palacios hypercall(s) not functional");
        goto err_unmap;
    }

    if (state->bar_state.vmx_capable > 0) {
        vmcall = 1;
    } else {
        vmcall = 0;
    }

    /* Initialize the rest of the state */
    INIT_WORK(&(state->work), xpmem_work_fn);

    /* Add connection to name/forwarding service */
    state->link = xpmem_add_connection(
            (void *)state,
            xpmem_cmd_fn, 
            xpmem_segid_fn,
            xpmem_kill_fn);

    if (state->link <= 0) {
        XPMEM_ERR("Failed to register Palacios interface with name/forwarding service");
        goto err_unmap;
    }

    /* Register IRQ handler */
    if (request_irq(dev->irq, irq_handler, IRQF_SHARED, "xpmem", (void *)state) != 0) {
        XPMEM_ERR("Failed to request IRQ for Palacios device (irq = %d)", dev->irq);
        goto err_remove;
    }

    state->irq = dev->irq;

    /* Save vmm link */
    spin_lock(&vmm_link_lock);
    vmm_link = state->link;
    spin_unlock(&vmm_link_lock);

    /* Remember the state with the driver's private data field */
    pci_set_drvdata(dev, (void *)state);

    /* Signal device initialization by clearing irq status */
    xpmem_irq_clear_hcall(state);

    printk("XPMEM: Palacios PCI device enabled\n");
    return 0;

err_remove:
    xpmem_remove_connection(state->link);

err_unmap:
    pci_iounmap(dev, state->xpmem_bar);

err:
    printk("XPMEM: Palacios PCI device initialization failed\n");
    kfree(state);
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
xpmem_detach_host_paddr(u64 paddr)
{
    struct xpmem_palacios_state * state = NULL;
    xpmem_link_t                  link  = xpmem_get_host_link();

    /* We might be in the host already */
    if (link == 0)
        return 0;

    state = xpmem_get_link_data(link);
    if (state == NULL)
        return -1;

    xpmem_detach_hcall(state, paddr);

    xpmem_put_link_data(state->link);

    return 0;

}


int
xpmem_request_host_vector(int vector)
{
    struct xpmem_palacios_state * state       = NULL;
    xpmem_link_t                  link        = xpmem_get_host_link();
    int                           host_vector = vector;

    if (link == 0)
        return host_vector;

    state = xpmem_get_link_data(link);
    if (state == NULL)
        return -EBUSY;

    xpmem_request_irq_hcall(state, vector, &host_vector);
    if (host_vector < 0)
        XPMEM_ERR("Cannot allocate host IDT vector");

    xpmem_put_link_data(link);
    return host_vector;
}

void
xpmem_release_host_vector(int host_vector)
{
    struct xpmem_palacios_state * state = NULL;
    xpmem_link_t                  link  = xpmem_get_host_link();

    if (link == 0)
        return;

    state = xpmem_get_link_data(link);
    if (state == NULL) {
        XPMEM_ERR("Leaking Host IDT vector %d", host_vector);
        return;
    }

    xpmem_release_irq_hcall(state, host_vector);
    xpmem_put_link_data(link);
}

int
xpmem_get_host_apic_id(int cpu)
{
    struct xpmem_palacios_state * state   = NULL;
    xpmem_link_t                  link    = xpmem_get_host_link();
    int                           apic_id = -1;

    if (link == 0)
        return apic->cpu_present_to_apicid(cpu);

    state = xpmem_get_link_data(link);
    if (state == NULL)
        return -EBUSY;

    xpmem_read_apicid_hcall(state, cpu, &apic_id);
    if (apic_id < 0)
        XPMEM_ERR("Cannot read host apic id for cpu %d", cpu);

    xpmem_put_link_data(link);
    return apic_id;
}

int
xpmem_palacios_init(void) {
    int ret = 0;

    /* Register PCI driver */
    ret = pci_register_driver(&xpmem_driver);
    if (ret != 0)
        XPMEM_ERR("Failed to register Palacios PCI device driver");

    return ret;
}

int
xpmem_palacios_deinit(void)
{
    xpmem_link_t link = xpmem_get_host_link();

    /* Remove the xpmem connection */
    if (link > 0)
        xpmem_remove_connection(link);

    pci_unregister_driver(&xpmem_driver);

    return 0;
}

MODULE_DEVICE_TABLE(pci, xpmem_ids);
