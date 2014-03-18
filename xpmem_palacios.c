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

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>

#define XPMEM_VENDOR_ID     0xfff0
#define XPMEM_SUBVENDOR_ID  0xfff0
#define XPMEM_DEVICE_ID     0x100d

#define INT_REQUEST        0x01
#define INT_COMPLETE       0x02


#define VMCALL      ".byte 0x0F,0x01,0xC1\r\n"


static void xpmem_make_hcall(int id, xpmem_segid_t segid) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(segid)
    );
}

static void xpmem_remove_hcall(int id, xpmem_segid_t segid) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(segid)
    );
}

static void xpmem_get_hcall(int id, xpmem_segid_t segid, u64 flags, u64 permit_type, u64 permit_value) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(segid), "c"(flags), "d"(permit_type), "S"(permit_value)
    );
}

static void xpmem_release_hcall(int id, xpmem_apid_t apid) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(apid)
    );
}

static void xpmem_attach_hcall(int id, xpmem_apid_t apid, u64 off, u64 size, u64 buffer_pa) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(apid), "c"(off), "d"(size), "S"(buffer_pa)
    );
}

static void xpmem_detach_hcall(int id, u64 vaddr) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(vaddr)
    );
}

static void xpmem_get_complete_hcall(int id, xpmem_apid_t apid) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(apid)
    );
}

static void xpmem_remove_complete_hcall(int id) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id)
    );
}

static void xpmem_attach_complete_hcall(int id, u64 buffer_pa) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(buffer_pa)
    );
}

static void xpmem_detach_complete_hcall(int id) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id)
    );
}


static const struct pci_device_id xpmem_ids[] = {
    { PCI_DEVICE(XPMEM_VENDOR_ID, XPMEM_DEVICE_ID) },
    { },
};

struct xpmem_hypercall_info {
    u32 make_hcall;
    u32 remove_hcall;
    u32 get_hcall;
    u32 release_hcall;
    u32 attach_hcall;
    u32 detach_hcall;
    u32 command_complete_hcall;
};

struct xpmem_bar_state {
    struct xpmem_hypercall_info hcall_info;
    u8 interrupt_status;
    struct xpmem_cmd_ex request;
    struct xpmem_cmd_ex response;
};

static void read_bar(void __iomem * xpmem_bar, void * bar_state) {
    u32 i = 0;
    for (i = 0; i < sizeof(struct xpmem_bar_state); i++) {
        *((u8 *)(bar_state + i)) = ioread8(xpmem_bar + i);
    }
}

struct xpmem_state {
    void __iomem * xpmem_bar;
    struct xpmem_bar_state bar_state;

    int initialized;

    int make_requested;
    int make_complete;

    int remove_requested;
    int remove_complete;

    int get_requested;
    int get_complete;

    int release_requested;
    int release_complete;

    int attach_requested;
    int attach_complete;

    int detach_requested;
    int detach_complete;

    /* Semaphore serializing access to device */
    struct semaphore mutex;

    /* Wait queue for Palacios completion notification */
    wait_queue_head_t waitq;
};

static struct xpmem_state state;


void xpmem_tasklet_fn(unsigned long data) {
    struct xpmem_bar_state * bar_state = (struct xpmem_bar_state *)data;
    struct xpmem_cmd_ex * request = (struct xpmem_cmd_ex *)&(bar_state->request);

    switch (request->type) {
        case XPMEM_GET:
            printk("Received XPMEM_GET request(segid: %lli, flags: %lu, permit_type: %lu, permit_value: %llu)\n",
                (signed long long)request->get.segid,
                (unsigned long)request->get.flags,
                (unsigned long)request->get.permit_type,
                (unsigned long long)request->get.permit_value
            );
            break;

        case XPMEM_RELEASE:
            printk("Received XPMEM_RELEASE request(apid: %lli)\n",
                (signed long long)request->release.apid
            );
            break;
        
        case XPMEM_ATTACH:
            printk("Received XPMEM_ATTACH request(apid: %lli, off: %llu, size: %llu)\n",
                (signed long long)request->attach.apid,
                (unsigned long long)request->attach.off,
                (unsigned long long)request->attach.size
            );
            break;

        case XPMEM_DETACH:
            printk("Received XPMEM_DETACH request(vaddr: %llu)\n",
                (unsigned long long)request->detach.vaddr
            );
            break;

        case XPMEM_MAKE:
        case XPMEM_REMOVE:
        default:
            printk("Unhandled XPMEM request: %d\n", request->type);
            break;

    }
}


DECLARE_TASKLET(xpmem_tasklet, xpmem_tasklet_fn, (unsigned long)&(state.bar_state));



static irqreturn_t irq_handler(int irq, void * data) {
    struct xpmem_state * state = (struct xpmem_state *)data; 
    u8 status;

    read_bar(state->xpmem_bar, (void *)&(state->bar_state));
    status = state->bar_state.interrupt_status;

    if (status & INT_COMPLETE) {
        if (state->make_requested) {
            state->make_requested = 0;
            state->make_complete = 1;
        } else if (state->remove_requested) {
            state->remove_requested = 0;
            state->remove_complete = 1;
        } else if (state->get_requested) {
            state->get_requested = 0;
            state->get_complete = 1;
        } else if (state->release_requested) {
            state->release_requested = 0;
            state->release_complete = 1;
        } else if (state->attach_requested) {
            state->attach_requested = 0;
            state->attach_complete = 1;
        } else if (state->detach_requested) {
            state->detach_requested = 0;
            state->detach_complete = 1;
        } else {
            // not good 
            return IRQ_NONE;
        }

        wake_up_interruptible(&(state->waitq));
    }

    if (status & INT_REQUEST) {
        tasklet_schedule(&(xpmem_tasklet));
    }

    return IRQ_HANDLED;
}


static int xpmem_probe_driver(struct pci_dev * dev, const struct pci_device_id * id) {
    int ret = -1;
    unsigned long bar_size = 0;

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
    bar_size = pci_resource_len(dev, 0);
    state.xpmem_bar = pci_iomap(dev, 0, bar_size); 

    if (!state.xpmem_bar) {
        printk("Failed to map Palacios XPMEM BAR 0 memory\n");
        ret = -1;
        goto err;
    }

    /* Read Palacios header from BAR0 */
    read_bar(state.xpmem_bar, (void *)&(state.bar_state));

    if ((state.bar_state.hcall_info.make_hcall == 0) || 
            (state.bar_state.hcall_info.remove_hcall == 0) || 
            (state.bar_state.hcall_info.get_hcall == 0) || 
            (state.bar_state.hcall_info.release_hcall == 0) || 
            (state.bar_state.hcall_info.attach_hcall == 0) ||
            (state.bar_state.hcall_info.detach_hcall == 0) ||
            (state.bar_state.hcall_info.command_complete_hcall == 0)) {
        printk("Palacios XPMEM hypercalls not available\n");
        ret = -1;
        goto err_unmap;
    }

    /* Register IRQ handler */
    if ((ret = request_irq(dev->irq, irq_handler, IRQF_SHARED, "xpmem", &state))) {
        printk("Failed to request IRQ for Palacios XPMEM device (irq = %d)\n", dev->irq);
        goto err_unmap;
    }

    init_waitqueue_head(&(state.waitq));
    sema_init(&(state.mutex), 1);
    state.initialized = 1;

    printk("Palacios XPMEM PCI device enabled\n");
    return 0;

err_unmap:
    pci_iounmap(dev, state.xpmem_bar);
err:
    printk("Palacios XPMEM device initialization failed\n");
    return ret;
}


static void xpmem_remove_driver(struct pci_dev * dev) {}


static struct pci_driver xpmem_driver = {
    .name       = "pci_xpmem",
    .id_table   = xpmem_ids,
    .probe      = xpmem_probe_driver,
    .remove     = xpmem_remove_driver,
};


int xpmem_palacios_init(void) {
    int ret;

    memset(&state, 0, sizeof(struct xpmem_state));

    /* Register PCI driver */
    ret = pci_register_driver(&xpmem_driver);

    if (ret != 0) {
        printk(KERN_ERR "Failed to register Palacios XPMEM driver\n");
    }

    return ret;
}



static int xpmem_make_palacios(xpmem_segid_t * segid) {
    if (!state.initialized) {
        return -1;
    }

    /* Take mutex */
    while (down_interruptible(&(state.mutex)));

    state.make_requested = 1;
    state.make_complete = 0;
    xpmem_make_hcall(state.bar_state.hcall_info.make_hcall, *segid);

    wait_event_interruptible(state.waitq, (state.make_complete == 1)); 
    *segid = state.bar_state.response.make.segid;

    /* Release mutex */
    up(&(state.mutex));
    return 0;
}

static int xpmem_remove_palacios(xpmem_segid_t segid) {
    if (!state.initialized) {
        return -1;
    }

    while (down_interruptible(&(state.mutex)));

    state.remove_requested = 1;
    state.remove_complete = 0;
    xpmem_remove_hcall(state.bar_state.hcall_info.remove_hcall, segid);

    wait_event_interruptible(state.waitq, (state.remove_complete == 1));

    up(&(state.mutex));
    return 0;
}

static int xpmem_get_palacios(xpmem_segid_t segid, int flags, int permit_type, u64 permit_value, xpmem_apid_t * apid) {
    if (!state.initialized) {
        return -1;
    }

    while (down_interruptible(&(state.mutex)));

    state.get_requested = 1;
    state.get_complete = 0;
    xpmem_get_hcall(state.bar_state.hcall_info.get_hcall, segid, flags, permit_type, permit_value);

    wait_event_interruptible(state.waitq, (state.get_complete == 1));
    *apid = state.bar_state.response.get.apid;

    up(&(state.mutex));
    return 0;
}

static int xpmem_release_palacios(xpmem_apid_t apid) {
    if (!state.initialized) {
        return -1;
    }

    while (down_interruptible(&(state.mutex)));

    state.release_requested = 1;
    state.release_complete = 0;
    xpmem_release_hcall(state.bar_state.hcall_info.release_hcall, apid);

    wait_event_interruptible(state.waitq, (state.release_complete == 1));

    up(&(state.mutex));
    return 0;
}

static int xpmem_attach_palacios(xpmem_apid_t apid, off_t offset, size_t size, u64 * vaddr) {
    if (!state.initialized) {
        return -1;
    }

    while (down_interruptible(&(state.mutex)));

    state.attach_requested = 1;
    state.attach_complete = 0;
    xpmem_attach_hcall(state.bar_state.hcall_info.remove_hcall, apid, offset, size, /* TODO: buffer pa*/ 0);

    wait_event_interruptible(state.waitq, (state.attach_complete == 1));

    /* TODO: read pfns from buffer PA, invoke ioremap() on them, set *vaddr */

    up(&(state.mutex));
    return 0;
}

static int xpmem_detach_palacios(u64 vaddr) {
    if (!state.initialized) {
        return -1;
    }

    while (down_interruptible(&(state.mutex)));

    state.detach_requested = 1;
    state.detach_complete = 0;
    xpmem_detach_hcall(state.bar_state.hcall_info.remove_hcall, vaddr);

    wait_event_interruptible(state.waitq, (state.detach_complete == 1));

    up(&(state.mutex));
    return 0;
}



struct xpmem_extended_ops palacios_ops = {
    .make       = xpmem_make_palacios,
    .remove     = xpmem_remove_palacios,
    .get        = xpmem_get_palacios,
    .release    = xpmem_release_palacios,
    .attach     = xpmem_attach_palacios,
    .detach     = xpmem_detach_palacios,
};

MODULE_DEVICE_TABLE(pci, xpmem_ids);
