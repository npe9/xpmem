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
#define MAX_DEVICES     16


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

static void xpmem_get_req_complete_hcall(int id, xpmem_apid_t apid) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(apid)
    );
}

static void xpmem_release_req_complete_hcall(int id) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id)
    );
}

static void xpmem_attach_req_complete_hcall(int id, u64 buffer_pa) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id), "b"(buffer_pa)
    );
}

static void xpmem_detach_req_complete_hcall(int id) {
    unsigned long long ret = 0;
    __asm__ volatile(
        VMCALL
        : "=a"(ret)
        : "a"(id)
    );
}


struct xpmem_hypercall_info {
    u32 make_hcall;
    u32 remove_hcall;
    u32 get_hcall;
    u32 release_hcall;
    u32 attach_hcall;
    u32 detach_hcall;
    u32 command_req_complete_hcall;
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

struct palacios_xpmem_state {
    void __iomem * xpmem_bar;
    struct xpmem_bar_state bar_state;
    int initialized;
    struct tasklet_struct t;

    struct mutex mutex;
    wait_queue_head_t waitq;
    int req_complete;
};

static struct palacios_xpmem_state palacios_devs[MAX_DEVICES];
static int dev_off = 0;
DEFINE_SPINLOCK(palacios_lock);


void xpmem_tasklet_fn(unsigned long data) {
    struct xpmem_bar_state * bar_state = (struct xpmem_bar_state *)data;
    struct xpmem_cmd_ex * request = (struct xpmem_cmd_ex *)&(bar_state->request);

    switch (request->type) {
        case XPMEM_GET: {
            xpmem_apid_t apid;

            printk("Received XPMEM_GET request(segid: %lli, flags: %lu, permit_type: %lu, permit_value: %llu)\n",
                (signed long long)request->get.segid,
                (unsigned long)request->get.flags,
                (unsigned long)request->get.permit_type,
                (unsigned long long)request->get.permit_value
            );

            if (xpmem_get_remote(&(request->get))) {
                printk("Request failed!\n");
                apid = -1;
            } else {
                apid = request->get.apid;
            }

            xpmem_get_req_complete_hcall(bar_state->hcall_info.command_req_complete_hcall, apid); 
            break;
        }

        case XPMEM_RELEASE:
            printk("Received XPMEM_RELEASE request(apid: %lli)\n",
                (signed long long)request->release.apid
            );

            if (xpmem_release_remote(&(request->release))) {
                printk("Request failed!\n");
            }

            xpmem_release_req_complete_hcall(bar_state->hcall_info.command_req_complete_hcall);
            break;
        
        case XPMEM_ATTACH:
            printk("Received XPMEM_ATTACH request(apid: %lli, off: %llu, size: %llu)\n",
                (signed long long)request->attach.apid,
                (unsigned long long)request->attach.off,
                (unsigned long long)request->attach.size
            );

            if (xpmem_attach_remote(&(request->attach))) {
                printk("Request failed!\n");
            }

            xpmem_attach_req_complete_hcall(bar_state->hcall_info.command_req_complete_hcall, 0x0);
            break;

        case XPMEM_DETACH:
            printk("Received XPMEM_DETACH request(vaddr: %llu)\n",
                (unsigned long long)request->detach.vaddr
            );

            if (xpmem_detach_remote(&(request->detach))) {
                printk("Request failed!\n");
            }

            xpmem_detach_req_complete_hcall(bar_state->hcall_info.command_req_complete_hcall);
            break;

        case XPMEM_MAKE:
        case XPMEM_REMOVE:
        default:
            printk("Unhandled XPMEM request: %d\n", request->type);
            break;

    }
}



static irqreturn_t irq_handler(int irq, void * data) {
    struct palacios_xpmem_state * state = (struct palacios_xpmem_state *)data; 
    u8 status;

    read_bar(state->xpmem_bar, (void *)&(state->bar_state));
    status = state->bar_state.interrupt_status;

    if (status & INT_COMPLETE) {
        state->req_complete = 1; 
        wake_up_interruptible(&(state->waitq));
    }

    if (status & INT_REQUEST) {
        tasklet_schedule(&(state->t));
    }

    return IRQ_HANDLED;
}



static const struct pci_device_id xpmem_ids[] = {
    { PCI_DEVICE(XPMEM_VENDOR_ID, XPMEM_DEVICE_ID) },
    { },
};

static int xpmem_probe_driver(struct pci_dev * dev, const struct pci_device_id * id) {
    int ret = -1;
    unsigned long bar_size = 0;
    unsigned long flags;
    struct palacios_xpmem_state * palacios_state = NULL;

    spin_lock_irqsave(&(palacios_lock), flags);
    palacios_state = &(palacios_devs[dev_off]);
    spin_unlock_irqrestore(&(palacios_lock), flags);

    memset(palacios_state, 0, sizeof(struct palacios_xpmem_state));

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
    palacios_state->xpmem_bar = pci_iomap(dev, 0, bar_size); 

    if (!palacios_state->xpmem_bar) {
        printk("Failed to map Palacios XPMEM BAR 0 memory\n");
        ret = -1;
        goto err;
    }

    /* Read Palacios header from BAR0 */
    read_bar(palacios_state->xpmem_bar, (void *)&(palacios_state->bar_state));

    if ((palacios_state->bar_state.hcall_info.make_hcall == 0) || 
            (palacios_state->bar_state.hcall_info.remove_hcall == 0) || 
            (palacios_state->bar_state.hcall_info.get_hcall == 0) || 
            (palacios_state->bar_state.hcall_info.release_hcall == 0) || 
            (palacios_state->bar_state.hcall_info.attach_hcall == 0) ||
            (palacios_state->bar_state.hcall_info.detach_hcall == 0) ||
            (palacios_state->bar_state.hcall_info.command_req_complete_hcall == 0)) {
        printk("Palacios XPMEM hypercalls not available\n");
        ret = -1;
        goto err_unmap;
    }

    /* Register IRQ handler */
    if ((ret = request_irq(dev->irq, irq_handler, IRQF_SHARED, "xpmem", palacios_state))) {
        printk("Failed to request IRQ for Palacios XPMEM device (irq = %d)\n", dev->irq);
        goto err_unmap;
    }


    init_waitqueue_head(&(palacios_state->waitq));
    mutex_init(&(palacios_state->mutex));
    tasklet_init(&(palacios_state->t), &(xpmem_tasklet_fn), (unsigned long)&(palacios_state->bar_state));

    palacios_state->initialized = 1;
    spin_lock_irqsave(&(palacios_lock), flags);
    ++dev_off;
    spin_unlock_irqrestore(&(palacios_lock), flags);

    printk("Palacios XPMEM PCI device enabled\n");
    return 0;

err_unmap:
    pci_iounmap(dev, palacios_state->xpmem_bar);
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


int xpmem_palacios_init(struct xpmem_partition * part) {
    int ret;
    unsigned long flags;

    spin_lock_irqsave(&(palacios_lock), flags);
    part->palacios_state = &(palacios_devs[dev_off]);
    spin_unlock_irqrestore(&(palacios_lock), flags);

    /* Register PCI driver */
    ret = pci_register_driver(&xpmem_driver);

    if (ret != 0) {
        printk(KERN_ERR "Failed to register Palacios XPMEM driver\n");
    }

    return ret;
}

int xpmem_palacios_deinit(struct xpmem_partition * part) {
    pci_unregister_driver(&xpmem_driver);
    return 0;
}


static int xpmem_make_palacios(struct xpmem_partition * part, xpmem_segid_t * segid) {
    struct palacios_xpmem_state * state = part->palacios_state;

    if (!state->initialized) {
        return -1;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    state->req_complete = 0;
    xpmem_make_hcall(state->bar_state.hcall_info.make_hcall, *segid);
    wait_event_interruptible(state->waitq, (state->req_complete == 1)); 
    *segid = state->bar_state.response.make.segid;

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_remove_palacios(struct xpmem_partition * part, xpmem_segid_t segid) {
    struct palacios_xpmem_state * state = part->palacios_state;

    if (!state->initialized) {
        return -1;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    state->req_complete = 0;
    xpmem_remove_hcall(state->bar_state.hcall_info.remove_hcall, segid);
    wait_event_interruptible(state->waitq, (state->req_complete == 1));

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_get_palacios(struct xpmem_partition * part, xpmem_segid_t segid, int flags, int permit_type, u64 permit_value, xpmem_apid_t * apid) {
    struct palacios_xpmem_state * state = part->palacios_state;

    if (!state->initialized) {
        return -1;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    state->req_complete = 0;;
    xpmem_get_hcall(state->bar_state.hcall_info.get_hcall, segid, flags, permit_type, permit_value);
    wait_event_interruptible(state->waitq, (state->req_complete == 1));
    *apid = state->bar_state.response.get.apid;

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_release_palacios(struct xpmem_partition * part, xpmem_apid_t apid) {
    struct palacios_xpmem_state * state = part->palacios_state;

    if (!state->initialized) {
        return -1;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    state->req_complete = 0;
    xpmem_release_hcall(state->bar_state.hcall_info.release_hcall, apid);
    wait_event_interruptible(state->waitq, (state->req_complete == 1));

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_attach_palacios(struct xpmem_partition * part, xpmem_apid_t apid, off_t offset, size_t size, u64 * vaddr) {
    struct palacios_xpmem_state * state = part->palacios_state;

    if (!state->initialized) {
        return -1;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    state->req_complete = 0;
    xpmem_attach_hcall(state->bar_state.hcall_info.remove_hcall, apid, offset, size, /* TODO: buffer pa*/ 0);
    wait_event_interruptible(state->waitq, (state->req_complete == 1));

    /* TODO: read pfns from buffer PA, invoke ioremap() on them, set *vaddr */

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_detach_palacios(struct xpmem_partition * part, u64 vaddr) {
    struct palacios_xpmem_state * state = part->palacios_state;

    if (!state->initialized) {
        return -1;
    }

    while (mutex_lock_interruptible(&(state->mutex)));

    state->req_complete = 0;
    xpmem_detach_hcall(state->bar_state.hcall_info.remove_hcall, vaddr);
    wait_event_interruptible(state->waitq, (state->req_complete == 1));

    mutex_unlock(&(state->mutex));
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
