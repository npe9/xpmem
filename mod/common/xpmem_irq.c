/*
 * IPI request/release protocols. IRQs are associated with IPI vectors for cross-enclave
 * notifications
 *
 * (c) Brian Kocoloski, 2014 (briankoco@cs.pitt.edu)
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/pci.h>
#include <asm/ipi.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
#include <asm/irq_cfg.h>
#endif

#include <xpmem.h>
#include <xpmem_private.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
static void 
mask_lapic_irq(unsigned int irq) 
{
    unsigned long v = apic_read(APIC_LVT0);
    apic_write(APIC_LVT0, v | APIC_LVT_MASKED);
}

static void 
unmask_lapic_irq(unsigned int irq) 
{
    unsigned long v = apic_read(APIC_LVT0);
    apic_write(APIC_LVT0, v & ~APIC_LVT_MASKED);
}

static void 
ack_lapic_irq(unsigned int irq) 
{
    ack_APIC_irq();
}

/* lapic_chip (arch/x86/kernel/apic/io_apic.c */
static struct irq_chip 
ipi_chip =
{
    .name   = "xpmem-IPI",
    .mask   = mask_lapic_irq,
    .unmask = unmask_lapic_irq,
    .ack    = ack_lapic_irq,
};
#else
static void
mask_lapic_irq(struct irq_data * data)
{
    unsigned long v = apic_read(APIC_LVT0);
    apic_write(APIC_LVT0, v | APIC_LVT_MASKED);
}

static void
unmask_lapic_irq(struct irq_data * data)
{
    unsigned long v = apic_read(APIC_LVT0);
    apic_write(APIC_LVT0, v & ~APIC_LVT_MASKED);
}

static void
ack_lapic_irq(struct irq_data * data)
{
    ack_APIC_irq();
}

/* lapic_chip (arch/x86/kernel/apic/io_apic.c */
static struct irq_chip 
ipi_chip =
{
    .name       = "xpmem-IPI",
    .irq_mask   = mask_lapic_irq,
    .irq_unmask = unmask_lapic_irq,
    .irq_ack    = ack_lapic_irq,
};
#endif


static int
xpmem_alloc_irq(void)
{
    int irq;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) 
    irq = linux_create_irq();
#else
    irq = irq_alloc_hwirq(-1);
#endif

    if (irq > 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
        struct irq_desc * desc = linux_irq_to_desc(irq);
        if (desc == NULL) {
            XPMEM_ERR("No desc for irq %d", irq);
            linux_destroy_irq(irq);
            return -1;
        }

        desc->status &= ~IRQ_LEVEL;
        set_irq_chip(irq, &ipi_chip);
        __set_irq_handler(irq, linux_handle_edge_irq, 0, NULL);
#else
        irq_clear_status_flags(irq, IRQ_LEVEL);
        irq_set_chip_and_handler(irq, &ipi_chip, linux_handle_edge_irq);
#endif
    }

    return irq;
}

static void
xpmem_free_irq(int irq)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) 
    linux_destroy_irq(irq);
#else
    irq_free_hwirq(irq);
#endif
}

int 
xpmem_request_irq(irqreturn_t (*callback)(int, void *),
                  void      * priv_data)
{
    int  irq = 0;
    char name[16];

    /* Allocate hardware irq */
    irq = xpmem_alloc_irq();
    if (irq < 0) {
        XPMEM_ERR("Cannot allocate irq");
        return irq;
    }

    /* Request irq callback */
    memset(name, 0, 16);
    snprintf(name, 16, "xpmem-%d", irq);

    if (request_irq(irq, callback, 0, name, priv_data) != 0) {
        XPMEM_ERR("Unable to request callback for irq %d", irq);
        xpmem_free_irq(irq);
        return -1;
    }

    return irq;
}

EXPORT_SYMBOL(xpmem_request_irq);


void
xpmem_release_irq(int    irq,
                  void * priv_data) 
{
    /* Free Linux irq handler */
    free_irq(irq, priv_data);

    /* Free hardware irq */
    xpmem_free_irq(irq);
}

EXPORT_SYMBOL(xpmem_release_irq);


int
xpmem_irq_to_vector(int irq)
{
    struct irq_cfg * cfg;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
    {
        struct irq_desc * desc = linux_irq_to_desc(irq);
        if (desc == NULL) {
            XPMEM_ERR("No desc for irq %d", irq);
            return -1;
        }

        cfg = (struct irq_cfg *)desc->chip_data;
    }
#else
    cfg = irq_get_chip_data(irq);
#endif

    if (cfg == NULL) {
        XPMEM_ERR("No chip data for irq %d", irq);
        return -1;
    }

    return cfg->vector;
}

EXPORT_SYMBOL(xpmem_irq_to_vector);

void
xpmem_send_ipi_to_apic(unsigned int apic_id, 
                       unsigned int vector)
{
    unsigned long flags = 0;

    local_irq_save(flags);
    {
        __default_send_IPI_dest_field(apic_id, vector, APIC_DEST_PHYSICAL);
    }
    local_irq_restore(flags);
}
