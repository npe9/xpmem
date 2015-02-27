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
#include <linux/poll.h>

#include <xpmem.h>
#include <xpmem_private.h>


static ssize_t
signal_read(struct file * filp,
            char __user * buffer,
            size_t        length,
            loff_t      * offset)
{
    struct xpmem_thread_group * seg_tg;
    struct xpmem_segment      * seg;
    xpmem_segid_t               segid;
    unsigned long               irqs;

    if (length != sizeof(unsigned long))
        return -EINVAL;

    segid = (xpmem_segid_t)filp->private_data;

    seg_tg = xpmem_tg_ref_by_segid(segid);
    if (IS_ERR(seg_tg))
        return PTR_ERR(seg_tg);

    seg = xpmem_seg_ref_by_segid(seg_tg, segid);
    if (IS_ERR(seg)) {
        xpmem_tg_deref(seg_tg);
        return PTR_ERR(seg);
    }

    wait_event_interruptible(seg->signalled_wq,
        (atomic_read(&(seg->irq_count)) > 0)
    );

    irqs = atomic_dec_return(&(seg->irq_count));

    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);

    if (copy_to_user(buffer, &irqs, sizeof(unsigned long))) 
        return -EFAULT;

    return length;
}

static unsigned int
signal_poll(struct file              * filp,
            struct poll_table_struct * poll)
{
    struct xpmem_thread_group * seg_tg;
    struct xpmem_segment      * seg;
    xpmem_segid_t               segid;
    unsigned long               irqs;
    unsigned int                mask = 0;

    segid = (xpmem_segid_t)filp->private_data;

    seg_tg = xpmem_tg_ref_by_segid(segid);
    if (IS_ERR(seg_tg))
        return PTR_ERR(seg_tg);

    seg = xpmem_seg_ref_by_segid(seg_tg, segid);
    if (IS_ERR(seg)) {
        xpmem_tg_deref(seg_tg);
        return PTR_ERR(seg);
    }

    poll_wait(filp, &(seg->signalled_wq), poll);

    irqs = atomic_read(&(seg->irq_count));
    if (irqs > 0) 
        mask = POLLIN | POLLRDNORM;

    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);

    return mask;
}

/* Free segment's signal on release */
static int
signal_release(struct inode * inodep,
               struct file  * filp)
{
    struct xpmem_thread_group * seg_tg;
    struct xpmem_segment      * seg;
    xpmem_segid_t               segid;

    segid = (xpmem_segid_t)filp->private_data;

    seg_tg = xpmem_tg_ref_by_segid(segid);
    if (IS_ERR(seg_tg))
        return PTR_ERR(seg_tg);

    seg = xpmem_seg_ref_by_segid(seg_tg, segid);
    if (IS_ERR(seg)) {
        xpmem_tg_deref(seg_tg);
        return PTR_ERR(seg);
    }

    xpmem_free_seg_signal(seg);

    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);

    return 0;
}

struct file_operations 
xpmem_signal_fops = 
{
    .owner   = THIS_MODULE,
    .read    = signal_read,
    .poll    = signal_poll,
    .release = signal_release,
};


static irqreturn_t 
xpmem_irq_fn(int    irq,
             void * priv_data)
{
    xpmem_segid_t segid = (xpmem_segid_t)priv_data;

    return (xpmem_segid_signal(segid) == 0) ? IRQ_HANDLED : IRQ_NONE;
}

int
xpmem_alloc_seg_signal(struct xpmem_segment * seg)
{
    int irq;
    int vector, host_vector;
    int apic_id;

    /* Request irq */
    irq = xpmem_request_irq(xpmem_irq_fn, (void *)seg->segid);
    if (irq < 0) 
        return irq;

    /* Get IDT vector */
    vector = xpmem_irq_to_vector(irq);
    if (vector < 0) {
        xpmem_release_irq(irq, (void *)seg->segid);
        return vector;
    }

    /* Get hardware IDT vector from host */
    host_vector = xpmem_request_host_vector(vector);

    /* Get hardware apic ID for logical cpu 0*/
    apic_id = xpmem_get_host_apic_id(0);
    if (apic_id < 0) {
        xpmem_release_host_vector(host_vector);
        xpmem_release_irq(irq, (void *)seg->segid);
        return apic_id;
    }

    /* Save sigid in seg structure */
    seg->sig.irq     = irq;
    seg->sig.vector  = host_vector;
    seg->sig.apic_id = apic_id;

    return 0;
}

void
xpmem_free_seg_signal(struct xpmem_segment * seg)
{
    int status = 0;

    spin_lock(&(seg->lock));
    if (seg->flags & XPMEM_FLAG_SIGNALLABLE) {
        status = 1;
        seg->flags &= ~XPMEM_FLAG_SIGNALLABLE;
    } 
    spin_unlock(&(seg->lock));

    if (status) {
        /* Release host IDT vector */
        xpmem_release_host_vector(seg->sig.vector);

        /* Release the irq */
        xpmem_release_irq(seg->sig.irq, (void *)seg->segid);
    }
}

void
xpmem_seg_signal(struct xpmem_segment * seg)
{
    atomic_inc(&(seg->irq_count));
    mb();

    wake_up(&(seg->signalled_wq));
}

int
xpmem_segid_signal(xpmem_segid_t segid)
{
    struct xpmem_thread_group * seg_tg;
    struct xpmem_segment      * seg; 

    seg_tg = xpmem_tg_ref_by_segid(segid);
    if (IS_ERR(seg_tg))
        return PTR_ERR(seg_tg);

    seg = xpmem_seg_ref_by_segid(seg_tg, segid);
    if (IS_ERR(seg)) {
        xpmem_tg_deref(seg_tg);
        return PTR_ERR(seg);
    }    

    xpmem_seg_signal(seg);

    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);

    return 0;

}

/*
 * Send a signal to segment associated with access permit
 */
int
xpmem_signal(xpmem_apid_t apid)
{
    struct xpmem_thread_group  * ap_tg, * seg_tg;
    struct xpmem_access_permit * ap; 
    struct xpmem_segment       * seg;
    int ret;

    if (apid <= 0)
        return -EINVAL;

    ap_tg = xpmem_tg_ref_by_apid(apid);
    if (IS_ERR(ap_tg))
        return PTR_ERR(ap_tg);

    ap = xpmem_ap_ref_by_apid(ap_tg, apid);
    if (IS_ERR(ap)) {
        xpmem_tg_deref(ap_tg);
        return PTR_ERR(ap);
    }

    seg = ap->seg;
    xpmem_seg_ref(seg);
    seg_tg = seg->tg;
    xpmem_tg_ref(seg_tg);

    ret = xpmem_seg_down_read(seg_tg, seg, 0, 1);
    if (ret != 0)
        goto out_1;

    if (!(seg->flags & XPMEM_FLAG_SIGNALLABLE)) {
        ret = -EACCES;
        goto out_2;
    }

    /* Send signal */
    if (seg->flags & XPMEM_FLAG_SHADOW) {
        /* Shadow segment */
        ret = xpmem_irq_deliver(
            seg->segid,
            *((xpmem_sigid_t *)&(seg->sig)),
            seg->domid);
    }
    else {
        /* Local segment */
        xpmem_seg_signal(seg);
    }

    ret = 0;

out_2:
    xpmem_seg_up_read(seg_tg, seg, 0);
out_1:
    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);
    xpmem_ap_deref(ap);
    xpmem_tg_deref(ap_tg);
    return ret;
}

