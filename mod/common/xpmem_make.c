/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 */

/*
 * Cross Partition Memory (XPMEM) make segment support.
 */

#include <linux/err.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/anon_inodes.h>

#include <xpmem.h>
#include <xpmem_extended.h>
#include <xpmem_private.h>

static int
xpmem_alloc_seg_signal(struct xpmem_segment * seg)
{
    int irq;
    int vector;
    int apic_id;

    /* Request irq */
    irq = xpmem_request_irq_link(xpmem_my_part->domain_link);
    if (irq < 0) 
        return irq;

    /* Get irq IPI vector */
    vector = xpmem_irq_to_vector(irq);
    if (vector < 0) {
        xpmem_release_irq_link(xpmem_my_part->domain_link, irq);
        return vector;
    }

    /* Store local apic id of logical cpu 0 */
    apic_id = apic->cpu_present_to_apicid(0);

    /* Save sigid in seg structure */
    seg->sig.irq     = irq;
    seg->sig.vector  = vector;
    seg->sig.apic_id = apic_id;

    return 0;
}

static void
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
        /* Release the irq */
        status = xpmem_release_irq_link(xpmem_my_part->domain_link, seg->sig.irq);
        if (status != 0)
            XPMEM_ERR("Could not free irq %d for segid %lli", seg->sig.irq, seg->segid);
    }
}

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

static struct file_operations 
signal_fops = 
{
    .owner   = THIS_MODULE,
    .read    = signal_read,
    .poll    = signal_poll,
    .release = signal_release,
};


/*
 * Create a new and unique segid.
 */
static xpmem_segid_t
xpmem_make_segid(struct xpmem_thread_group *seg_tg, xpmem_segid_t request)
{
    struct xpmem_id segid;
    xpmem_segid_t *segid_p = (xpmem_segid_t *)&segid;
    int ret;

    DBUG_ON(sizeof(struct xpmem_id) != sizeof(xpmem_segid_t));

    *segid_p = 0;

    /* If there's no explicit request, the tgid is encoded directly in the segid */
    if (request == 0)
        segid.tgid = seg_tg->tgid;

    /* Allocate a segid from the nameserver */
    ret = xpmem_make_remote(xpmem_my_part->domain_link, request, segid_p);
    if (ret != 0)
        return ret;

    return *segid_p;
}

int
xpmem_make_segment(u64                         vaddr,
                   size_t                      size, 
                   int                         permit_type,
                   void                      * permit_value,
                   int                         flags,
                   struct xpmem_thread_group * seg_tg,
                   xpmem_segid_t               segid,
                   int                       * fd_p)
{
    struct xpmem_segment *seg;
    int status;

    /* create a new struct xpmem_segment structure with a unique segid */
    seg = kzalloc(sizeof(struct xpmem_segment), GFP_KERNEL);
    if (seg == NULL) {
        return -ENOMEM;
    }

    spin_lock_init(&(seg->lock));
    init_rwsem(&seg->sema);
    atomic_set(&(seg->irq_count), 0);
    seg->segid = segid;
    seg->vaddr = vaddr;
    seg->size = size;
    seg->permit_type = permit_type;
    seg->permit_value = permit_value;
    init_waitqueue_head(&seg->destroyed_wq);
    seg->tg = seg_tg;
    INIT_LIST_HEAD(&seg->ap_list);
    INIT_LIST_HEAD(&seg->seg_node);

    if (flags & XPMEM_FLAG_SHADOW) {
        seg->flags = XPMEM_FLAG_SHADOW;
    }

    if (flags & XPMEM_SIG_MODE) {
        char name[16];
        int fd;

        /* Allocate signal */
        status = xpmem_alloc_seg_signal(seg);
        if (status != 0) {
            kfree(seg);
            return status;
        }

        /* Allocate everything else */
        init_waitqueue_head(&seg->signalled_wq);
        seg->flags |= XPMEM_FLAG_SIGNALLABLE;

        /* Allocate anon fd */
        memset(name, 0, 16);
        snprintf(name, 16, "xpmem-irq-%d", seg->sig.irq);

        fd = anon_inode_getfd(name, &signal_fops, (void *)seg->segid, O_RDONLY);
        if (fd < 0) {
            xpmem_free_seg_signal(seg);
            kfree(seg);
            return fd;
        }

        seg->fd = fd;
        *fd_p   = fd;
    }

    xpmem_seg_not_destroyable(seg);

    /* add seg to its tg's list of segs */
    write_lock(&seg_tg->seg_list_lock);
    list_add_tail(&seg->seg_node, &seg_tg->seg_list);
    write_unlock(&seg_tg->seg_list_lock);

    /* add seg to global hash list of well-known segids, if necessary */
    if (segid <= XPMEM_MAX_WK_SEGID) {
        write_lock(&xpmem_my_part->wk_segid_to_tgid_lock);
        xpmem_my_part->wk_segid_to_tgid[segid] = seg_tg->tgid;
        write_unlock(&xpmem_my_part->wk_segid_to_tgid_lock);
    }

    return 0;
}

/*
 * Make a segid and segment for the specified address segment.
 */
int
xpmem_make(u64 vaddr, size_t size, int permit_type, void *permit_value, int flags,
        xpmem_segid_t request, xpmem_segid_t *segid_p, int *fd_p)
{
    xpmem_segid_t segid;
    struct xpmem_thread_group *seg_tg;
    int status;

    if (permit_type != XPMEM_PERMIT_MODE ||
        ((u64)permit_value & ~00777)) 
    {
        return -EINVAL;
    }


    /* BJK: sanity check xpmem_make_hobbes() stuff.
       MEM_MODE: size must be greater than 0 
       SIG_MODE AND NOT MEM_MODE: size must be 0
       REQUEST_MODE: check segid in valid range
     */
    if (flags & XPMEM_MEM_MODE) {
        if (size <= 0) {
            return -EINVAL;
        }
    } else if (!(flags & XPMEM_SIG_MODE)) {
        return -EINVAL;
    } else if (size != 0) {
        return -EINVAL;
    }

    if (flags & XPMEM_REQUEST_MODE) {
        if (request <= 0 || request > XPMEM_MAX_WK_SEGID) {
            return -EINVAL;
        }
    } else {
        request = 0;
    }

    seg_tg = xpmem_tg_ref_by_tgid(current->tgid);
    if (IS_ERR(seg_tg)) {
        DBUG_ON(PTR_ERR(seg_tg) != -ENOENT);
        return -XPMEM_ERRNO_NOPROC;
    }

    if (vaddr + size > seg_tg->addr_limit) {
        if (size != XPMEM_MAXADDR_SIZE) {
            xpmem_tg_deref(seg_tg);
            return -EINVAL;
        }
        size = seg_tg->addr_limit - vaddr;
    }

    /*
     * The start of the segment must be page aligned and it must be a
     * multiple of pages in size.
     */
    if (offset_in_page(vaddr) != 0 || offset_in_page(size) != 0) {
        xpmem_tg_deref(seg_tg);
        return -EINVAL;
    }

    segid = xpmem_make_segid(seg_tg, request);
    if (segid <= 0) {
        xpmem_tg_deref(seg_tg);
        return segid;
    }


    status = xpmem_make_segment(vaddr, size, permit_type, permit_value, flags, seg_tg, segid, fd_p);

    if (status == 0) {
        *segid_p = segid;
    }

    xpmem_tg_deref(seg_tg);

    return status;
}

/*
 * Remove a segment from the system.
 */
int
xpmem_remove_seg(struct xpmem_thread_group *seg_tg, struct xpmem_segment *seg)
{
    DBUG_ON(atomic_read(&seg->refcnt) <= 0);

    /* see if the requesting thread is the segment's owner */
    if (current->tgid != seg_tg->tgid)
        return -EACCES;

    spin_lock(&seg->lock);
    if (seg->flags & XPMEM_FLAG_DESTROYING) {
        spin_unlock(&seg->lock);
        return 0;
    }
    seg->flags |= XPMEM_FLAG_DESTROYING;
    spin_unlock(&seg->lock);

    xpmem_seg_down_write(seg);

    /* unpin pages and clear PTEs for each attachment to this segment */
    xpmem_clear_PTEs(seg);

    /* Remove signal */
    xpmem_free_seg_signal(seg);

    /* indicate that the segment has been destroyed */
    spin_lock(&seg->lock);
    seg->flags |= XPMEM_FLAG_DESTROYED;
    spin_unlock(&seg->lock);

    /* Remove segment structure from its tg's list of segs */
    write_lock(&seg_tg->seg_list_lock);
    list_del_init(&seg->seg_node);
    write_unlock(&seg_tg->seg_list_lock);

    /* Remove segment structure from global list of well-known segids */
    if (seg->segid <= XPMEM_MAX_WK_SEGID) {
        write_lock(&xpmem_my_part->wk_segid_to_tgid_lock);
        xpmem_my_part->wk_segid_to_tgid[seg->segid] = 0;
        write_unlock(&xpmem_my_part->wk_segid_to_tgid_lock);
    }

    /* Nameserver does not know about shadow segments, so don't remove them */
    if (!(seg->flags & XPMEM_FLAG_SHADOW)) {
        xpmem_remove_remote(xpmem_my_part->domain_link, seg->segid);
    }

    xpmem_seg_up_write(seg);
    xpmem_seg_destroyable(seg);

    return 0;
}

/*
 * Remove all segments belonging to the specified thread group.
 */
void
xpmem_remove_segs_of_tg(struct xpmem_thread_group *seg_tg)
{
    struct xpmem_segment *seg;

    DBUG_ON(current->tgid != seg_tg->tgid);

    read_lock(&seg_tg->seg_list_lock);

    while (!list_empty(&seg_tg->seg_list)) {
        seg = list_entry((&seg_tg->seg_list)->next,
                 struct xpmem_segment, seg_node);
        if (!(seg->flags & XPMEM_FLAG_DESTROYING)) {
            xpmem_seg_ref(seg);
            read_unlock(&seg_tg->seg_list_lock);

            (void)xpmem_remove_seg(seg_tg, seg);

            xpmem_seg_deref(seg);
            read_lock(&seg_tg->seg_list_lock);
        }
    }
    read_unlock(&seg_tg->seg_list_lock);
}

/*
 * Remove a segment from the system.
 */
int
xpmem_remove(xpmem_segid_t segid)
{
    struct xpmem_thread_group *seg_tg;
    struct xpmem_segment *seg;
    int ret;

    if (segid <= 0)
        return -EINVAL;

    seg_tg = xpmem_tg_ref_by_segid(segid);
    if (IS_ERR(seg_tg))
        return PTR_ERR(seg_tg);

    if (current->tgid != seg_tg->tgid) {
        xpmem_tg_deref(seg_tg);
        return -EACCES;
    }

    seg = xpmem_seg_ref_by_segid(seg_tg, segid);
    if (IS_ERR(seg)) {
        xpmem_tg_deref(seg_tg);
        return PTR_ERR(seg);
    }
    DBUG_ON(seg->tg != seg_tg);

    ret = xpmem_remove_seg(seg_tg, seg);
    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);

    return ret;
}
