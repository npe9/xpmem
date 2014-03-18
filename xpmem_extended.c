/*
 * XPMEM extensions for multiple domain support.
 *
 * This file implements XPMEM commands for remote processes, requesting
 * get/release, attach/detach to local XPMEM data. It's hacky in places but I
 * don't think that's avoidable
 *
 * This code is independent of code implementing transport interfaces -
 * that exists in xpmem_{ns,palacios,pisces}.c
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>

u32 extend_enabled = 0;
struct xpmem_extended_ops * xpmem_extended_ops = NULL;

int xpmem_extend_enable(xpmem_domain_t dom) {
    switch (dom) {
        case XPMEM_EXT_NS:
            xpmem_extended_ops = &ns_ops;
            break;

        case XPMEM_EXT_PALACIOS:
            xpmem_extended_ops = &palacios_ops;
            break;

        default:
            return -1;
    }

    extend_enabled = 1;
    return 0;
}

static xpmem_apid_t
xpmem_make_apid_extended(struct xpmem_thread_group * ap_tg, xpmem_segid_t segid) {
    struct xpmem_id apid, * segid_id_p;
    xpmem_apid_t *apid_p = (xpmem_apid_t *)&apid;
    int uniq;

    segid_id_p = (struct xpmem_id *)&segid;
    uniq = segid_id_p->uniq;

    *apid_p = 0;
    apid.tgid = ap_tg->tgid;
    apid.uniq = (unsigned short) uniq;

    DBUG_ON(*apid_p <= 0);
    return *apid_p;

}


static int
xpmem_validate_remote_access(struct xpmem_access_permit *ap, off_t offset,
            size_t size, int mode, u64 *vaddr) {
    if (mode == XPMEM_RDWR && ap->mode == XPMEM_RDONLY) {
        return -EACCES;
    }

    if (offset < 0 || size == 0 || offset + size > ap->seg->size) {
        return -EINVAL;
    }

    *vaddr = ap->seg->vaddr + offset;
    return 0;
}

/* Handle remote requests */
int xpmem_get_remote(struct xpmem_cmd_get_ex * get_ex) {
    xpmem_apid_t apid;
    struct xpmem_access_permit *ap;
    struct xpmem_segment *seg;
    struct xpmem_thread_group *ap_tg, *seg_tg;
    int index;

    xpmem_segid_t segid = get_ex->segid;
    int flags = get_ex->flags;
    int permit_type = get_ex->permit_type;
    void * permit_value = (void *)get_ex->permit_value;

    if (segid <= 0)
        return -EINVAL;

    if ((flags & ~(XPMEM_RDONLY | XPMEM_RDWR)) ||
        (flags & (XPMEM_RDONLY | XPMEM_RDWR)) ==
        (XPMEM_RDONLY | XPMEM_RDWR))
        return -EINVAL;

    if (permit_type != XPMEM_PERMIT_MODE || permit_value != NULL)
        return -EINVAL;

    seg_tg = xpmem_tg_ref_by_segid(segid);
    if (IS_ERR(seg_tg)) {
        return PTR_ERR(seg_tg);
    }   

    seg = xpmem_seg_ref_by_segid(seg_tg, segid);
    if (IS_ERR(seg)) {
        xpmem_tg_deref(seg_tg);
       return PTR_ERR(seg);
    }

    /* assuming XPMEM_PERMIT_MODE, do the appropriate permission check */
    if (xpmem_check_permit_mode(flags, seg) != 0) {
        xpmem_seg_deref(seg);
        xpmem_tg_deref(seg_tg);
        return -EACCES;
    }

    /* find accessor's thread group structure.
     * NOTE: we do this ref by segid, which means the ap_tg struct is for the
     * source (local) process that created the segid */
    //ap_tg = xpmem_tg_ref_by_tgid(current->tgid);
    ap_tg = xpmem_tg_ref_by_segid(segid);
    if (IS_ERR(ap_tg)) {
        DBUG_ON(PTR_ERR(ap_tg) != -ENOENT);
        xpmem_seg_deref(seg);
        xpmem_tg_deref(seg_tg);
        return -XPMEM_ERRNO_NOPROC;
    }

    apid = xpmem_make_apid_extended(ap_tg, segid);
    if (apid < 0) {
        xpmem_tg_deref(ap_tg);
        xpmem_seg_deref(seg);
        xpmem_tg_deref(seg_tg);
        return apid;
    }

    /* create a new xpmem_access_permit structure with a unique apid */
    ap = kzalloc(sizeof(struct xpmem_access_permit), GFP_KERNEL);
    if (ap == NULL) {
        xpmem_tg_deref(ap_tg);
        xpmem_seg_deref(seg);
        xpmem_tg_deref(seg_tg);
        return -ENOMEM;
    }

    ap->lock = __SPIN_LOCK_UNLOCKED(ap->lock);
    ap->seg = seg;
    ap->tg = ap_tg;
    ap->apid = apid;
    ap->mode = flags;
    INIT_LIST_HEAD(&ap->att_list);
    INIT_LIST_HEAD(&ap->ap_list);
    INIT_LIST_HEAD(&ap->ap_hashlist);

    xpmem_ap_not_destroyable(ap);

    /* add ap to its seg's access permit list */
    spin_lock(&seg->lock);
    list_add_tail(&ap->ap_list, &seg->ap_list);
    spin_unlock(&seg->lock);

    /* add ap to its hash list */
    index = xpmem_ap_hashtable_index(ap->apid);
    write_lock(&ap_tg->ap_hashtable[index].lock);
    list_add_tail(&ap->ap_hashlist, &ap_tg->ap_hashtable[index].list);
    write_unlock(&ap_tg->ap_hashtable[index].lock);

    xpmem_tg_deref(ap_tg);

    /*
     * The following two derefs
     *
     *      xpmem_seg_deref(seg);
     *      xpmem_tg_deref(seg_tg);
     *
     * aren't being done at this time in order to prevent the seg
     * and seg_tg structures from being prematurely kfree'd as long as the
     * potential for them to be referenced via this ap structure exists.
     *
     * These two derefs will be done by xpmem_release_ap() at the time
     * this ap structure is destroyed.
     */

    get_ex->apid = apid;
    return 0;
}

int xpmem_release_remote(struct xpmem_cmd_release_ex * release_ex) {
    struct xpmem_thread_group *ap_tg;
    struct xpmem_access_permit *ap;
    xpmem_apid_t apid = release_ex->apid;

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
    DBUG_ON(ap->tg != ap_tg);

    xpmem_release_ap(ap_tg, ap);
    xpmem_ap_deref(ap);
    xpmem_tg_deref(ap_tg);

    return 0;
}

int xpmem_attach_remote(struct xpmem_cmd_attach_ex * attach_ex) {
    int ret;
    u64 seg_vaddr, pfn, num_pfns, i;
    u64 * pfns;
    struct xpmem_thread_group *ap_tg, *seg_tg;
    struct xpmem_access_permit *ap;
    struct xpmem_segment *seg;

    xpmem_apid_t apid = attach_ex->apid;
    off_t offset = attach_ex->off;
    size_t size = attach_ex->size;

    if (apid <= 0)
        return -EINVAL;

    /* The offset of the attachment must be page aligned */
    if (offset_in_page(offset) != 0)
        return -EINVAL;

    /* If the size is not page aligned, fix it */
    if (offset_in_page(size) != 0)  
        size += PAGE_SIZE - offset_in_page(size);

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

    ret = xpmem_validate_remote_access(ap, offset, size, XPMEM_RDWR, &seg_vaddr);
    if (ret != 0)
        goto out_2;

    /* size needs to reflect page offset to start of segment */
    size += offset_in_page(seg_vaddr);

    /* This will allocate and pin pages in the source virtual address space */
    num_pfns = size / PAGE_SIZE;
    ret = xpmem_ensure_valid_PFNs(seg, seg_vaddr, num_pfns, 0);

    if (ret != 0) {
        printk(KERN_ERR "XPMEM: could not pin memory\n");
        goto out_2;
    }

    pfns = kmalloc(sizeof(u64) * num_pfns, GFP_KERNEL);
    if (!pfns) {
        printk(KERN_ERR "XPMEM: out of memory\n");
        ret = -ENOMEM;
        goto out_2;
    }

    for (i = 0; i < num_pfns; i++) {
        pfn = xpmem_vaddr_to_PFN(seg_tg->mm, seg_vaddr + (i * PAGE_SIZE));
        if (!pfn_valid(pfn)) {
            printk(KERN_ERR "XPMEM: invalid PFN\n");
            kfree(pfns);

            ret = -EFAULT;
            goto out_2;
        }
        pfns[i] = pfn;
    }

    attach_ex->num_pfns = num_pfns;
    attach_ex->pfns = pfns;

out_2:
    xpmem_seg_up_read(seg_tg, seg, 0);
out_1:
    xpmem_ap_deref(ap);
    xpmem_tg_deref(ap_tg);
    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);
    return ret;
}

int xpmem_detach_remote(struct xpmem_cmd_detach_ex * detach_ex) {
    return 0;
}
