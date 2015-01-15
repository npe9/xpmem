/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 */

/*
 * Cross Partition Memory (XPMEM) attach support.
 */

#include <linux/err.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/version.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>

/*
 * This function is called whenever a XPMEM address segment is unmapped.
 * We only expect this to occur from a XPMEM detach operation, and if that
 * is the case, there is nothing to do since the detach code takes care of
 * everything. In all other cases, something is tinkering with XPMEM vmas
 * outside of the XPMEM API, so we do the necessary cleanup and kill the
 * current thread group. The vma argument is the portion of the address space
 * that is being unmapped.
 */
static void
xpmem_close_handler(struct vm_area_struct *vma)
{
    struct vm_area_struct *remaining_vma;
    u64 remaining_vaddr;
    struct xpmem_access_permit *ap;
    struct xpmem_attachment *att;

    XPMEM_DEBUG("cleaning up");

    att = (struct xpmem_attachment *)vma->vm_private_data;
    if (att == NULL) {
        /* can happen if a user tries to mmap /dev/xpmem directly */
        return;
    }

    xpmem_att_ref(att);
    mutex_lock(&att->mutex);

    if (att->flags & XPMEM_FLAG_DESTROYING) {
        /* the unmap is being done normally via a detach operation */
        mutex_unlock(&att->mutex);
        xpmem_att_deref(att);
        XPMEM_DEBUG("already cleaned up");
        return;
    }

    /*
     * See if the entire vma is being unmapped. If so, clean up the
     * the xpmem_attachment structure and leave the vma to be cleaned up
     * by the kernel exit path.
     */
    if (vma->vm_start == att->at_vaddr &&
            ((vma->vm_end - vma->vm_start) == att->at_size)) {

        att->flags |= XPMEM_FLAG_DESTROYING;

        ap = att->ap;
        xpmem_ap_ref(ap);

        spin_lock(&ap->lock);
        list_del_init(&att->att_node);
        spin_unlock(&ap->lock);

        xpmem_ap_deref(ap);

        xpmem_att_destroyable(att);
        goto out;
    }

    /*
     * Find the starting vaddr of the vma that will remain after the unmap
     * has finished. The following if-statement tells whether the kernel
     * is unmapping the head, tail, or middle of a vma respectively.
     */
    if (vma->vm_start == att->at_vaddr)
        remaining_vaddr = vma->vm_end;
    else if (vma->vm_end == att->at_vaddr + att->at_size)
        remaining_vaddr = att->at_vaddr;
    else {
        /*
         * If the unmap occurred in the middle of vma, we have two
         * remaining vmas to fix up. We first clear out the tail vma
         * so it gets cleaned up at exit without any ties remaining
         * to XPMEM.
         */
        remaining_vaddr = vma->vm_end;
        remaining_vma = find_vma(current->mm, remaining_vaddr);
        BUG_ON(!remaining_vma ||
                remaining_vma->vm_start > remaining_vaddr ||
                remaining_vma->vm_private_data != vma->vm_private_data);

        /* this should be safe (we have the mmap_sem write-locked) */
        remaining_vma->vm_private_data = NULL;
        remaining_vma->vm_ops = NULL;

        /* now set the starting vaddr to point to the head vma */
        remaining_vaddr = att->at_vaddr;
    }

    /*
     * Find the remaining vma left over by the unmap split and fix
     * up the corresponding xpmem_attachment structure.
     */
    remaining_vma = find_vma(current->mm, remaining_vaddr);
    BUG_ON(!remaining_vma ||
            remaining_vma->vm_start > remaining_vaddr ||
            remaining_vma->vm_private_data != vma->vm_private_data);

    att->at_vaddr = remaining_vma->vm_start;
    att->at_size = remaining_vma->vm_end - remaining_vma->vm_start;

    /* clear out the private data for the vma being unmapped */
    vma->vm_private_data = NULL;

out:
    mutex_unlock(&att->mutex);
    xpmem_att_deref(att);

    /* cause the demise of the current thread group */
    printk("xpmem_close_handler: unexpected unmap of XPMEM segment at "
            "[0x%lx - 0x%lx]\n", vma->vm_start, vma->vm_end);
    sigaddset(&current->pending.signal, SIGKILL);
    set_tsk_thread_flag(current, TIF_SIGPENDING);
}

static int
xpmem_fault_handler(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    int ret;
    int seg_tg_mmap_sem_locked = 0, vma_verification_needed = 0;
    u64 vaddr = (u64)vmf->virtual_address;
    u64 seg_vaddr;
    unsigned long pfn = 0;
    struct xpmem_thread_group *ap_tg, *seg_tg;
    struct xpmem_access_permit *ap;
    struct xpmem_attachment *att;
    struct xpmem_segment *seg;
    sigset_t oldset;

    if (current->flags & PF_DUMPCORE)
        return VM_FAULT_SIGBUS;

    att = (struct xpmem_attachment *)vma->vm_private_data;
    if (att == NULL) {
        /*
         * Users who effectively bypass xpmem_attach() by opening
         * and mapping /dev/xpmem will have a NULL finfo and will
         * be killed here.
         */
        return VM_FAULT_SIGBUS;
    }

    xpmem_att_ref(att);
    ap = att->ap;
    xpmem_ap_ref(ap);
    ap_tg = ap->tg;
    xpmem_tg_ref(ap_tg);

    if ((ap->flags & XPMEM_FLAG_DESTROYING) ||
            (ap_tg->flags & XPMEM_FLAG_DESTROYING)) {
        xpmem_att_deref(att);
        xpmem_ap_deref(ap);
        xpmem_tg_deref(ap_tg);
        return VM_FAULT_SIGBUS;
    }

    if (ap->flags & XPMEM_AP_REMOTE) {
        xpmem_att_deref(att);
        xpmem_ap_deref(ap);
        xpmem_tg_deref(ap_tg);
        return VM_FAULT_SIGBUS;
    }

    DBUG_ON(current->tgid != ap_tg->tgid);
    DBUG_ON(ap->mode != XPMEM_RDWR);

    seg = ap->seg;
    xpmem_seg_ref(seg);
    seg_tg = seg->tg;
    xpmem_tg_ref(seg_tg);

    /*
     * The faulting thread has its mmap_sem locked on entrance to this
     * fault handler. In order to supply the missing page we will need
     * to get access to the segment that has it, as well as lock the
     * mmap_sem of the thread group that owns the segment should it be
     * different from the faulting thread's. Together these provide the
     * potential for a deadlock, which we attempt to avoid in what follows.
     */

    ret = xpmem_seg_down_read(seg_tg, seg, 1, 0);

avoid_deadlock_1:
    if (ret == -EAGAIN) {
        /* to avoid possible deadlock drop current->mm->mmap_sem */
        up_read(&current->mm->mmap_sem);
        ret = xpmem_seg_down_read(seg_tg, seg, 1, 1);
        down_read(&current->mm->mmap_sem);
        vma_verification_needed = 1;
    }
    if (ret != 0)
        goto out_1;

avoid_deadlock_2:
    /* verify vma hasn't changed due to dropping current->mm->mmap_sem */
    if (vma_verification_needed) {
        struct vm_area_struct *retry_vma;

        retry_vma = find_vma(current->mm, vaddr);
        if (!retry_vma ||
                retry_vma->vm_start > vaddr ||
                !xpmem_is_vm_ops_set(retry_vma) ||
                retry_vma->vm_private_data != att)
            goto out_2;
        vma_verification_needed = 0;
    }

    xpmem_block_nonfatal_signals(&oldset);
    if (mutex_lock_interruptible(&att->mutex)) {
        xpmem_unblock_nonfatal_signals(&oldset);
        goto out_2;
    }
    xpmem_unblock_nonfatal_signals(&oldset);

    if ((att->flags & XPMEM_FLAG_DESTROYING) ||
            (ap_tg->flags & XPMEM_FLAG_DESTROYING) ||
            (seg_tg->flags & XPMEM_FLAG_DESTROYING))
        goto out_3;

    if (vaddr < att->at_vaddr || vaddr + 1 > att->at_vaddr + att->at_size)
        goto out_3;

    /* translate the fault virtual address to the source virtual address */
    seg_vaddr = ((u64)att->vaddr & PAGE_MASK) + (vaddr - att->at_vaddr);
    XPMEM_DEBUG("vaddr = %llx, seg_vaddr = %llx", vaddr, seg_vaddr);

    if (!seg_tg_mmap_sem_locked &&
            &current->mm->mmap_sem > &seg_tg->mm->mmap_sem) {
        /*
         * The faulting thread's mmap_sem is numerically smaller
         * than the seg's thread group's mmap_sem address-wise,
         * therefore we need to acquire the latter's mmap_sem in a
         * safe manner before calling xpmem_ensure_valid_PFNs() to
         * avoid a potential deadlock.
         */
        seg_tg_mmap_sem_locked = 1;
        atomic_inc(&seg_tg->mm->mm_users);
        if (!down_read_trylock(&seg_tg->mm->mmap_sem)) {
            mutex_unlock(&att->mutex);
            up_read(&current->mm->mmap_sem);
            down_read(&seg_tg->mm->mmap_sem);
            down_read(&current->mm->mmap_sem);
            vma_verification_needed = 1;
            goto avoid_deadlock_2;
        }
    }

    ret = xpmem_ensure_valid_PFNs(seg, seg_vaddr, 1,
            seg_tg_mmap_sem_locked);
    if (seg_tg_mmap_sem_locked) {
        up_read(&seg_tg->mm->mmap_sem);
        atomic_dec(&seg_tg->mm->mm_users);
        seg_tg_mmap_sem_locked = 0;
    }
    if (ret != 0) {
        if (ret == -EAGAIN) {
            mutex_unlock(&att->mutex);
            xpmem_seg_up_read(seg_tg, seg, 1);
            goto avoid_deadlock_1;
        }
        goto out_3;
    }

    pfn = xpmem_vaddr_to_PFN(seg_tg->mm, seg_vaddr);

    att->flags |= XPMEM_FLAG_VALIDPTEs;

out_3:
    mutex_unlock(&att->mutex);
out_2:
    if (seg_tg_mmap_sem_locked) {
        up_read(&seg_tg->mm->mmap_sem);
        atomic_dec(&seg_tg->mm->mm_users);
    }
    xpmem_seg_up_read(seg_tg, seg, 1);
out_1:
    xpmem_att_deref(att);
    xpmem_ap_deref(ap);
    xpmem_tg_deref(ap_tg);
    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);
    if (pfn_valid(pfn) && pfn > 0) {
        XPMEM_DEBUG("calling remap_pfn_range() vaddr=%llx, pfn=%lx",
                vaddr, pfn);
        ret = remap_pfn_range(vma, vaddr, pfn, PAGE_SIZE,
                vma->vm_page_prot);
        if (!ret)
            return VM_FAULT_NOPAGE;
    }
    return VM_FAULT_SIGBUS;
}

struct vm_operations_struct xpmem_vm_ops = {
    .close = xpmem_close_handler,
    .fault = xpmem_fault_handler
};

/*
 * This function is called via the Linux kernel mmap() code, which is
 * instigated by the call to do_mmap() in xpmem_attach().
 */
int
xpmem_mmap(struct file *file, struct vm_area_struct *vma)
{
    /*
     * When a mapping is related to a file, the file pointer is typically
     * stored in vma->vm_file and a fput() is done to it when the VMA is
     * unmapped. Since file is of no interest in XPMEM's case, we ensure
     * vm_file is empty and do the fput() here.
     */
    vma->vm_file = NULL;
    fput(file);

    vma->vm_ops = &xpmem_vm_ops;
    return 0;
}

/*
 * Attach a remote XPMEM address segment
 */
static int
xpmem_try_attach_remote(xpmem_segid_t segid, 
                        xpmem_apid_t  apid,
                        off_t         offset,
                        size_t        size,
                        u64           at_vaddr)
{
    return xpmem_attach_remote(
        &(xpmem_my_part->part_state),
        segid,
        apid,
        offset,
        size,
        at_vaddr);
}


static unsigned long
do_xpmem_mmap(struct file * file, 
              unsigned long addr, 
              unsigned long len, 
              unsigned long prot,
              unsigned long flags,
              unsigned long offset)
{
    unsigned long vaddr = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
    vaddr = do_mmap(file, addr, len, prot, flags, offset);
#else
    up_write(&current->mm->mmap_sem);
    vaddr = vm_mmap(file, addr, len, prot, flags, offset);
    down_write(&current->mm->mmap_sem);
#endif

    return vaddr;
}

static int
do_xpmem_munmap(struct mm_struct * mm,
                unsigned long      addr,
                unsigned long      size)
{
    int ret = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
    ret = do_munmap(mm, addr, size);
#else
    up_write(&current->mm->mmap_sem);
    ret = vm_munmap(addr, size);
    down_write(&current->mm->mmap_sem);
#endif

    return ret;
}


/*
 * Attach a XPMEM address segment.
 */
int
xpmem_attach(struct file *file, xpmem_apid_t apid, off_t offset, size_t size,
        u64 vaddr, int fd, int att_flags, u64 *at_vaddr_p)
{
    int ret;
    unsigned long flags, prot_flags = PROT_READ | PROT_WRITE;
    u64 seg_vaddr, at_vaddr;
    struct xpmem_thread_group *ap_tg, *seg_tg;
    struct xpmem_access_permit *ap;
    struct xpmem_segment *seg;
    struct xpmem_attachment *att;
    struct vm_area_struct *vma;

    if (apid <= 0)
        return -EINVAL;

    /* Ensure vaddr is valid */
    if (vaddr && vaddr + PAGE_SIZE - offset_in_page(vaddr) >= TASK_SIZE)
        return -EINVAL;

    /* The start of the attachment must be page aligned */
    if (offset_in_page(vaddr) != 0 || offset_in_page(offset) != 0)
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

    ret = xpmem_validate_access(ap_tg, ap, offset, size, XPMEM_RDWR, &seg_vaddr);
    if (ret != 0)
        goto out_2;

    /* size needs to reflect page offset to start of segment */
    size += offset_in_page(seg_vaddr);

    /*
     * Ensure thread is not attempting to attach its own memory on top
     * of itself (i.e. ensure the destination vaddr range doesn't overlap
     * the source vaddr range).
     */
    seg = ap->seg;
    if (current->tgid == seg_tg->tgid && vaddr) {
        if ((vaddr + size > seg_vaddr) && (vaddr < seg_vaddr + size)) {
            ret = -EINVAL;
            goto out_2;
        }
    }

    /* create new attach structure */
    att = kzalloc(sizeof(struct xpmem_attachment), GFP_KERNEL);
    if (att == NULL) {
        ret = -ENOMEM;
        goto out_2;
    }

    mutex_init(&att->mutex);
    att->vaddr = seg_vaddr;
    att->at_size = size;
    att->ap = ap;
    INIT_LIST_HEAD(&att->att_node);
    att->mm = current->mm;

    xpmem_att_not_destroyable(att);
    xpmem_att_ref(att);

    /* must lock mmap_sem before att's sema to prevent deadlock */
    down_write(&current->mm->mmap_sem);
    mutex_lock(&att->mutex);    /* this will never block */

    /* link attach structure to its access permit's att list */
    spin_lock(&ap->lock);
    list_add_tail(&att->att_node, &ap->att_list);
    if (ap->flags & XPMEM_FLAG_DESTROYING) {
        spin_unlock(&ap->lock);
        ret = -ENOENT;
        goto out_3;
    }
    spin_unlock(&ap->lock);

    flags = MAP_SHARED;
    if (vaddr != (u64)NULL)
        flags |= MAP_FIXED;

    /* check if a segment is already attached in the requested area */
    if (flags & MAP_FIXED) {
        struct vm_area_struct *existing_vma;

        existing_vma = find_vma_intersection(current->mm, vaddr,
                vaddr + size);
        for ( ; existing_vma && existing_vma->vm_start < vaddr + size
                ; existing_vma = existing_vma->vm_next) {
            if (xpmem_is_vm_ops_set(existing_vma)) {
                ret = -EINVAL;
                goto out_3;
            }
        }
    }

    at_vaddr = do_xpmem_mmap(file, vaddr, size, prot_flags, flags, offset);
    if (IS_ERR((void *)at_vaddr)) {
        ret = at_vaddr;
        goto out_3;
    }

    /* if remote, load pfns in now */
    if (ap->flags & XPMEM_AP_REMOTE) {
        DBUG_ON(ap->remote_apid <= 0);
        if (xpmem_try_attach_remote(seg->segid, ap->remote_apid, offset, size, at_vaddr) != 0) {
            do_xpmem_munmap(current->mm, at_vaddr, size);
            ret = -EFAULT;
            goto out_3;
        }
    }

    att->at_vaddr = at_vaddr;

    vma = find_vma(current->mm, at_vaddr);
    vma->vm_private_data = att;
    vma->vm_flags |=
        VM_DONTCOPY /*| VM_RESERVED*/ | VM_IO | VM_DONTEXPAND | VM_PFNMAP;
    vma->vm_ops = &xpmem_vm_ops;

    att->at_vma = vma;

    /*
     * The attach point where we mapped the portion of the segment the
     * user was interested in is page aligned. But the start of the portion
     * of the segment may not be, so we adjust the address returned to the
     * user by that page offset difference so that what they see is what
     * they expected to see.
     */
    *at_vaddr_p = at_vaddr + offset_in_page(att->vaddr);

    ret = 0;
out_3:
    if (ret != 0) {
        att->flags |= XPMEM_FLAG_DESTROYING;
        spin_lock(&ap->lock);
        list_del_init(&att->att_node);
        spin_unlock(&ap->lock);
        xpmem_att_destroyable(att);
    }
    mutex_unlock(&att->mutex);
    up_write(&current->mm->mmap_sem);
    xpmem_att_deref(att);
out_2:
    xpmem_seg_up_read(seg_tg, seg, 0);
out_1:
    xpmem_ap_deref(ap);
    xpmem_tg_deref(ap_tg);
    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);
    return ret;
}

/*
 * Detach an attached XPMEM address segment.
 */
int
xpmem_detach(u64 at_vaddr)
{
    int ret;
    struct xpmem_access_permit *ap;
    struct xpmem_attachment *att;
    struct vm_area_struct *vma;
    sigset_t oldset;

    down_write(&current->mm->mmap_sem);

    /* find the corresponding vma */
    vma = find_vma(current->mm, at_vaddr);
    if (!vma || vma->vm_start > at_vaddr) {
        up_write(&current->mm->mmap_sem);
        return 0;
    }

    att = (struct xpmem_attachment *)vma->vm_private_data;
    if (!xpmem_is_vm_ops_set(vma) || att == NULL) {
        up_write(&current->mm->mmap_sem);
        return PTR_ERR(att);
    }
    xpmem_att_ref(att);

    xpmem_block_nonfatal_signals(&oldset);
    
    if (mutex_lock_interruptible(&att->mutex)) {
        xpmem_unblock_nonfatal_signals(&oldset);
        xpmem_att_deref(att);
        up_write(&current->mm->mmap_sem);
        return -EINTR;
    }
    
    xpmem_unblock_nonfatal_signals(&oldset);

    if (att->flags & XPMEM_FLAG_DESTROYING) {
        mutex_unlock(&att->mutex);
        xpmem_att_deref(att);
        up_write(&current->mm->mmap_sem);
        return 0;
    }
    att->flags |= XPMEM_FLAG_DESTROYING;

    ap = att->ap;
    xpmem_ap_ref(ap);

    if (current->tgid != ap->tg->tgid) {
        att->flags &= ~XPMEM_FLAG_DESTROYING;
        xpmem_ap_deref(ap);
        mutex_unlock(&att->mutex);
        xpmem_att_deref(att);
        up_write(&current->mm->mmap_sem);
        return -EACCES;
    }

    /* NOTE: ATT_REMOTE is not possible here, because ATT_REMOTE attachments are only for
     * remote processes attaching local memory 
     */

    if (ap->flags & XPMEM_AP_REMOTE) {
        u64 pa = 0;

        xpmem_detach_remote(&(xpmem_my_part->part_state), ap->seg->segid, ap->remote_apid, att->at_vaddr);

        /* Free from Palacios, if we're in a VM */ 
        pa = xpmem_vaddr_to_PFN(att->mm, att->at_vaddr) << PAGE_SHIFT;
        if (pa == 0) {
            XPMEM_ERR("Cannot find pa for vaddr %p, cannot detach in Palacios\n", (void *)att->at_vaddr);
        } else {
            xpmem_palacios_detach_paddr(&(xpmem_my_part->part_state), pa);
        }
    } else {
        xpmem_unpin_pages(ap->seg, current->mm, att->at_vaddr, att->at_size);
    }

    vma->vm_private_data = NULL;

    ret = do_xpmem_munmap(current->mm, vma->vm_start, att->at_size);
    DBUG_ON(ret != 0);

    att->flags &= ~XPMEM_FLAG_VALIDPTEs;

    spin_lock(&ap->lock);
    list_del_init(&att->att_node);
    spin_unlock(&ap->lock);

    mutex_unlock(&att->mutex);
    up_write(&current->mm->mmap_sem);

    xpmem_att_destroyable(att);

    xpmem_ap_deref(ap);
    xpmem_att_deref(att);

    return 0;
}

/*
 * Detach a remote attached XPMEM address segment. 
 */
static void
xpmem_detach_remote_att(struct xpmem_access_permit *ap, struct xpmem_attachment *att)
{
    struct xpmem_segment *seg;
    struct xpmem_thread_group* seg_tg;

    seg = ap->seg;
    xpmem_seg_ref(seg);
    seg_tg = seg->tg;
    xpmem_tg_ref(seg_tg);

    down_write(&seg_tg->mm->mmap_sem);
    mutex_lock(&att->mutex);

    if (att->flags & XPMEM_FLAG_DESTROYING) {
        xpmem_seg_deref(seg);
        xpmem_tg_deref(seg_tg);
        mutex_unlock(&att->mutex);
        up_write(&seg_tg->mm->mmap_sem);
        return;
    }

    att->flags |= XPMEM_FLAG_DESTROYING;

    /* We unpin from the source address space. This basically does a put_page on each
     * page from att->vaddr (which is set to the source vaddr) for at_size length, which
     * is exactly what we want
     */

//    xpmem_unpin_pages(seg, seg_tg->mm, att->vaddr, att->at_size);

    xpmem_seg_deref(seg);
    xpmem_tg_deref(seg_tg);

    att->flags &= ~XPMEM_FLAG_VALIDPTEs;

    spin_lock(&ap->lock);
    list_del_init(&att->att_node);
    spin_unlock(&ap->lock);

    mutex_unlock(&att->mutex);
    up_write(&seg_tg->mm->mmap_sem);

    xpmem_att_destroyable(att);
}

/*
 * Detach an attached XPMEM address segment. This is functionally identical
 * to xpmem_detach(). It is called when ap and att are known.
 */
void
xpmem_detach_att(struct xpmem_access_permit *ap, struct xpmem_attachment *att)
{
    struct vm_area_struct *vma;
    int ret = 0;

    if (att->flags & XPMEM_ATT_REMOTE) {
        xpmem_detach_remote_att(ap, att);
        return;
    }

    /* must lock mmap_sem before att's sema to prevent deadlock */
    down_write(&att->mm->mmap_sem);
    mutex_lock(&att->mutex);

    if (att->flags & XPMEM_FLAG_DESTROYING) {
        mutex_unlock(&att->mutex);
        up_write(&att->mm->mmap_sem);
        return;
    }
    att->flags |= XPMEM_FLAG_DESTROYING;

    /* find the corresponding vma */
    vma = find_vma(att->mm, att->at_vaddr);
    if (!vma || vma->vm_start > att->at_vaddr) {
        DBUG_ON(1);
        mutex_unlock(&att->mutex);
        up_write(&att->mm->mmap_sem);
        return;
    }
    DBUG_ON(!xpmem_is_vm_ops_set(vma));
    DBUG_ON((vma->vm_end - vma->vm_start) != att->at_size);
    DBUG_ON(vma->vm_private_data != att);

    if (ap->flags & XPMEM_AP_REMOTE) {
        u64 pa = 0;

        xpmem_detach_remote(&(xpmem_my_part->part_state), ap->seg->segid, ap->remote_apid, att->at_vaddr);

        /* Free from Palacios, if we're in a VM */ 
        pa = xpmem_vaddr_to_PFN(att->mm, att->at_vaddr) << PAGE_SHIFT;
        if (pa == 0) {
            XPMEM_ERR("Cannot find pa for vaddr %p, cannot detach in Palacios\n", (void *)att->at_vaddr);
        } else {
            xpmem_palacios_detach_paddr(&(xpmem_my_part->part_state), pa);
        }
    } else {
        xpmem_unpin_pages(ap->seg, att->mm, att->at_vaddr, att->at_size);
    }

    vma->vm_private_data = NULL;

    //ret = do_munmap(att->mm, vma->vm_start, att->at_size);
    if (att->mm == current->mm)
    {
        ret = do_xpmem_munmap(att->mm, vma->vm_start, att->at_size);
        DBUG_ON(ret != 0);
    }

    att->flags &= ~XPMEM_FLAG_VALIDPTEs;

    spin_lock(&ap->lock);
    list_del_init(&att->att_node);
    spin_unlock(&ap->lock);

    mutex_unlock(&att->mutex);
    up_write(&att->mm->mmap_sem);

    xpmem_att_destroyable(att);
}

/*
 * Clear all of the PTEs associated with the specified attachment within the
 * range specified by start and end. The last argument needs to be 0 except
 * when called by the mmu notifier.
 */
static void
xpmem_clear_PTEs_of_att(struct xpmem_attachment *att, u64 start, u64 end,
        int from_mmu)
{
    int locked_mmap = 1, locked_att = 1;

    /*
     * This function should ideally acquire both att->mm->mmap_sem
     * and att->mutex.  However, if it is called from a MMU notifier
     * function, we can not sleep (something both down_read() and
     * mutex_lock() can do).  For MMU notifier callouts, we try to
     * acquire the locks once anyway, but if one or both locks were
     * not acquired, we are technically OK for this function since other
     * XPMEM functions assure that the vma structure will not be freed
     * from underneath us, and the prior call to xpmem_att_ref() before
     * entering the function unsures that att will be valid.
     *
     * Must lock mmap_sem before att's sema to prevent deadlock.
     */


    if (from_mmu) {
        locked_mmap = down_read_trylock(&att->mm->mmap_sem);
        locked_att = mutex_trylock(&att->mutex);
    } else {
        down_read(&att->mm->mmap_sem);
        mutex_lock(&att->mutex);
    }

    /*
     * The att may have been detached before the down() succeeded.
     * If not, clear kernel PTEs, flush TLBs, etc.
     */
    if (att->flags & XPMEM_FLAG_VALIDPTEs) {
        struct vm_area_struct *vma;
        u64 invalidate_start, invalidate_end, invalidate_len;
        u64 offset_start, offset_end, unpin_at;
        u64 att_vaddr_end = att->vaddr + att->at_size;

        /* 
         * SOURCE   [ PG 0 | PG 1 | PG 2 | PG 3 | PG 4 | ... ]
         *          ^                    ^
         *          |                    |
         *  seg->vaddr                 att->vaddr
         *
         *          [ attach_info.offset ]
         *
         * ------------------------------------------------------
         *
         * ATTACH   [ PG 3 | PG 4 | ... ]
         *          ^                   ^
         *          |                   |
         * att->at_vaddr          att_vaddr_end
         *
         * The invalidate range (start, end) arguments are originally
         * in the source address space.
         *
         * Convert the attachment address space to the source address
         * space and find the intersection with (start, end).
         */
        invalidate_start = max(start, att->vaddr);
        if (invalidate_start >= att_vaddr_end)
            goto out;
        invalidate_end = min(end, att_vaddr_end);
        if (invalidate_end <= att->vaddr)
            goto out;

        /* Convert the intersection of vaddr into offsets. */
        offset_start = invalidate_start - att->vaddr;
        offset_end = invalidate_end - att->vaddr;

        /*
         * Add the starting offset to the attachment's starting vaddr
         * to get the invalidate range in the attachment address space.
         */
        unpin_at = att->at_vaddr + offset_start;
        invalidate_len = offset_end - offset_start;
        DBUG_ON(offset_in_page(unpin_at) ||
                offset_in_page(invalidate_len));
        XPMEM_DEBUG("unpin_at = %llx, invalidate_len = %llx\n",
                unpin_at, invalidate_len);

        /* Unpin the pages if the access permit is local */
        if (!(att->ap->flags & XPMEM_AP_REMOTE)) {
            xpmem_unpin_pages(att->ap->seg, att->mm, unpin_at,
                    invalidate_len);
        }

        /*
         * Clear the PTEs, using the vma out of the att if we
         * couldn't acquire the mmap_sem.
         */
        if (!locked_mmap)
            vma = att->at_vma;
        else
            vma = find_vma(att->mm, att->at_vaddr);
        zap_page_range(vma, unpin_at, invalidate_len, NULL);

        /* Only clear the flag if all pages were zapped */
        if (offset_start == 0 && att->at_size == invalidate_len)
            att->flags &= ~XPMEM_FLAG_VALIDPTEs;
    }
out:
    if (locked_att)
        mutex_unlock(&att->mutex);
    if (locked_mmap)
        up_read(&att->mm->mmap_sem);
}

/*
 * Clear all of the PTEs associated with all attachments related to the
 * specified access permit within the range specified by start and end.
 * The last argument needs to be 0 except when called by the mmu notifier.
 */
static void
xpmem_clear_PTEs_of_ap(struct xpmem_access_permit *ap, u64 start, u64 end,
        int from_mmu)
{
    struct xpmem_attachment *att;

    spin_lock(&ap->lock);
    list_for_each_entry(att, &ap->att_list, att_node) {
        if (!(att->flags & XPMEM_FLAG_VALIDPTEs))
            continue;

        xpmem_att_ref(att);  /* don't care if XPMEM_FLAG_DESTROYING */
        spin_unlock(&ap->lock);

        xpmem_clear_PTEs_of_att(att, start, end, from_mmu);

        spin_lock(&ap->lock);
        if (list_empty(&att->att_node)) {
            /* att was deleted from ap->att_list, start over */
            xpmem_att_deref(att);
            att = list_entry(&ap->att_list, struct xpmem_attachment,
                    att_node);
        } else
            xpmem_att_deref(att);
    }
    spin_unlock(&ap->lock);
}

/*
 * Clear all of the PTEs associated with all attaches to the specified segment
 * within the range specified by start and end. The last argument needs to be
 * 0 except when called by the mmu notifier.
 */
void
xpmem_clear_PTEs_range(struct xpmem_segment *seg, u64 start, u64 end,
        int from_mmu)
{
    struct xpmem_access_permit *ap;

    spin_lock(&seg->lock);
    list_for_each_entry(ap, &seg->ap_list, ap_node) {
        xpmem_ap_ref(ap);  /* don't care if XPMEM_FLAG_DESTROYING */
        spin_unlock(&seg->lock);

        xpmem_clear_PTEs_of_ap(ap, start, end, from_mmu);

        spin_lock(&seg->lock);
        if (list_empty(&ap->ap_node)) {
            /* ap was deleted from seg->ap_list, start over */
            xpmem_ap_deref(ap);
            ap = list_entry(&seg->ap_list,
                    struct xpmem_access_permit, ap_node);
        } else
            xpmem_ap_deref(ap);
    }
    spin_unlock(&seg->lock);
}

/*
 * Wrapper for xpmem_clear_PTEs_range() that uses the max range
 */
void xpmem_clear_PTEs(struct xpmem_segment *seg)
{
    xpmem_clear_PTEs_range(seg, seg->vaddr, seg->vaddr + seg->size, 0);
}
