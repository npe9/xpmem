/*
 * XPMEM mmu notifier related operations and callback function definitions.
 *
 * Copyright (c) 2010 Cray, Inc.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. See the file "COPYING" in the main directory of this archive for
 * more details.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/percpu.h>

#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>

#include <xpmem.h>
#include <xpmem_private.h>

static inline void
xpmem_invalidate_PTEs_range(struct xpmem_thread_group *seg_tg,
			    unsigned long start, unsigned long end)
{
	struct xpmem_segment *seg;
	u64 seg_start, seg_end;

	read_lock(&seg_tg->seg_list_lock);
	list_for_each_entry(seg, &seg_tg->seg_list, seg_list) {
		if (!(seg->flags & XPMEM_FLAG_DESTROYING)) {
			seg_start = seg->vaddr;
			seg_end = seg->vaddr + seg->size;

			if (start <= seg_end && end >= seg_start) {
				XPMEM_DEBUG("start=%lx, end=%lx", start, end);
				xpmem_clear_PTEs_range(seg, start, end, 1);
			}
		}
	}
	read_unlock(&seg_tg->seg_list_lock);
}

/*
 * MMU notifier callout for invalidating a range of pages.
 *
 * XPMEM only uses the invalidate_range_end() portion. That is, when all pages
 * in the range have been unmapped and the pages have been freed by the VM.
 */
static void
xpmem_invalidate_range(struct mmu_notifier *mn, struct mm_struct *mm,
		       unsigned long start, unsigned long end)
{
	struct xpmem_thread_group *seg_tg;
	struct vm_area_struct *vma;
	//struct mmu_gather *tlb;
	//struct mm_struct *tlb_mm;
	//unsigned int tlb_fullmm;
	struct mmu_gather tlb;

	seg_tg = container_of(mn, struct xpmem_thread_group, mmu_not);

	/*
	 * This invalidate callout came from a destination address space
	 * and we can return because we have already done all the necessary
	 * invalidate operations.
	 */
	if (seg_tg->tgid != current->tgid)
		return;

	if (offset_in_page(start) != 0)
		start -= offset_in_page(start);
	if (offset_in_page(end) != 0)
		end += PAGE_SIZE - offset_in_page(end);
	/*
	 * Save off some mmu_gather data so we can restore it before returning
	 * to the kernel.  This is needed because XPMEM, via the MMU notifier
	 * callout, can call zap_page_range() which itself does a
	 * tlb_gather_mmu().  Since the kernel itself may be part-way 
	 * through a tlb_gather_mmu/tlb_finish_mmu seqeuence itself when
	 * calling the MMU notifier, we need to restore this mmu state before
	 * returning.
	 */
	//tlb = &get_cpu_var(mmu_gathers);
	//tlb_mm = tlb->mm;
	//tlb_fullmm = tlb->fullmm;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    tlb_gather_mmu(&tlb, mm, 1);
#else
    tlb_gather_mmu(&tlb, mm, start, end);
#endif

	/*
	 * We could be in the middle of an unmap_region() -> unmap_vmas() which
	 * eventually calls tlb_finish_mmu() to flush the tlb. However, we
	 * later call zap_page_range() on a different mm, thus wiping out the
	 * work needed to be done by tlb_finish_mmu() in unmap_region(). So to
	 * prevent this work from being neglected, we flush out the tlb here.
	 */
	//if (tlb->need_flush)
	//	tlb_flush_mmu(tlb, start, end);
	if (tlb.need_flush)
		tlb_flush_mmu(&tlb);
		//tlb_flush_mmu(&tlb, start, end);

	vma = find_vma_intersection(mm, start, end);
	if (vma == NULL) {
		xpmem_invalidate_PTEs_range(seg_tg, start, end);
		goto out;
	}
	for ( ; vma && vma->vm_start < end; vma = vma->vm_next) {
		unsigned long vm_start;
		unsigned long vm_end;

		/*
		 * If the vma is XPMEM-attached memory, bail out.  XPMEM handles
		 * this case outside of the MMU notifier functions and we don't
		 * want xpmem_invalidate_range() to perform the operations a
		 * second time and screw up page counts, etc. We can't block in
		 * an MMU notifier callout, so we skip locking the mmap_sem
		 * around the call to find_vma(). This is OK however since the
		 * kernel can't rearrange the address space while a MMU notifier
		 * callout is occurring.
		 */
		if (xpmem_is_vm_ops_set(vma))
			continue;

		vm_start = max(vma->vm_start, start);
		if (vm_start >= vma->vm_end)
			continue;

		vm_end = min(vma->vm_end, end);
		if (vm_end <= vma->vm_start)
			continue;

		xpmem_invalidate_PTEs_range(seg_tg, vm_start, vm_end);
	}
out:
	/* restore the mmu state */
	//(void) tlb_gather_mmu(tlb_mm, tlb_fullmm);
	//put_cpu_var(mmu_gathers);
    tlb_finish_mmu(&tlb, start, end);
}

/*
 * MMU notifier callout for invalidating a single page.
 */
static void
xpmem_invalidate_page(struct mmu_notifier *mn, struct mm_struct *mm,
		      unsigned long start)
{
	xpmem_invalidate_range(mn, mm, start, start + PAGE_SIZE);
}

static const struct mmu_notifier_ops xpmem_mmuops = {
	.invalidate_page	= xpmem_invalidate_page,
	.invalidate_range_end	= xpmem_invalidate_range,
};

/*
 * Initialize MMU notifier related fields in the XPMEM segment, and register
 * for MMU callbacks.
 */
int
xpmem_mmu_notifier_init(struct xpmem_thread_group *tg)
{
	int ret;

	if (!tg) {
		return -EFAULT;
	}

	if (!tg->mmu_initialized) {
		tg->mmu_not.ops = &xpmem_mmuops;
		tg->mmu_unregister_called = 0;
		XPMEM_DEBUG("tg->mm=%p", tg->mm);
		ret = mmu_notifier_register(&tg->mmu_not, tg->mm);
		if (ret)
			return ret;

		tg->mmu_initialized = 1;
	}

	return 0;
}

/*
 * Unlink MMU notifier callbacks
 */
void
xpmem_mmu_notifier_unlink(struct xpmem_thread_group *tg)
{
	if (tg && tg->mmu_initialized && !tg->mmu_unregister_called) {
		XPMEM_DEBUG("tg->mm=%p", tg->mm);
		mmu_notifier_unregister(&tg->mmu_not, tg->mm);
		tg->mmu_unregister_called = 1;
	}
}
