/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 */

/*
 * Private Cross Partition Memory (XPMEM) structures and macros.
 */

#ifndef _XPMEM_PRIVATE_H
#define _XPMEM_PRIVATE_H

#include <linux/version.h>
#include <linux/bit_spinlock.h>
#include <linux/sched.h>
#include <linux/hugetlb.h>
#include <asm/signal.h>

#include <xpmem.h>
#include <xpmem_partition.h>
#include <xpmem_extended.h>


#ifdef CONFIG_MMU_NOTIFIER
#include <linux/mmu_notifier.h>
#else
#error "Kernel needs to be configured with CONFIG_MMU_NOTIFIER"
#endif /* CONFIG_MMU_NOTIFIER */

/*
 * XPMEM_CURRENT_VERSION is used to identify functional differences
 * between various releases of XPMEM to users. XPMEM_CURRENT_VERSION_STRING
 * is printed when the kernel module is loaded and unloaded.
 *
 *   version  differences
 *
 *     1.0    initial implementation of XPMEM
 *     1.1    fetchop (AMO) pages supported
 *     1.2    GET space and write combining attaches supported
 *     1.3    Convert to build for both 2.4 and 2.6 versions of kernel
 *     1.4    add recall PFNs RPC
 *     1.5    first round of resiliency improvements
 *     1.6    make coherence domain union of sharing partitions
 *     2.0    replace 32-bit xpmem_handle_t by 64-bit xpmem_segid_t
 *            replace 32-bit xpmem_id_t by 64-bit xpmem_apid_t
 *     2.1    CRAY: remove PFNtable cache
 *     2.2    CRAY: add support for MMU notifiers
 *
 *     3.0    U. Pittsburgh: add support for multi-enclave environments
 *
 * This int constant has the following format:
 *
 *      +----+------------+----------------+
 *      |////|   major    |     minor      |
 *      +----+------------+----------------+
 *
 *       major - major revision number (12-bits)
 *       minor - minor revision number (16-bits)
 */
#define XPMEM_CURRENT_VERSION       0x00030000
#define XPMEM_CURRENT_VERSION_STRING    "3.0"

#define XPMEM_MODULE_NAME "xpmem"

#ifdef USE_DBUG_ON
#define DBUG_ON(condition)      BUG_ON(condition)
#else
#define DBUG_ON(condition)
#endif

extern uint32_t xpmem_debug_on;

#define XPMEM_DEBUG(format, a...)                   \
    if (xpmem_debug_on)                     \
        printk("[%d]%s: "format"\n", current->tgid, __func__, ##a);

#define delayed_work work_struct

static inline pte_t *
xpmem_hugetlb_pte(struct mm_struct *mm, u64 vaddr, u64 *offset)
{
    struct vm_area_struct *vma;
    u64 address;
    pte_t *pte;

    vma = find_vma(mm, vaddr);
    if (!vma)
        return NULL;
    
    if (is_vm_hugetlb_page(vma)) {
        struct hstate *hs = hstate_vma(vma);

        address = vaddr & huge_page_mask(hs);
        if (offset) {
            *offset = (vaddr & (huge_page_size(hs) - 1)) & PAGE_MASK;
            XPMEM_DEBUG("vaddr = %llx, offset = %llx", vaddr, *offset);
        }
        
#ifdef CONFIG_CRAY_MRT
        pte = huge_pte_offset(mm, address, huge_page_size(hs));
#else
        pte = huge_pte_offset(mm, address);
#endif
        XPMEM_DEBUG("pte = %lx", pte_val(*pte));

        if (!pte || pte_none(*pte))
            return NULL;
        
        return (pte_t *)pte;
    }

    /*
     * We should never enter this area since xpmem_hugetlb_pte() is only
     * called if {pgd,pud,pmd}_large() is true
     */
    BUG();
}

/*
 * Given an address space and a virtual address return a pointer to its
 * pte if one is present.
 */
static inline pte_t *
xpmem_vaddr_to_pte_offset(struct mm_struct *mm, u64 vaddr, u64 *offset)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    if (offset)
        *offset = 0;

    pgd = pgd_offset(mm, vaddr);
    if (!pgd_present(*pgd))
        return NULL;
    else if (pgd_large(*pgd)) {
        XPMEM_DEBUG("pgd = %p", pgd);
        return xpmem_hugetlb_pte(mm, vaddr, offset);
    }

    pud = pud_offset(pgd, vaddr);
    if (!pud_present(*pud))
        return NULL;
    else if (pud_large(*pud)) {
        XPMEM_DEBUG("pud = %p", pud);
        return xpmem_hugetlb_pte(mm, vaddr, offset);
    }

    pmd = pmd_offset(pud, vaddr);
    if (!pmd_present(*pmd))
        return NULL;
    else if (pmd_large(*pmd)) {
        XPMEM_DEBUG("pmd = %p", pmd);
        return xpmem_hugetlb_pte(mm, vaddr, offset);
    }

    pte = pte_offset_map(pmd, vaddr);
    if (!pte_present(*pte))
        return NULL;

    return pte;
}

static inline pte_t *
xpmem_vaddr_to_pte(struct mm_struct *mm, u64 vaddr)
{
    return xpmem_vaddr_to_pte_offset(mm, vaddr, NULL);
}



#define XPMEM_REMOTE_TG_TGID    1 
#define XPMEM_REMOTE_TG_UID     1 
#define XPMEM_REMOTE_TG_GID     1 

/*
 * general internal driver structures
 */

struct xpmem_thread_group {
    pid_t                           tgid;                   /* tg's tgid */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
    uid_t                           uid;                    /* tg's uid */
    gid_t                           gid;                    /* tg's gid */
#else
    kuid_t                          uid;                    /* tg's uid */
    kgid_t                          gid;                    /* tg's gid */
#endif

    /* List of segments */
    struct list_head                seg_list;               /* tg's list of segs */
    rwlock_t                        seg_list_lock;

    /* Hashtable of access permits */
    struct xpmem_hashlist         * ap_hashtable;           /* locks + ap hash lists */

    /* PFN recall on tg teardown */
    struct mutex                    recall_PFNs_mutex;      /* lock for serializing recall of PFNs */
    wait_queue_head_t               block_recall_PFNs_wq;   /* wait to block recall of PFNs */
    wait_queue_head_t               allow_recall_PFNs_wq;   /* wait to allow recall of PFNs */
    atomic_t                        n_recall_PFNs;          /* #of recall of PFNs in progress */

    /* MMU notifier */
    struct mmu_notifier             mmu_not;                /* tg's mmu notifier struct */
    int                             mmu_initialized;        /* registered for mmu callbacks? */
    int                             mmu_unregister_called;  /* unregistered? */

    /* Other misc */
    struct task_struct            * group_leader;           /* thread group leader */
    struct mm_struct              * mm;                     /* tg's mm */
    u64                             addr_limit;             /* highest possible user addr */
    volatile int                    flags;                  /* tg attributes and state */

    atomic_t                        refcnt;                 /* references to tg */
    atomic_t                        n_pinned;               /* #of pages pinned by this tg */
    atomic_t                        uniq_segid;             /* uniq segid generation for this thread group */
    atomic_t                        uniq_apid;              /* uniq apid generation for this thread group */
    atomic_t                        uniq_attid;             /* uniq atid geneation for this thread group */

    /* Synchronization */
    spinlock_t                      lock;                   /* tg lock */

    /* List embeddings */
    struct list_head                tg_hashnode;            /* embedded in partition hash list */
};

struct xpmem_segment {
    /* List of access permits */
    struct list_head                ap_list;                /* local access permits of seg */

    /* This segment's exported region */
    xpmem_segid_t                   segid;                  /* unique segid */
    u64                             vaddr;                  /* starting address */
    size_t                          size;                   /* size of seg */
    int                             permit_type;            /* permission scheme */
    void                          * permit_value;           /* permission data */

    /* Other misc */
    volatile int                    flags;                  /* seg attributes and state */
    atomic_t                        refcnt;                 /* references to seg */
    struct xpmem_thread_group     * tg;                     /* creator's tg */

    /* Synchronization */
    wait_queue_head_t               destroyed_wq;           /* wait for seg to be destroyed */
    struct rw_semaphore             sema;                   /* seg sema */
    spinlock_t                      lock;                   /* seg lock */

    /* List embeddings */
    struct list_head                seg_node;               /* tg's list of segs */
};


struct xpmem_access_permit {
    /* List of attachments */
    struct list_head                att_list;               /* atts of this access permit's seg */

    /* This access permit's attached region */
    xpmem_apid_t                    apid;                   /* unique apid */
    xpmem_apid_t                    remote_apid;            /* unique remote apid */
    int                             mode;                   /* read/write mode */

    struct xpmem_segment          * seg;                    /* seg permitted to be accessed */
    struct xpmem_thread_group     * tg;                     /* access permit's tg */

    /* Other misc */
    volatile int                    flags;                  /* access permit attributes and state */
    atomic_t                        refcnt;                 /* references to access permit */

    /* Synchronization */
    spinlock_t                      lock;                   /* access permit lock */

    /* List embeddings */
    struct list_head                ap_node;                /* access permits linked to seg */
    struct list_head                ap_hashnode;            /* access permits linked to tg hash list */
};

struct xpmem_attachment {
    /* The source attached region */
    u64                             vaddr;                  /* starting address of seg attached */
    struct xpmem_access_permit    * ap;                     /* associated access permit */

    /* The local thread's attached region */
    atomic_t                        atid;                   /* uniq atid */
    struct mm_struct              * mm;                     /* mm struct attached to */
    struct vm_area_struct         * at_vma;                 /* vma where seg is attachment */
    u64                             at_vaddr;               /* address where seg is attached */
    size_t                          at_size;                /* size of seg attachment */

    /* Other misc */
    volatile int                    flags;                  /* att attributes and state */
    atomic_t                        refcnt;                 /* references to att */

    /* Synchronization */
    struct mutex                    mutex;                  /* att lock for serialization */

    /* List embeddings */
    struct list_head                att_node;               /* atts linked to access permit */
};



struct xpmem_partition {
    struct xpmem_hashlist         * tg_hashtable;           /* locks + tg hash lists */
    struct xpmem_thread_group     * tg_remote;              /* the special remote thread group */

    /* procfs debugging */
    atomic_t                        n_pinned;               /* # of pages pinned xpmem */
    atomic_t                        n_unpinned;             /* # of pages unpinned by xpmem */

    /* per-partition state */
    struct xpmem_partition_state    part_state;             /* extended per-partition state */
};

/*
 * Both the xpmem_segid_t and xpmem_apid_t are of type __s64 and designed
 * to be opaque to the user. Both consist of the same underlying fields.
 *
 * The 'uniq' field is designed to give each segid or apid a unique value.
 * Each type is only unique with respect to itself.
 *
 * An ID is never less than or equal to zero.
 */
struct xpmem_id {
    pid_t tgid;             /* thread group that owns ID */
    unsigned short uniq;  /* this value makes the ID unique */
};

#define XPMEM_MAX_UNIQ_ID       ((1 << (sizeof(short) * 8)) - 1)
#define XPMEM_MAX_UNIQ_APID     32
#define XPMEM_MAX_UNIQ_SEGID    (XPMEM_MAX_UNIQ_ID / XPMEM_MAX_UNIQ_APID)

static inline pid_t
xpmem_segid_to_tgid(xpmem_segid_t segid)
{
    DBUG_ON(segid <= 0);
    return ((struct xpmem_id *)&segid)->tgid;
}

static inline unsigned short
xpmem_segid_to_uniq(xpmem_segid_t segid)
{
    DBUG_ON(segid <= 0);
    return ((struct xpmem_id *)&segid)->uniq;
}

static inline pid_t
xpmem_apid_to_tgid(xpmem_apid_t apid)
{
    DBUG_ON(apid <= 0);
    return ((struct xpmem_id *)&apid)->tgid;
}

static inline unsigned short
xpmem_apid_to_uniq(xpmem_segid_t apid)
{
    DBUG_ON(apid <= 0);
    return ((struct xpmem_id *)&apid)->uniq;
}

/*
 * Attribute and state flags for various xpmem structures. Some values
 * are defined in xpmem.h, so we reserved space here via XPMEM_DONT_USE_X
 * to prevent overlap.
 */
#define XPMEM_FLAG_DESTROYING       0x00010 /* being destroyed */
#define XPMEM_FLAG_DESTROYED        0x00020 /* 'being destroyed' finished */
#define XPMEM_FLAG_CREATING_REMOTE  0x00040 /* being created */
#define XPMEM_AP_REMOTE             0x00080 /* remote access permit */
#define XPMEM_ATT_REMOTE            0x00100 /* remote attachment struct */

#define XPMEM_FLAG_VALIDPTEs        0x00200 /* valid PTEs exist */
#define XPMEM_FLAG_RECALLINGPFNS    0x00400 /* recalling PFNs */

#define XPMEM_DONT_USE_1        0x10000
#define XPMEM_DONT_USE_2        0x20000
#define XPMEM_DONT_USE_3        0x40000 /* reserved for xpmem.h */
#define XPMEM_DONT_USE_4        0x80000 /* reserved for xpmem.h */

static inline u64
xpmem_vaddr_to_PFN(struct mm_struct *mm, u64 vaddr)
{
    pte_t *pte;
    u64 pfn, offset;

    pte = xpmem_vaddr_to_pte_offset(mm, vaddr, &offset);
    if (pte == NULL)
        return 0;
    DBUG_ON(!pte_present(*pte));

    pfn = pte_pfn(*pte) + (offset >> PAGE_SHIFT);

    return pfn;
}

#define XPMEM_NODE_UNINITIALIZED    -1
#define XPMEM_CPUS_UNINITIALIZED    -1
#define XPMEM_NODE_OFFLINE      -2
#define XPMEM_CPUS_OFFLINE      -2

/* found in xpmem_make.c */
extern int xpmem_make_segment(u64, size_t, int, void *, struct xpmem_thread_group *, xpmem_segid_t );
extern int xpmem_make(u64, size_t, int, void *, xpmem_segid_t *);
extern void xpmem_remove_segs_of_tg(struct xpmem_thread_group *);
extern int xpmem_remove_seg(struct xpmem_thread_group *, struct xpmem_segment *);
extern int xpmem_remove(xpmem_segid_t);

/* found in xpmem_get.c */
extern int xpmem_check_permit_mode(int, struct xpmem_segment *);
extern xpmem_apid_t xpmem_make_apid(struct xpmem_thread_group *);
extern int xpmem_get_segment(int, int, void *, xpmem_apid_t, xpmem_apid_t, struct xpmem_segment *, struct xpmem_thread_group *, struct xpmem_thread_group *);
extern int xpmem_get(xpmem_segid_t, int, int, void *, xpmem_apid_t *);
extern void xpmem_release_aps_of_tg(struct xpmem_thread_group *);
extern void xpmem_release_ap(struct xpmem_thread_group *, struct xpmem_access_permit *);
extern int xpmem_release(xpmem_apid_t);

/* found in xpmem_attach.c */
extern struct vm_operations_struct xpmem_vm_ops;
extern int xpmem_attach(struct file *, xpmem_apid_t, off_t, size_t, u64, int,
            int, u64 *);
extern void xpmem_clear_PTEs_range(struct xpmem_segment *, u64, u64, int);
extern void xpmem_clear_PTEs(struct xpmem_segment *);
extern int xpmem_detach(u64);
extern void xpmem_detach_att(struct xpmem_access_permit *,
                 struct xpmem_attachment *);
extern int xpmem_mmap(struct file *, struct vm_area_struct *);

/* found in xpmem_pfn.c */
extern int xpmem_ensure_valid_PFNs(struct xpmem_segment *, u64, size_t, int);
extern int xpmem_block_recall_PFNs(struct xpmem_thread_group *, int);
extern void xpmem_unpin_pages(struct xpmem_segment *, struct mm_struct *, u64,
                size_t);
extern void xpmem_unblock_recall_PFNs(struct xpmem_thread_group *);
extern int xpmem_fork_begin(void);
extern int xpmem_fork_end(void);

/* found in xpmem_palacios.c */
extern int xpmem_palacios_detach_paddr(struct xpmem_partition_state *, u64);
#define XPMEM_TGID_STRING_LEN   11
extern spinlock_t xpmem_unpin_procfs_lock;
extern struct proc_dir_entry *xpmem_unpin_procfs_dir;
extern struct file_operations xpmem_unpin_procfs_fops;
//extern int xpmem_unpin_procfs_write(struct file *, const char *,
//                      unsigned long, void *);
//extern int xpmem_unpin_procfs_read(char *, char **, off_t, int, int *, void *);

/* found in xpmem_main.c */
extern struct xpmem_partition *xpmem_my_part;

/* found in xpmem_misc.c */
extern struct xpmem_thread_group *xpmem_tg_ref_by_tgid(pid_t);
extern struct xpmem_thread_group *xpmem_tg_ref_by_segid(xpmem_segid_t);
extern struct xpmem_thread_group *xpmem_tg_ref_by_apid(xpmem_apid_t);
extern void xpmem_tg_deref(struct xpmem_thread_group *);
extern struct xpmem_segment *xpmem_seg_ref_by_segid(struct xpmem_thread_group *,
                            xpmem_segid_t);
extern void xpmem_seg_deref(struct xpmem_segment *);
extern struct xpmem_access_permit *xpmem_ap_ref_by_apid(struct
                              xpmem_thread_group *,
                              xpmem_apid_t);
extern void xpmem_ap_deref(struct xpmem_access_permit *);
extern void xpmem_att_deref(struct xpmem_attachment *);
extern int xpmem_seg_down_read(struct xpmem_thread_group *,
                   struct xpmem_segment *, int, int);
extern int xpmem_validate_access(struct xpmem_thread_group *, struct xpmem_access_permit *, off_t, size_t,
                 int, u64 *);
extern void xpmem_block_nonfatal_signals(sigset_t *);
extern void xpmem_unblock_nonfatal_signals(sigset_t *);
//extern int xpmem_debug_printk_procfs_write(struct file *, const char *,
//                      unsigned long, void *);
//extern int xpmem_debug_printk_procfs_read(char *, char **, off_t, int, int *,
//                      void *);
extern struct file_operations xpmem_debug_printk_procfs_fops;
/* found in xpmem_mmu_notifier.c */
extern int xpmem_mmu_notifier_init(struct xpmem_thread_group *);
extern void xpmem_mmu_notifier_unlink(struct xpmem_thread_group *);





/*
 * Inlines that mark an internal driver structure as being destroyable or not.
 * The idea is to set the refcnt to 1 at structure creation time and then
 * drop that reference at the time the structure is to be destroyed.
 */
static inline void
xpmem_tg_not_destroyable(struct xpmem_thread_group *tg)
{
    atomic_set(&tg->refcnt, 1);
}

static inline void
xpmem_tg_destroyable(struct xpmem_thread_group *tg)
{
    xpmem_tg_deref(tg);
}

static inline void
xpmem_seg_not_destroyable(struct xpmem_segment *seg)
{
    atomic_set(&seg->refcnt, 1);
}

static inline void
xpmem_seg_destroyable(struct xpmem_segment *seg)
{
    xpmem_seg_deref(seg);
}

static inline void
xpmem_ap_not_destroyable(struct xpmem_access_permit *ap)
{
    atomic_set(&ap->refcnt, 1);
}

static inline void
xpmem_ap_destroyable(struct xpmem_access_permit *ap)
{
    xpmem_ap_deref(ap);
}

static inline void
xpmem_att_not_destroyable(struct xpmem_attachment *att)
{
    atomic_set(&att->refcnt, 1);
}

static inline void
xpmem_att_destroyable(struct xpmem_attachment *att)
{
    xpmem_att_deref(att);
}

/*
 * Inlines that increment the refcnt for the specified structure.
 */
static inline void
xpmem_tg_ref(struct xpmem_thread_group *tg)
{
    /* Do not allow refs of the remote thread group, unless this is in the
     * initialization */
    if (tg->tgid == XPMEM_REMOTE_TG_TGID) {
        if (!(tg->flags & XPMEM_FLAG_CREATING_REMOTE)) {
            return;
        }
    }

    DBUG_ON(atomic_read(&tg->refcnt) <= 0);
    atomic_inc(&tg->refcnt);
}

static inline void
xpmem_seg_ref(struct xpmem_segment *seg)
{
    DBUG_ON(atomic_read(&seg->refcnt) <= 0);
    atomic_inc(&seg->refcnt);
}

static inline void
xpmem_ap_ref(struct xpmem_access_permit *ap)
{
    DBUG_ON(atomic_read(&ap->refcnt) <= 0);
    atomic_inc(&ap->refcnt);
}

static inline void
xpmem_att_ref(struct xpmem_attachment *att)
{
    DBUG_ON(atomic_read(&att->refcnt) <= 0);
    atomic_inc(&att->refcnt);
}

/*
 * A simple test to determine whether the specified vma corresponds to a
 * XPMEM attachment.
 */
static inline int
xpmem_is_vm_ops_set(struct vm_area_struct *vma)
{
    return (vma->vm_ops == &xpmem_vm_ops);
}

/* xpmem_seg_down_read() can be found in xpmem_misc.c */

static inline void
xpmem_seg_up_read(struct xpmem_thread_group *seg_tg,
          struct xpmem_segment *seg, int unblock_recall_PFNs)
{
    up_read(&seg->sema);
    if (unblock_recall_PFNs)
        xpmem_unblock_recall_PFNs(seg_tg);
}

static inline void
xpmem_seg_down_write(struct xpmem_segment *seg)
{
    down_write(&seg->sema);
}

static inline void
xpmem_seg_up_write(struct xpmem_segment *seg)
{
    up_write(&seg->sema);
    wake_up(&seg->destroyed_wq);
}

static inline void
xpmem_wait_for_seg_destroyed(struct xpmem_segment *seg)
{
    wait_event(seg->destroyed_wq, ((seg->flags & XPMEM_FLAG_DESTROYED) ||
                       !(seg->flags & (XPMEM_FLAG_DESTROYING |
                               XPMEM_FLAG_RECALLINGPFNS))));
}

/*
 * Hash Tables
 *
 * XPMEM utilizes hash tables to enable faster lookups of list entries.
 * These hash tables are implemented as arrays. A simple modulus of the hash
 * key yields the appropriate array index. A hash table's array element (i.e.,
 * hash table bucket) consists of a hash list and the lock that protects it.
 *
 * XPMEM has the following two hash tables:
 *
 * table        bucket                  key
 * part->tg_hashtable   list of struct xpmem_thread_group   tgid
 * tg->ap_hashtable list of struct xpmem_access_permit  apid.uniq
 */

struct xpmem_hashlist {
    rwlock_t lock;      /* lock for hash list */
    struct list_head list;  /* hash list */
} ____cacheline_aligned;

#define XPMEM_TG_HASHTABLE_SIZE 8
#define XPMEM_AP_HASHTABLE_SIZE 8

static inline int
xpmem_tg_hashtable_index(pid_t tgid)
{
    return ((unsigned int)tgid % XPMEM_TG_HASHTABLE_SIZE);
}

static inline int
xpmem_ap_hashtable_index(xpmem_apid_t apid)
{
    DBUG_ON(apid <= 0);
    return (((struct xpmem_id *)&apid)->uniq % XPMEM_AP_HASHTABLE_SIZE);
}

#endif /* _XPMEM_PRIVATE_H */
