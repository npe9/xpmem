/*
 * XPMEM extensions for multiple domain support.
 *
 * This file implements XPMEM commands from remote processes 
 * destined for this domain, as well as wrappers for sending commands to remote
 * domains
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
#include <linux/mman.h>
#include <linux/mm.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>
#include <xpmem_hashtable.h>
#include <xpmem_iface.h>

struct xpmem_domain_state {
    int                            initialized;  /* domain state initialization */
    xpmem_link_t                   link;         /* XPMEM connection link */
    struct xpmem_partition_state * part;         /* pointer to XPMEM partition */

    int                            cmd_complete; /* command completion signal */
    wait_queue_head_t              dom_waitq;    /* wait for results from fwd/name service */
    struct mutex                   mutex;        /* serialize access to fwd/name service */
    struct xpmem_cmd_ex          * cmd;          /* shared command struct */
};


struct xpmem_hashtable * attach_htable = NULL;

struct xpmem_remote_attach_struct {
    unsigned long vaddr;
    unsigned long paddr;
    unsigned long size;
    struct list_head node;
};


extern int
xpmem_palacios_detach_paddr(struct xpmem_partition_state * part_state,
                            u64                            vaddr);

static u32 
domain_hash_fn(uintptr_t key)
{
    return hash_long(key);
}

static int
domain_eq_fn(uintptr_t key1, 
            uintptr_t key2)            
{
    return (key1 == key2);
}



static int
xpmem_validate_remote_access(struct xpmem_access_permit * ap, 
                             off_t                        offset,
                             size_t                       size, 
                             int                          mode, 
                             u64                        * vaddr)
{
    if (mode == XPMEM_RDWR && ap->mode == XPMEM_RDONLY) {
        return -EACCES;
    }

    if (offset < 0 || size == 0 || offset + size > ap->seg->size) {
        return -EINVAL;
    }

    *vaddr = ap->seg->vaddr + offset;
    return 0;
}


static int 
xpmem_get_domain(struct xpmem_cmd_get_ex * get_ex)
{
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

    apid = xpmem_make_apid(ap_tg);
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

static int 
xpmem_release_domain(struct xpmem_cmd_release_ex * release_ex)
{
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

static int 
xpmem_attach_domain(struct xpmem_cmd_attach_ex * attach_ex)
{
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

static int 
xpmem_detach_domain(struct xpmem_cmd_detach_ex * detach_ex)
{
    return 0;
}


static unsigned long 
xpmem_map_pfn_range(u64 * pfns, 
                    u64 num_pfns)
{
    struct vm_area_struct * vma = NULL;
    unsigned long size = 0;
    unsigned long addr = 0;
    unsigned long attach_addr = 0;
    u64 i = 0;
    int status = 0;
    struct xpmem_remote_attach_struct * remote;
    struct list_head * head;

    size = num_pfns * PAGE_SIZE;
    attach_addr = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
            MAP_SHARED, 0); 

    if (IS_ERR_VALUE(attach_addr)) {
        printk(KERN_ERR "XPMEM: vm_mmap failed\n");
        return attach_addr;
    }   

    vma = find_vma(current->mm, attach_addr);
    if (!vma) {
        printk(KERN_ERR "XPMEM: find_vma failed - this should be impossible\n");
        return -ENOMEM;
    }   

    for (i = 0; i < num_pfns; i++) {
        addr = attach_addr + (i * PAGE_SIZE);

        status = remap_pfn_range(vma, addr, pfns[i], PAGE_SIZE, vma->vm_page_prot);
        if (status) {
            printk(KERN_ERR "XPMEM: remap_pfn_range failed\n");
            vm_munmap(attach_addr, size);
            return -ENOMEM;
        }
    }   

    if (!attach_htable) {
        attach_htable = create_htable(0, domain_hash_fn, domain_eq_fn);
        if (!attach_htable) {
            vm_munmap(attach_addr, size);
            return -ENOMEM;
        }
    }

    remote = kmalloc(sizeof(struct xpmem_remote_attach_struct), GFP_KERNEL);
    if (!remote) {
        vm_munmap(attach_addr, size);
        return -1;
    }

    remote->vaddr = attach_addr;
    remote->paddr = (pfns[0] << PAGE_SHIFT);
    remote->size = size;

    head = (struct list_head *)htable_search(attach_htable, current->tgid);
    if (!head) {
        head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
        if (!head) {
            vm_munmap(attach_addr, size);
            return -ENOMEM;
        }

        INIT_LIST_HEAD(head);
        if (!htable_insert(attach_htable, (uintptr_t)current->tgid, (uintptr_t)head)) {
            vm_munmap(attach_addr, size);
            return -1;
        }
    }
    list_add_tail(&(remote->node), head);
    
    return attach_addr;
}


static void 
xpmem_detach_vaddr(struct xpmem_partition_state * part_state,
                   u64                            vaddr)
{
    struct list_head * head = NULL;

    if (!attach_htable) {
        return;
    }

    head = (struct list_head *)htable_search(attach_htable, current->tgid);
    if (!head) {
        printk(KERN_ERR "XPMEM_EXTENDED: LEAKING VIRTUAL ADDRESS SPACE\n");
    } else {
        struct xpmem_remote_attach_struct * remote = NULL, * next = NULL;
        list_for_each_entry_safe(remote, next, head, node) {
            if (remote->vaddr == vaddr) {
                vm_munmap(remote->vaddr, remote->size);

                /* If we are running in a Palacios VM, we need to tell the hypervisor */
                xpmem_palacios_detach_paddr(part_state, remote->paddr);

                list_del(&(remote->node));
                kfree(remote);
                break;
            }
        }

        if (list_empty(head)) {
            htable_remove(attach_htable, (uintptr_t)current->tgid, 0);
            kfree(head);
        }
    }
}


/* Callback for command being issued by the XPMEM name/forwarding service */
static int
xpmem_cmd_fn(struct xpmem_cmd_ex * cmd,
             void                * priv_data)
{
    struct xpmem_domain_state * state = (struct xpmem_domain_state *)priv_data;
    int                         ret   = 0;

    if (!state->initialized) {
        return -1;
    }

    /* Process commands destined for this domain */
    switch (cmd->type) {
        case XPMEM_GET:

            ret = xpmem_get_domain(&(cmd->get));

            if (ret != 0) {
                cmd->get.apid = -1;
            }

            cmd->type = XPMEM_GET_COMPLETE;

            xpmem_cmd_deliver(state->part, state->link, cmd);

            break;

        case XPMEM_RELEASE:
            ret = xpmem_release_domain(&(cmd->release));

            cmd->type = XPMEM_RELEASE_COMPLETE;

            xpmem_cmd_deliver(state->part, state->link, cmd);

            break;

        case XPMEM_ATTACH:
            ret = xpmem_attach_domain(&(cmd->attach));

            if (ret != 0) {
                cmd->attach.pfns = NULL;
                cmd->attach.num_pfns = 0;
            }

            cmd->type = XPMEM_ATTACH_COMPLETE;

            xpmem_cmd_deliver(state->part, state->link, cmd);

            break;

        case XPMEM_DETACH:
            ret = xpmem_detach_domain(&(cmd->detach));

            cmd->type = XPMEM_DETACH_COMPLETE;

            xpmem_cmd_deliver(state->part, state->link, cmd);

            break;

        case XPMEM_MAKE_COMPLETE:
        case XPMEM_REMOVE_COMPLETE:
        case XPMEM_GET_COMPLETE:
        case XPMEM_RELEASE_COMPLETE:
        case XPMEM_ATTACH_COMPLETE: 
        case XPMEM_DETACH_COMPLETE: {
            state->cmd = kmalloc(sizeof(struct xpmem_cmd_ex), GFP_KERNEL);
            if (!state->cmd) {
                printk(KERN_ERR "XPMEM: out of memory\n");
                break;
            }

            *state->cmd = *cmd;
            
            if (cmd->type == XPMEM_ATTACH_COMPLETE) {
                state->cmd->attach.pfns = kmalloc(sizeof(u64) * cmd->attach.num_pfns, GFP_KERNEL);
                if (!state->cmd->attach.pfns) {
                    printk(KERN_ERR "XPMEM: out of memory\n");
                    kfree(state->cmd);
                    break;
                }

                memcpy(state->cmd->attach.pfns, cmd->attach.pfns, cmd->attach.num_pfns * sizeof(u64));
            }

            state->cmd_complete = 1;

            mb();
            wake_up_interruptible(&(state->dom_waitq));

            break;
        }

        default:
            printk(KERN_ERR "XPMEM: domain given unknown XPMEM command %d\n", cmd->type);
            return -1;

    }

    return 0;
}


int
xpmem_domain_init(struct xpmem_partition_state * part)
{
    struct xpmem_domain_state * state = kzalloc(sizeof(struct xpmem_domain_state), GFP_KERNEL);
    if (!state) {
        return -1;
    }
    
    mutex_init(&(state->mutex));
    init_waitqueue_head(&(state->dom_waitq));

    state->link = xpmem_add_connection(
            part,
            XPMEM_CONN_LOCAL,
            xpmem_cmd_fn,
            (void *)state);

    if (state->link <= 0) {
        printk(KERN_ERR "XPMEM: failed to register local domain with"
            " name/forwarding service\n");
        kfree(state);
        return -1;
    }

    state->cmd_complete = 0;
    state->initialized  = 1;
    state->part         = part;
    part->domain_priv   = state;

    printk("XPMEM local domain initialized\n");

    return 0;
}

int
xpmem_domain_deinit(struct xpmem_partition_state * part)
{
    struct xpmem_domain_state * state = (struct xpmem_domain_state *)part->domain_priv;

    if (!state) {
        return 0;
    }
    
    /* Remove domain connection */
    xpmem_remove_connection(state->part, state->link);

    kfree(state);
    part->domain_priv = NULL;

    printk("XPMEM local domain deinitialized\n");

    return 0;
}



/* Package XPMEM command into xpmem_cmd_ex structure and pass to forwarding/name
 * service layer. Wait for a response before proceeding
 */
int
xpmem_make_remote(struct xpmem_partition_state * part,
                  xpmem_segid_t                * segid)
{
    struct xpmem_domain_state * state = (struct xpmem_domain_state *)(struct xpmem_domain_state *)part->domain_priv;
    struct xpmem_cmd_ex         cmd;

    if (!state->initialized) {
        return -1;
    }

    memset(&cmd, 0, sizeof(struct xpmem_cmd_ex));

    cmd.type       = XPMEM_MAKE;
    cmd.make.segid = *segid;

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        state->cmd_complete = 0;

        /* Deliver command */
        xpmem_cmd_deliver(state->part, state->link, &cmd);

        /* Wait for completion */
        mb();
        wait_event_interruptible(state->dom_waitq, state->cmd_complete == 1);
        
        /* Check command completion  */
        if (state->cmd_complete == 0) {
            return -1;
        }

        /* Grab allocated segid */
        *segid = state->cmd->make.segid;
    }

    mutex_unlock(&(state->mutex));

    kfree(state->cmd);

    return 0;
}

int
xpmem_remove_remote(struct xpmem_partition_state * part,
                    xpmem_segid_t                  segid)
{
    struct xpmem_domain_state * state = (struct xpmem_domain_state *)part->domain_priv;
    struct xpmem_cmd_ex         cmd;

    if (!state->initialized) {
        return -1;
    }

    memset(&cmd, 0, sizeof(struct xpmem_cmd_ex));

    cmd.type         = XPMEM_REMOVE;
    cmd.remove.segid = segid;

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        state->cmd_complete = 0;

        /* Deliver command */
        xpmem_cmd_deliver(state->part, state->link, &cmd);

        /* Wait for completion */
        mb();
        wait_event_interruptible(state->dom_waitq, state->cmd_complete == 1);

        /* Check command completion  */
        if (state->cmd_complete == 0) {
            return -1;
        }
    }

    mutex_unlock(&(state->mutex));

    kfree(state->cmd);

    return 0;
}

int
xpmem_get_remote(struct xpmem_partition_state * part,
                 xpmem_segid_t                  segid,
                 int                            flags,
                 int                            permit_type,
                 u64                            permit_value,
                 xpmem_apid_t                 * apid)
{
    struct xpmem_domain_state * state = (struct xpmem_domain_state *)part->domain_priv;
    struct xpmem_cmd_ex         cmd;

    if (!state->initialized) {
        return -1;
    }

    memset(&cmd, 0, sizeof(struct xpmem_cmd_ex));

    cmd.type             = XPMEM_GET;
    cmd.get.segid        = segid;
    cmd.get.flags        = flags;
    cmd.get.permit_type  = permit_type;
    cmd.get.permit_value = permit_value;

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        state->cmd_complete = 0;

        /* Deliver command */
        xpmem_cmd_deliver(state->part, state->link, &cmd);

        /* Wait for completion */
        mb();
        wait_event_interruptible(state->dom_waitq, state->cmd_complete == 1);

        /* Check command completion  */
        if (state->cmd_complete == 0) {
            return -1;
        }

        /* Grab allocated apid */
        *apid = state->cmd->get.apid;
    }

    mutex_unlock(&(state->mutex));

    kfree(state->cmd);

    return 0;
}

int
xpmem_release_remote(struct xpmem_partition_state * part,
                     xpmem_apid_t                   apid)
{
    struct xpmem_domain_state * state = (struct xpmem_domain_state *)part->domain_priv;
    struct xpmem_cmd_ex         cmd;

    if (!state->initialized) {
        return -1;
    }

    memset(&cmd, 0, sizeof(struct xpmem_cmd_ex));

    cmd.type         = XPMEM_RELEASE;
    cmd.release.apid = apid;

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        state->cmd_complete = 0;

        /* Deliver command */
        xpmem_cmd_deliver(state->part, state->link, &cmd);

        /* Wait for completion */
        mb();
        wait_event_interruptible(state->dom_waitq, state->cmd_complete == 1);

        /* Check command completion  */
        if (state->cmd_complete == 0) {
            return -1;
        }
    }

    mutex_unlock(&(state->mutex));

    kfree(state->cmd);

    return 0;
}

int
xpmem_attach_remote(struct xpmem_partition_state * part,
                    xpmem_apid_t                   apid,
                    off_t                          offset,
                    size_t                         size,
                    u64                          * vaddr)
{
    struct xpmem_domain_state * state   = (struct xpmem_domain_state *)part->domain_priv;
    struct xpmem_cmd_ex         cmd;

    if (!state->initialized) {
        return -1;
    }

    memset(&cmd, 0, sizeof(struct xpmem_cmd_ex));

    cmd.type        = XPMEM_ATTACH;
    cmd.attach.apid = apid;
    cmd.attach.off  = offset;
    cmd.attach.size = size;

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        state->cmd_complete = 0;

        /* Deliver command */
        xpmem_cmd_deliver(state->part, state->link, &cmd);

        /* Wait for completion */
        mb();
        wait_event_interruptible(state->dom_waitq, state->cmd_complete == 1);

        /* Check command completion  */
        if (state->cmd_complete == 0) {
            return -1;
        }

        /* Map pfn list */
        if (state->cmd->attach.num_pfns > 0) {
            *vaddr = (u64)xpmem_map_pfn_range(
                        state->cmd->attach.pfns,
                        state->cmd->attach.num_pfns
                    );
        } else {
            *vaddr = 0;
        }
    }

    mutex_unlock(&(state->mutex));

    kfree(state->cmd);

    return 0;
}



int
xpmem_detach_remote(struct xpmem_partition_state * part,
                    u64                            vaddr)
{
    struct xpmem_domain_state * state = (struct xpmem_domain_state *)part->domain_priv;
    struct xpmem_cmd_ex         cmd;

    if (!state->initialized) {
        return -1;
    }

    memset(&cmd, 0, sizeof(struct xpmem_cmd_ex));

    cmd.type         = XPMEM_DETACH;
    cmd.detach.vaddr = vaddr;

    while (mutex_lock_interruptible(&(state->mutex)));

    {
        state->cmd_complete = 0;

        /* Deliver command */
        xpmem_cmd_deliver(state->part, state->link, &cmd);

        /* Wait for completion */
        mb();
        wait_event_interruptible(state->dom_waitq, state->cmd_complete == 1);

        /* Check command completion  */
        if (state->cmd_complete == 0) {
            return -1;
        }
    }

    mutex_unlock(&(state->mutex));

    kfree(state->cmd);

    /* Free virtual address space */
    xpmem_detach_vaddr(part, vaddr);

    return 0;
}
