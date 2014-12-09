/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 */

/*
 * Cross Partition Memory (XPMEM) support.
 *
 * This module (along with a corresponding library) provides support for
 * cross-partition shared memory between threads.
 *
 * Caveats
 *
 *   * XPMEM cannot allocate VM_IO pages on behalf of another thread group
 *     since get_user_pages() doesn't handle VM_IO pages. This is normally
 *     valid if a thread group attaches a portion of an address space and is
 *     the first to touch that portion.
 */

#include <asm/uaccess.h>

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>
#include <xpmem_partition.h>
#include <xpmem_syms.h>


struct xpmem_partition * xpmem_my_part  = NULL;  /* pointer to this partition */
struct proc_dir_entry  * xpmem_proc_dir = NULL;

int ns = 0;
module_param(ns, int, 0);


/*
 * User open of the XPMEM driver. Called whenever /dev/xpmem is opened.
 * Create a struct xpmem_thread_group structure for the specified thread group.
 * And add the structure to the tg hash table.
 */
static int
xpmem_open(struct inode *inode, struct file *file)
{
    struct xpmem_thread_group *tg;
    int index;

    /* if this has already been done, just return silently */
    tg = xpmem_tg_ref_by_tgid(current->tgid);
    if (!IS_ERR(tg)) {
        xpmem_tg_deref(tg);
        return 0;
    }

    /* create tg */
    tg = kzalloc(sizeof(struct xpmem_thread_group), GFP_KERNEL);
    if (tg == NULL) {
        return -ENOMEM;
    }

    tg->lock = __SPIN_LOCK_UNLOCKED(tg->lock);
    tg->tgid = current->tgid;
    tg->uid = current->cred->uid;
    tg->gid = current->cred->gid;
    //atomic_set(&tg->uniq_segid, 0);
    atomic_set(&tg->uniq_apid, 0);
    atomic_set(&tg->n_pinned, 0);
    tg->addr_limit = TASK_SIZE;
    rwlock_init(&(tg->seg_list_lock));
    INIT_LIST_HEAD(&tg->seg_list);
    INIT_LIST_HEAD(&tg->tg_hashnode);
    atomic_set(&tg->n_recall_PFNs, 0);
    mutex_init(&tg->recall_PFNs_mutex);
    init_waitqueue_head(&tg->block_recall_PFNs_wq);
    init_waitqueue_head(&tg->allow_recall_PFNs_wq);
    tg->mmu_initialized = 0;
    tg->mmu_unregister_called = 0;
    tg->mm = current->mm;

    /* Register MMU notifier callbacks */
    if (xpmem_mmu_notifier_init(tg) != 0) {
        kfree(tg);
        return -EFAULT;
    }
    
    /* create and initialize struct xpmem_access_permit hashtable */
    tg->ap_hashtable = kzalloc(sizeof(struct xpmem_hashlist) *
                     XPMEM_AP_HASHTABLE_SIZE, GFP_KERNEL);
    if (tg->ap_hashtable == NULL) {
        xpmem_mmu_notifier_unlink(tg);
        kfree(tg);
        return -ENOMEM;
    }
    for (index = 0; index < XPMEM_AP_HASHTABLE_SIZE; index++) {
        rwlock_init(&(tg->ap_hashtable[index].lock));
        INIT_LIST_HEAD(&tg->ap_hashtable[index].list);
    }

    xpmem_tg_not_destroyable(tg);

    /* add tg to its hash list */
    index = xpmem_tg_hashtable_index(tg->tgid);
    write_lock(&xpmem_my_part->tg_hashtable[index].lock);
    list_add_tail(&tg->tg_hashnode,
              &xpmem_my_part->tg_hashtable[index].list);
    write_unlock(&xpmem_my_part->tg_hashtable[index].lock);

    /*
     * Increment 'usage' and 'mm->mm_users' for the current task's thread
     * group leader. This ensures that both its task_struct and mm_struct
     * will still be around when our thread group exits. (The Linux kernel
     * normally tears down the mm_struct prior to calling a module's
     * 'flush' function.) Since all XPMEM thread groups must go through
     * this path, this extra reference to mm_users also allows us to
     * directly inc/dec mm_users in xpmem_ensure_valid_PFNs() and avoid
     * mmput() which has a scaling issue with the mmlist_lock.
     */
    get_task_struct(current->group_leader);
    tg->group_leader = current->group_leader;
    BUG_ON(current->mm != current->group_leader->mm);
    atomic_inc(&current->group_leader->mm->mm_users);

    return 0;
}

static int
xpmem_flush_tg(struct xpmem_thread_group * tg)
{
    int index;

    spin_lock(&tg->lock);
    if (tg->flags & XPMEM_FLAG_DESTROYING) {
        spin_unlock(&tg->lock);
        xpmem_tg_deref(tg);
        return -EALREADY;
    }
    tg->flags |= XPMEM_FLAG_DESTROYING;
    spin_unlock(&tg->lock);

    xpmem_release_aps_of_tg(tg);
    xpmem_remove_segs_of_tg(tg);

    /*
     * At this point, XPMEM no longer needs to reference the thread group
     * leader's task_struct or mm_struct. Decrement its 'usage' and
     * 'mm->mm_users' to account for the extra increments previously done
     * in xpmem_open().
     */
    if (tg->mm) {
        xpmem_mmu_notifier_unlink(tg);
        mmput(tg->mm);
        put_task_struct(tg->group_leader);
    }

    /* Remove tg structure from its hash list */
    if (tg->tgid != XPMEM_REMOTE_TG_TGID) {
        index = xpmem_tg_hashtable_index(tg->tgid);
        write_lock(&xpmem_my_part->tg_hashtable[index].lock);
        list_del_init(&tg->tg_hashnode);
        write_unlock(&xpmem_my_part->tg_hashtable[index].lock);
    }

    xpmem_tg_destroyable(tg);
    xpmem_tg_deref(tg);

    return 0;
}

/*
 * The following function gets called whenever a thread group that has opened
 * /dev/xpmem closes it.
 */
static int
xpmem_flush(struct file *file, fl_owner_t owner)
{
    struct xpmem_thread_group *tg;

    tg = xpmem_tg_ref_by_tgid(current->tgid);
    if (IS_ERR(tg)) {
        /*
         * xpmem_flush() can get called twice for thread groups
         * which inherited /dev/xpmem: once for the inherited fd,
         * once for the first explicit use of /dev/xpmem. If we
         * don't find the tg via xpmem_tg_ref_by_tgid() we assume we
         * are in this type of scenario and return silently.
         */
        return 0;
    }

    return xpmem_flush_tg(tg);
}

/*
 * User ioctl to the XPMEM driver. Only 64-bit user applications are
 * supported.
 */
static long
xpmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret;

    switch (cmd) {
    case XPMEM_CMD_VERSION: {
        return XPMEM_CURRENT_VERSION;
    }
    case XPMEM_CMD_MAKE: {
        struct xpmem_cmd_make make_info;
        xpmem_segid_t segid;

        if (copy_from_user(&make_info, (void __user *)arg,
                   sizeof(struct xpmem_cmd_make)))
            return -EFAULT;

        ret = xpmem_make(make_info.vaddr, make_info.size,
                 make_info.permit_type,
                 (void *)make_info.permit_value, 
                 &segid);
        if (ret != 0)
            return ret;

        if (put_user(segid,
                 &((struct xpmem_cmd_make __user *)arg)->segid)) {
            (void)xpmem_remove(segid);
            return -EFAULT;
        }
        return 0;
    }
    case XPMEM_CMD_REMOVE: {
        struct xpmem_cmd_remove remove_info;

        if (copy_from_user(&remove_info, (void __user *)arg,
                   sizeof(struct xpmem_cmd_remove)))
            return -EFAULT;

        return xpmem_remove(remove_info.segid);
    }
    case XPMEM_CMD_GET: {
        struct xpmem_cmd_get get_info;
        xpmem_apid_t apid;

        if (copy_from_user(&get_info, (void __user *)arg,
                   sizeof(struct xpmem_cmd_get)))
            return -EFAULT;

        ret = xpmem_get(get_info.segid, get_info.flags,
                get_info.permit_type,
                (void *)get_info.permit_value, &apid);
        if (ret != 0)
            return ret;

        if (put_user(apid,
                 &((struct xpmem_cmd_get __user *)arg)->apid)) {
            (void)xpmem_release(apid);
            return -EFAULT;
        }
        return 0;
    }
    case XPMEM_CMD_RELEASE: {
        struct xpmem_cmd_release release_info;

        if (copy_from_user(&release_info, (void __user *)arg,
                   sizeof(struct xpmem_cmd_release)))
            return -EFAULT;

        return xpmem_release(release_info.apid);
    }
    case XPMEM_CMD_ATTACH: {
        struct xpmem_cmd_attach attach_info;
        u64 at_vaddr;

        if (copy_from_user(&attach_info, (void __user *)arg,
                   sizeof(struct xpmem_cmd_attach)))
            return -EFAULT;

        ret = xpmem_attach(file, attach_info.apid, attach_info.offset,
                   attach_info.size, attach_info.vaddr,
                   attach_info.fd, attach_info.flags,
                   &at_vaddr);
        if (ret != 0)
            return ret;

        if (put_user(at_vaddr,
                 &((struct xpmem_cmd_attach __user *)arg)->vaddr)) {
            (void)xpmem_detach(at_vaddr);
            return -EFAULT;
        }
        return 0;
    }
    case XPMEM_CMD_DETACH: {
        struct xpmem_cmd_detach detach_info;

        if (copy_from_user(&detach_info, (void __user *)arg,
                   sizeof(struct xpmem_cmd_detach)))
            return -EFAULT;

        return xpmem_detach(detach_info.vaddr);
    }
    case XPMEM_CMD_FORK_BEGIN: {
        return xpmem_fork_begin();
    }
    case XPMEM_CMD_FORK_END: {
        return xpmem_fork_end();
    }
    default:
        break;
    }
    return -ENOIOCTLCMD;
}

static struct file_operations xpmem_fops = {
    //.owner = THIS_MODULE,
    .open = xpmem_open,
    .flush = xpmem_flush,
    .unlocked_ioctl = xpmem_ioctl,
    .mmap = xpmem_mmap,
};

static struct miscdevice xpmem_dev_handle = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = XPMEM_MODULE_NAME,
    .fops = &xpmem_fops
};



static int
xpmem_create_remote_thread_group(void)
{
    struct xpmem_thread_group *tg;
    int index;

    /* create tg */
    tg = kzalloc(sizeof(struct xpmem_thread_group), GFP_KERNEL);
    if (tg == NULL) {
        return -ENOMEM;
    }

    tg->lock = __SPIN_LOCK_UNLOCKED(tg->lock);
    tg->tgid = XPMEM_REMOTE_TG_TGID;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
    tg->uid = XPMEM_REMOTE_TG_UID;
    tg->gid = XPMEM_REMOTE_TG_GID;
#else
    tg->uid.val = XPMEM_REMOTE_TG_UID;
    tg->gid.val = XPMEM_REMOTE_TG_GID;
#endif
    //atomic_set(&tg->uniq_segid, 0);
    atomic_set(&tg->uniq_apid, 0);
    atomic_set(&tg->n_pinned, 0);
    tg->addr_limit = TASK_SIZE;
    rwlock_init(&(tg->seg_list_lock));
    INIT_LIST_HEAD(&tg->seg_list);
    INIT_LIST_HEAD(&tg->tg_hashnode);
    tg->mm = NULL;

    /* create and initialize struct xpmem_access_permit hashtable */
    tg->ap_hashtable = kzalloc(sizeof(struct xpmem_hashlist) *
                     XPMEM_AP_HASHTABLE_SIZE, GFP_KERNEL);
    if (tg->ap_hashtable == NULL) {
        xpmem_mmu_notifier_unlink(tg);
        kfree(tg);
        return -ENOMEM;
    }
    for (index = 0; index < XPMEM_AP_HASHTABLE_SIZE; index++) {
        rwlock_init(&(tg->ap_hashtable[index].lock));
        INIT_LIST_HEAD(&tg->ap_hashtable[index].list);
    }

    xpmem_tg_not_destroyable(tg);
    xpmem_tg_ref(tg);

    xpmem_my_part->tg_remote = tg;

    return 0;
}

static int
xpmem_remove_remote_thread_group(void)
{
    if (xpmem_my_part->tg_remote != NULL) {
        xpmem_flush_tg(xpmem_my_part->tg_remote);
        xpmem_my_part->tg_remote = NULL;
    }

    return 0;
}



/*
 * Initialize the XPMEM driver.
 */
int __init
xpmem_init(void)
{
    int i, ret;
    //struct proc_dir_entry *global_pages_entry;
    //struct proc_dir_entry *debug_printk_entry;

    /* create and initialize struct xpmem_partition array */
    xpmem_my_part = kzalloc(sizeof(struct xpmem_partition), GFP_KERNEL);
    if (xpmem_my_part == NULL)
        return -ENOMEM;

    xpmem_my_part->tg_hashtable = kzalloc(sizeof(struct xpmem_hashlist) *
                    XPMEM_TG_HASHTABLE_SIZE, GFP_KERNEL);
    if (xpmem_my_part->tg_hashtable == NULL) {
        kfree(xpmem_my_part);
        return -ENOMEM;
    }

    for (i = 0; i < XPMEM_TG_HASHTABLE_SIZE; i++) {
        rwlock_init(&(xpmem_my_part->tg_hashtable[i].lock));
        INIT_LIST_HEAD(&xpmem_my_part->tg_hashtable[i].list);
    }

    rwlock_init(&(xpmem_my_part->wk_segid_to_tgid_lock));

    /* create the /proc interface directory (/proc/xpmem) */
    xpmem_proc_dir = proc_mkdir(XPMEM_MODULE_NAME, NULL);

    /* create the XPMEM character device (/dev/xpmem) */
    ret = misc_register(&xpmem_dev_handle);
    if (ret != 0)
        goto out_1;

    if (xpmem_partition_init(&(xpmem_my_part->part_state), ns) != 0) {
        goto out_2;
    }

    /* Symbol lookups */
    xpmem_linux_symbol_init();

    /* Create remote thread group */
    xpmem_create_remote_thread_group();

    printk("SGI XPMEM kernel module v%s loaded\n",
           XPMEM_CURRENT_VERSION_STRING);
    return 0;

out_2:
    misc_deregister(&xpmem_dev_handle);

out_1:
    kfree(xpmem_my_part->tg_hashtable);
    kfree(xpmem_my_part);
    return ret;
}



/*
 * Remove the XPMEM driver from the system.
 */
void __exit
xpmem_exit(void)
{
    /* Remove the remote_tg, if it was created */
    xpmem_remove_remote_thread_group();

    /* Free partition resources */
    xpmem_partition_deinit(&(xpmem_my_part->part_state));

    kfree(xpmem_my_part->tg_hashtable);
    kfree(xpmem_my_part);

    misc_deregister(&xpmem_dev_handle);
    //remove_proc_entry("global_pages", xpmem_unpin_procfs_dir);
    //remove_proc_entry("debug_printk", xpmem_unpin_procfs_dir);
    
    remove_proc_entry(XPMEM_MODULE_NAME, NULL);

    printk("SGI XPMEM kernel module v%s unloaded\n",
           XPMEM_CURRENT_VERSION_STRING);
}

#ifdef EXPORT_NO_SYMBOLS
EXPORT_NO_SYMBOLS;
#endif
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Silicon Graphics, Inc.");
MODULE_INFO(supported, "external");
MODULE_DESCRIPTION("XPMEM support");
module_init(xpmem_init);
module_exit(xpmem_exit);
