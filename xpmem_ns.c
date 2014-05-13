/*
 * XPMEM extensions for multiple domain support.
 *
 * This file implements XPMEM requests for local processes executing with
 * the NS. 
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
#include <linux/poll.h>
#include <linux/anon_inodes.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>


/* These will pack commands into request structures and write them to the NS
 * command list
 */
static int xpmem_make_ns(struct xpmem_partition * part, xpmem_segid_t * segid_p) {
    struct ns_xpmem_state * state = part->ns_state;
    struct xpmem_cmd_ex * cmd = &(state->cmd);

    if (!state->initialized) {
        return -1;
    }

    printk("MAKE_NS\n");

    while (mutex_lock_interruptible(&(state->mutex)));

    spin_lock(&(state->lock));
    cmd->type = XPMEM_MAKE;
    cmd->make.segid = *segid_p;
    state->requested = 1;
    state->processed = 0;
    state->complete = 0;
    spin_unlock(&(state->lock));

    wake_up_interruptible(&(state->ns_wq));
    wait_event_interruptible(state->client_wq, (state->complete == 1));

    spin_lock(&(state->lock));
    *segid_p = cmd->make.segid;
    spin_unlock(&(state->lock));

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_remove_ns(struct xpmem_partition * part, xpmem_segid_t segid) {
    struct ns_xpmem_state * state = part->ns_state;
    struct xpmem_cmd_ex * cmd = &(state->cmd);

    if (!state->initialized) {
        return -1;
    }

    printk("REMOVE_NS\n");

    while (mutex_lock_interruptible(&(state->mutex)));

    spin_lock(&(state->lock));
    cmd->type = XPMEM_REMOVE;
    cmd->remove.segid = segid;
    state->requested = 1;
    state->processed = 0;
    state->complete = 0;
    spin_unlock(&(state->lock));

    wake_up_interruptible(&(state->ns_wq));
    wait_event_interruptible(state->client_wq, (state->complete == 1));

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_get_ns(struct xpmem_partition * part, xpmem_segid_t segid, int flags, 
            int permit_type, u64 permit_value, xpmem_apid_t * apid_p) {
    struct ns_xpmem_state * state = part->ns_state;
    struct xpmem_cmd_ex * cmd = &(state->cmd);

    if (!state->initialized) {
        return -1;
    }

    printk("GET_NS\n");

    while (mutex_lock_interruptible(&(state->mutex)));

    spin_lock(&(state->lock));
    cmd->type = XPMEM_GET;
    cmd->get.segid = segid;
    cmd->get.flags = flags;
    cmd->get.permit_type = permit_type;
    cmd->get.permit_value = permit_value;
    state->requested = 1;
    state->processed = 0;
    state->complete = 0;
    spin_unlock(&(state->lock));

    wake_up_interruptible(&(state->ns_wq));
    wait_event_interruptible(state->client_wq, (state->complete == 1));

    spin_lock(&(state->lock));
    *apid_p = cmd->get.apid;
    spin_unlock(&(state->lock));

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_release_ns(struct xpmem_partition * part, xpmem_apid_t apid) {
    struct ns_xpmem_state * state = part->ns_state;
    struct xpmem_cmd_ex * cmd = &(state->cmd);

    if (!state->initialized) {
        return -1;
    }

    printk("RELEASE_NS\n");

    while (mutex_lock_interruptible(&(state->mutex)));

    spin_lock(&(state->lock));
    cmd->type = XPMEM_RELEASE;
    cmd->release.apid = apid;
    state->requested = 1;
    state->processed = 0;
    state->complete = 0;
    spin_unlock(&(state->lock));

    wake_up_interruptible(&(state->ns_wq));
    wait_event_interruptible(state->client_wq, (state->complete == 1));

    mutex_unlock(&(state->mutex));
    return 0;
}

static int xpmem_attach_ns(struct xpmem_partition * part, xpmem_apid_t apid, off_t off, 
            size_t size, u64 * vaddr) {
    struct ns_xpmem_state * state = part->ns_state;
    struct xpmem_cmd_ex * cmd = &(state->cmd);
    u64 * pfns;
    u64 num_pfns;

    if (!state->initialized) {
        return -1;
    }

    printk("ATTACH_NS\n");

    while (mutex_lock_interruptible(&(state->mutex)));

    spin_lock(&(state->lock));
    cmd->type = XPMEM_ATTACH;
    cmd->attach.apid = apid;
    cmd->attach.off = off;
    cmd->attach.size = size;
    state->requested = 1;
    state->processed = 0;
    state->complete = 0;
    spin_unlock(&(state->lock));

    wake_up_interruptible(&(state->ns_wq));
    wait_event_interruptible(state->client_wq, (state->complete == 1));

    spin_lock(&(state->lock));
    num_pfns = cmd->attach.num_pfns;
    pfns = cmd->attach.pfns;

    if (!pfns || num_pfns == 0) {
        *vaddr = 0;
    } else {
        *vaddr = (u64)xpmem_map_pfn_range(pfns, num_pfns);
        kfree(pfns);
    }

    spin_unlock(&(state->lock));
    mutex_unlock(&(state->mutex));

    return 0;
}

static int xpmem_detach_ns(struct xpmem_partition * part, u64 vaddr) {
    struct ns_xpmem_state * state = part->ns_state;
    struct xpmem_cmd_ex * cmd = &(state->cmd);

    if (!state->initialized) {
        return -1;
    }

    printk("DETACH_NS\n");

    while (mutex_lock_interruptible(&(state->mutex)));

    spin_lock(&(state->lock));
    cmd->type = XPMEM_DETACH;
    cmd->detach.vaddr = vaddr;
    state->requested = 1;
    state->processed = 0;
    state->complete = 0;
    spin_unlock(&(state->lock));

    wake_up_interruptible(&(state->ns_wq));
    wait_event_interruptible(state->client_wq, (state->complete == 1));

    xpmem_detach_vaddr(vaddr);

    mutex_unlock(&(state->mutex));
    return 0;
}

struct xpmem_extended_ops ns_ops = {
    .make               = xpmem_make_ns,
    .remove             = xpmem_remove_ns,
    .get                = xpmem_get_ns,
    .release            = xpmem_release_ns,
    .attach             = xpmem_attach_ns,
    .detach             = xpmem_detach_ns,
};


static int local_open(struct inode * inodep, struct file * filp) {
    return 0;
}

static int local_release(struct inode * inodep, struct file * filp) {
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    spin_lock(&(ns_state->lock));
    ns_state->local_fd = -1;
    spin_unlock(&(ns_state->lock));

    return 0;
}

static ssize_t local_read(struct file * filp, char __user * buffer, size_t size, loff_t * offp) {
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    if (size != sizeof(struct xpmem_cmd_ex)) {
        return -EINVAL;
    }

    spin_lock(&(ns_state->lock));
    if ((!ns_state->requested) || (ns_state->processed)) {
        spin_unlock(&(ns_state->lock));
        return 0;
    }

    if (copy_to_user(buffer, (void *)&(ns_state->cmd), size)) {
        spin_unlock(&(ns_state->lock));
        return -EFAULT;
    }

    ns_state->processed = 1;
    spin_unlock(&(ns_state->lock));
    return size;
}

static ssize_t local_write(struct file * filp, const char __user * buffer, size_t size, loff_t * offp) {
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;
    ssize_t ret = size;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    if (size != sizeof(struct xpmem_cmd_ex)) {
        return -EINVAL;
    }

    spin_lock(&(ns_state->lock));
    if ((!ns_state->requested || !ns_state->processed)) {
        printk(KERN_ERR "XPMEM local channel not writeable - no requests in process\n");
        return 0;
    }

    if (copy_from_user((void *)&(ns_state->cmd), buffer, sizeof(struct xpmem_cmd_ex))) {
        return -EFAULT;
    }

    switch (ns_state->cmd.type) {
        case XPMEM_MAKE_COMPLETE:
        case XPMEM_REMOVE_COMPLETE:
        case XPMEM_GET_COMPLETE:
        case XPMEM_RELEASE_COMPLETE:
        case XPMEM_ATTACH_COMPLETE:
        case XPMEM_DETACH_COMPLETE:
            ns_state->complete = 1;
            ns_state->requested = 0;
            ns_state->processed = 0;
            wake_up_interruptible(&(ns_state->client_wq));
            break;

        default:
            printk(KERN_ERR "Invalid local XPMEM write: %d\n", ns_state->cmd.type);
            ret = -EINVAL;
    }

    spin_unlock(&(ns_state->lock));
    return ret;
}

static unsigned int local_poll(struct file * filp, struct poll_table_struct * pollp) {
    unsigned int ret = 0;
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    poll_wait(filp, &(ns_state->ns_wq), pollp);

    spin_lock(&(ns_state->lock));
    if (ns_state->requested) {
        if (ns_state->processed) {
            printk("LOCAL POLL: write\n");
            ret = POLLOUT | POLLWRNORM;
        } else {
            printk("LOCAL POLL: read\n");
            ret = POLLIN | POLLRDNORM;
        }
    }
    spin_unlock(&(ns_state->lock));
    
    return ret;
}

static int remote_open(struct inode * inodep, struct file * filp) {
    return 0;
}

static int remote_release(struct inode * inodep, struct file * filp) {
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    spin_lock(&(ns_state->lock));
    ns_state->remote_fd = -1;
    spin_unlock(&(ns_state->lock));

    return 0;
}

static ssize_t remote_read(struct file * filp, char __user * buffer, size_t size, loff_t * offp) {
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    if (size != sizeof(struct xpmem_cmd_ex)) {
        return -EINVAL;
    }

    spin_lock(&(ns_state->lock));
    if (!ns_state->remote_requested) {
        spin_unlock(&(ns_state->lock));
        return 0;
    }

    if (copy_to_user(buffer, (void *)&(ns_state->remote_cmd), size)) {
        spin_unlock(&(ns_state->lock));
        return -EFAULT;
    }

    ns_state->remote_requested = 0;
    spin_unlock(&(ns_state->lock));
    return size;
}

static ssize_t remote_write(struct file * filp, const char __user * buffer, size_t size, loff_t * offp) {
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;
    struct xpmem_cmd_ex * cmd = NULL;
    ssize_t ret = size;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    if (size != sizeof(struct xpmem_cmd_ex)) {
        return -EINVAL;
    }

    spin_lock(&(ns_state->lock));
    if (ns_state->remote_requested) {
        printk(KERN_ERR "XPMEM remote channel not writeable - request already in process\n");
        return 0;
    }

    cmd = &(ns_state->remote_cmd);
    if (copy_from_user((void *)cmd, buffer, sizeof(struct xpmem_cmd_ex))) {
        return -EFAULT;
    }

    switch (cmd->type) {
        case XPMEM_GET: {
            printk("Received XPMEM_GET request(segid: %lli, flags: %lu, permit_type: %lu, permit_value: %llu)\n",
                (signed long long)cmd->get.segid,
                (unsigned long)cmd->get.flags,
                (unsigned long)cmd->get.permit_type,
                (unsigned long long)cmd->get.permit_value
            );

            if (xpmem_get_remote(&(cmd->get))) {
                printk("Request failed\n");
                cmd->get.apid = -1;
            }

            ns_state->remote_requested = 1;
            cmd->type = XPMEM_GET_COMPLETE;
            break;
        }

        case XPMEM_RELEASE: {
            printk("Received XPMEM_RELEASE request(apid: %lli)\n",
                (signed long long)cmd->release.apid
            );
            
            if (xpmem_release_remote(&(cmd->release))) {
                printk("Request failed\n");
            }

            ns_state->remote_requested = 1;
            cmd->type = XPMEM_RELEASE_COMPLETE;
            break;
        }

        case XPMEM_ATTACH: {
            printk("Received XPMEM_ATTACH request(apid: %lli, off: %llu, size: %llu)\n",
                (signed long long)cmd->attach.apid,
                (unsigned long long)cmd->attach.off,
                (unsigned long long)cmd->attach.size
            );

            if (xpmem_attach_remote(&(cmd->attach))) {
                printk("Request failed\n");
                cmd->attach.num_pfns = 0;
                cmd->attach.pfns = NULL;
            }

            printk("Created pfn list:\n");
            {
                u64 i;
                for (i = 0; i < cmd->attach.num_pfns; i++) {
                    printk("%llu  \n", (unsigned long long)cmd->attach.pfns[i]);
                }
                printk("\n");
            }

            ns_state->remote_requested = 1;
            cmd->type = XPMEM_ATTACH_COMPLETE;
            break;
        }

        case XPMEM_DETACH: {
            printk("Received XPMEM_DETACH request(vaddr: %llu)\n",
                (unsigned long long)cmd->detach.vaddr
            );

            if (xpmem_detach_remote(&(cmd->detach))) {
                printk("Request failed\n");
            }

            ns_state->remote_requested = 1;
            cmd->type = XPMEM_DETACH_COMPLETE;
            break;
        }

        default:
            printk(KERN_ERR "Invalid remote XPMEM write: %d\n", cmd->type);
            ret = -EINVAL;
    }

    spin_unlock(&(ns_state->lock));
    return ret;
}

static unsigned int remote_poll(struct file * filp, struct poll_table_struct * pollp) {
    unsigned int ret = 0;
    struct ns_xpmem_state * ns_state = (struct ns_xpmem_state *)filp->private_data;

    if (!ns_state || !ns_state->initialized) {
        return -EBADF;
    }

    poll_wait(filp, &(ns_state->ns_wq), pollp);

    spin_lock(&(ns_state->lock));
    if (ns_state->remote_requested) {
        printk("REMOTE POLL: read\n");
        ret = POLLIN | POLLRDNORM;
    } else {
        printk("REMOTE POLL: write\n");
        ret = POLLOUT | POLLWRNORM;
    }
    spin_unlock(&(ns_state->lock));
    
    return ret;
}

static struct file_operations local_fops = {
    .open       = local_open,
    .release    = local_release,
    .read       = local_read,
    .write      = local_write,
    .poll       = local_poll,
};

static struct file_operations remote_fops = {
    .open       = remote_open,
    .release    = remote_release,
    .read       = remote_read,
    .write      = remote_write,
    .poll       = remote_poll,
};

int xpmem_ns_init(struct xpmem_partition * part) {
    part->ns_state = kzalloc(sizeof(struct ns_xpmem_state), GFP_KERNEL);
    if (!part->ns_state) {
        return -1;
    }

    spin_lock_init(&(part->ns_state->lock));
    mutex_init(&(part->ns_state->mutex));
    init_waitqueue_head(&(part->ns_state->client_wq));
    init_waitqueue_head(&(part->ns_state->ns_wq));

    part->ns_state->local_fd = -1;
    part->ns_state->remote_fd = -1;
    part->ns_state->initialized = 1;
    return 0;
}

int xpmem_ns_deinit(struct xpmem_partition * part) {
    if (!part) {
        return 0;
    }

    if (part->ns_state) {
        kfree(part->ns_state);
    }

    part->ns_state = NULL;
    return 0;
}


int xpmem_local_connect(struct ns_xpmem_state * state) {
    if (!state || !state->initialized) {
        return -1;
    }

    spin_lock(&(state->lock));
    if (state->local_fd != -1) {
        printk(KERN_ERR "XPMEM local channel already connected\n");
        goto out;
    }

    state->local_fd = anon_inode_getfd("xpmem-ext-local", &local_fops, state, O_RDWR);
    if (state->local_fd < 0) {
        printk(KERN_ERR "Error creating XPMEM local inode\n");
    }

out:
    spin_unlock(&(state->lock));
    return state->local_fd;
}

int xpmem_local_disconnect(struct ns_xpmem_state * state) {
    if (!state || !state->initialized) {
        return -1;
    }

    spin_lock(&(state->lock));
    state->local_fd = -1;
    spin_unlock(&(state->lock));
    return 0;
}

int xpmem_remote_connect(struct ns_xpmem_state * state) {
    if (!state || !state->initialized) {
        return -1;
    }

    spin_lock(&(state->lock));
    if (state->remote_fd != -1) {
        printk(KERN_ERR "XPMEM remote channel already connected\n");
        goto out;
    }

    state->remote_fd = anon_inode_getfd("xpmem-ext-remote", &remote_fops, state, O_RDWR);
    if (state->remote_fd < 0) {
        printk(KERN_ERR "Error creating XPMEM remote inode\n");
    }

out:
    spin_unlock(&(state->lock));
    return state->remote_fd;
}

int xpmem_remote_disconnect(struct ns_xpmem_state * state) {
    if (!state || !state->initialized) {
        return -1;
    }

    spin_lock(&(state->lock));
    state->remote_fd = -1;
    spin_unlock(&(state->lock));
    return 0;
}
