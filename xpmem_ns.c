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
    /* TODO: map PFNS */
    num_pfns = cmd->attach.num_pfns;
    pfns = cmd->attach.pfns;
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

    mutex_unlock(&(state->mutex));
    return 0;
}

struct xpmem_extended_ops ns_ops = {
    .make       = xpmem_make_ns,
    .remove     = xpmem_remove_ns,
    .get        = xpmem_get_ns,
    .release    = xpmem_release_ns,
    .attach     = xpmem_attach_ns,
    .detach     = xpmem_detach_ns,
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
