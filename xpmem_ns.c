/*
 * XPMEM extensions for multiple domain support.
 *
 * xpmem_ns.c: The XPMEM name server
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
#include <linux/list.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>

#include <xpmem.h>
#include <xpmem_extended.h>
#include <xpmem_ns.h>
#include <xpmem_hashtable.h>


/* The XPMEM link map is used to connect the name server to all locally
 * attached domains in the system. The map has one entry for each VM and each
 * enclave connected to the name server, as well as one for local processes.
 *
 * Each domain in the system has a map of local connection links to a list of
 * XPMEM domids accessible via those links. For example, consider the following
 * topology:
 *
 *               < XPMEM name server>
 *                       ^
 *                       |
 *                       |
 *                  <  Dom 1  >
 *                   ^       ^
 *                   |       |
 *                   |       |
 *                <Dom 2>  <Dom 3>
 *                   ^
 *                   |
 *                   |
 *                <Dom 4>
 *
 * The maps look like:
 *
 * <Domain 0 (name server) map>
 *   [0: local] (local processes (domid 0) are connected via link 0)
 *   [1: <1, 2, 3, 4>] (domids 1, 2, 3, and 4 are downstream via link 1)
 *
 * <Domain 1 map>
 *   [0: local] (local processes (domid 1) are connected via link 0)
 *   [1: <2,4>] (domids 2 and 4 are downstream via link 1)
 *   [2: <3>]   (domid 3 is downstream via link 2)
 *
 * <Domain 2 map>
 *   [0: local] (local processes (domid 2) are connected via link 0)
 *   [1: <4>] (domid 4 is downstream via link 1)
 *
 * <Domain 3 map>
 *   [0: local] (local processes (domid 3) are connected via link 0)
 *
 * <Domain 4 map>
 *   [0: local] (local processes (domid 4) are connected via link 0)
 *
 */

struct xpmem_ns_state {
    /* Device initialization */
    int initialized;

    /* Has a command been issued? */
    int cmd_issued;

    /* command list */
    struct list_head cmd_list;

    /* protect command list access */
    spinlock_t lock;

    /* waitq for name server */
    wait_queue_head_t ns_waitq;

    /* kernel thread for running the name server */
    struct task_struct * ns_thread;

    /* Unique domids */
    atomic_t uniq_domid;

    /* Unique link */
    atomic_t uniq_link;

    /* map of XPMEM domids to local link ids (as specified above) */
    struct xpmem_hashtable * domid_map;

    /* map of link ids to command callback functions */
    struct xpmem_hashtable * link_map;

    /* map of XPMEM segids to XPMEM domids */
    struct xpmem_hashtable * segid_map;
};


struct xpmem_cmd_ex_iter {
    struct xpmem_cmd_ex * cmd;
    xpmem_link_id_t       link_id;
    struct list_head      node;
};

static u32
xpmem_hash_fn(uintptr_t key)
{
    return hash_long(key);
}

static int
xpmem_eq_fn(uintptr_t key1, uintptr_t key2)
{
    return (key1 == key2);
}

static inline char *
cmd_to_string(xpmem_op_t op)
{
    switch (op) {
        case XPMEM_MAKE:
            return "XPMEM_MAKE";
        case XPMEM_REMOVE:
            return "XPMEM_REMOVE";
        case XPMEM_GET:
            return "XPMEM_GET";
        case XPMEM_RELEASE:
            return "XPMEM_RELEASE";
        case XPMEM_ATTACH:
            return "XPMEM_ATTACH";
        case XPMEM_DETACH:
            return "XPMEM_DETACH";
        case XPMEM_MAKE_COMPLETE:
            return "XPMEM_MAKE_COMPLETE";
        case XPMEM_REMOVE_COMPLETE:
            return "XPMEM_REMOVE_COMPLETE";
        case XPMEM_GET_COMPLETE:
            return "XPMEM_GET_COMPLETE";
        case XPMEM_RELEASE_COMPLETE:
            return "XPMEM_RELEASE_COMPLETE";
        case XPMEM_ATTACH_COMPLETE:
            return "XPMEM_ATTACH_COMPLETE";
        case XPMEM_DETACH_COMPLETE:
            return "XPMEM_DETACH_COMPLETE";
        case XPMEM_PING_NS:
            return "XPMEM_PING_NS";
        case XPMEM_PING_NS_COMPLETE:
            return "XPMEM_PING_NS_COMPLETE";
        default:
            return "UNKNOWN OPERATION";
    }   
}

static inline char *
dom_type_to_string(xpmem_endpoint_t p)
{
    switch (p) {
        case VM: 
            return "VM";
        case ENCLAVE:
            return "Enclave";
        case LOCAL:
            return "Process";
        default:
            return "Unknown";
    }
}


static int32_t
alloc_uniq_segid(void)
{
    return 1;
}

static void
xpmem_ns_process_cmd(struct xpmem_ns_state * state,
                     xpmem_link_id_t         link_id;
                     struct xpmem_cmd_ex   * cmd)
{


}

/* TODO: This is the code when we are NOT the NS */
static void
xpmem_ns_process_cmd(struct xpmem_ns_state * state,
                     xpmem_link_id_t         link_id;
                     struct xpmem_cmd_ex   * cmd)
{
    /* First, we must allocate a domid if we don't have one already */
{



static int
xpmem_ns_thread_fn(void * arg)
{
    struct xpmem_ns_state * state = (struct xpmem_ns_state *)arg;

    while (1) {
        unsigned long flags;

        spin_lock_irqsave(&(state->lock), flags);
        {
            state->cmd_issued = !list_empty(&(state->cmd_list));
        }
        spin_unlock_irqrestore(&(state->lock), flags);

        mb();
        wait_event_interruptible(state->ns_waitq, state->cmd_issued == 1);

        {
            struct xpmem_cmd_ex_iter * iter = NULL;

            spin_lock_irqsave(&(state->lock), flags);
            {
                iter = list_first_entry(&(state->cmd_list), struct xpmem_cmd_ex_iter, node);
                list_del(&(iter->node));
            }
            spin_unlock_irqrestore(&(state->lock), flags);

            /* Process cmd */
            xpmem_ns_process_cmd(state, iter->cmd);

            /* Free list iterator and command */
            kfree(iter->cmd);
            kfree(iter);
        }
    }


    return 0;
}


static xpmem_link_id_t
alloc_xpmem_link_id(struct xpmem_ns_state * state)
{
    return (xpmem_link_id_t)atomic_inc_return(&(state->uniq_link));
}

static xpmem_domid_t 
alloc_xpmem_domid(struct xpmem_ns_state * state)
{
    return (xpmem_domid_t)atomic_inc_return(&(state->uniq_domid));
}

struct xpmem_partition *
xpmem_get_partition(void)
{
    extern struct xpmem_partition * xpmem_my_part;
    return xpmem_my_part;
}


int
xpmem_add_connection(struct xpmem_partition * part,
                     int (*in_cmd_fn)(struct xpmem_cmd_ex *))
{
    struct xpmem_ns_state * state   = part->ns_state;
    xpmem_link_id_t         link_id = 0;
    xpmem_domid_t           domid   = 0;

    if (!state || !state->initialized) {
        return -1;
    }

    link_id = alloc_xpmem_link_id(state);

    if (!htable_insert(state->link_map, (uintptr_t)link_id, (uintptr_t)in_cmd_fn)) {
        return -1;
    }

    return 0;
}


/* Package an XPMEM request and write to the name server */
int
xpmem_cmd_request(struct xpmem_partition * part,
                  xpmem_link_id_t          link_id
                  struct xpmem_cmd_ex    * cmd)
{
    struct xpmem_ns_state    * state = part->ns_state;
    struct xpmem_cmd_ex_iter * iter  = NULL;

    unsigned long flags = 0;

    if (!state || !state->initialized) {
        return -1;
    }

    iter = kmalloc(sizeof(struct xpmem_cmd_ex_iter), GFP_KERNEL);
    if (!iter) {
        return -ENOMEM;
    }

    /* Full command copy */
    {
        uint64_t pfn_len = 0;

        if (cmd->type == XPMEM_ATTACH_COMPLETE) {
            pfn_len = sizeof(uint64_t) * cmd->attach.num_pfns;
        }

        iter->cmd = kmalloc(sizeof(struct xpmem_cmd_ex) + pfn_len, GFP_KERNEL);
        if (!iter->cmd) {
            kfree(iter);
            return -ENOMEM;
        }

        memcpy(iter->cmd, cmd, sizeof(struct xpmem_cmd_ex) + pfn_len);
    }

    iter->link_id = link_id;

    spin_lock_irqsave(&(state->lock), flags);
    {
        list_add_tail(&(iter->node), &(state->cmd_list));
        state->cmd_issued = 1;
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    mb();
    wake_up_interruptible(&(state->ns_waitq));

    return 0;
}


int
xpmem_ns_init(struct xpmem_partition * part)
{
    struct xpmem_ns_state * state = NULL;

    state = kzalloc(sizeof(struct xpmem_ns_state), GFP_KERNEL);
    if (!state) {
        return -1;
    }

    /* Create hashtables */
    state->link_map = create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    if (!state->link_map) {
        kfree(state);
        return -1;
    }

    state->domid_map = create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    if (!state->domid_map) {
        free_htable(state->link_map, 0, 0);
        kfree(state);
        return -1;
    }

    state->segid_map = create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    if (!state->segid_map) {
        free_htable(state->link_map, 0, 0);
        free_htable(state->domid_map, 0, 0);
        kfree(state);
        return -1;
    }

    /* Create kernel thread */
    state->ns_thread = kthread_create(xpmem_ns_thread_fn, state, "kxpmem-ns");
    if (!state->ns_thread) {
        free_htable(state->link_map, 0, 0);
        free_htable(state->domid_map, 0, 0);
        free_htable(state->segid_map, 0, 0);
        kfree(state);
        return -1;
    }

    /* Create everything else */
    INIT_LIST_HEAD(&(state->cmd_list));
    spin_lock_init(&(state->lock));
    init_waitqueue_head(&(state->ns_waitq));

    atomic_set(&(state->uniq_link), 0);
    atomic_set(&(state->uniq_domid), 0);

    state->initialized = 1;
    part->ns_state = state;

    return 0;
}

int
xpmem_ns_deinit(struct xpmem_partition * part)
{
    struct xpmem_ns_state * state = part->ns_state;

    if (!state) {
        return 0;
    }

    /* Free hashtables */
    free_htable(state->link_map, 0, 0);
    free_htable(state->domid_map, 0, 0);
    free_htable(state->segid_map, 0, 0);

    /* Free kernel thread */
    kthread_stop(state->ns_thread);

    kfree(state);
    part->ns_state = NULL;

    return 0;
}
