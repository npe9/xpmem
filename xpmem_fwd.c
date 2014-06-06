/*
 * XPMEM extensions for multiple domain support.
 *
 * xpmem_fwd.c: The XPMEM forwarding service
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/delay.h>

#include <asm/uaccess.h>

#include <xpmem.h>
#include <xpmem_ns.h>
#include <xpmem_extended.h>
#include <xpmem_hashtable.h>


/* The XPMEM link map is used to connect the forwarding service to all locally
 * attached domains in the system. The map has one entry for each VM and each
 * enclave connected to the domain, as well as one for local processes.
 *
 * Each domain in the system has a map of local connection links to a list of
 * XPMEM domids accessible via those links. For example, consider the following
 * topology:
 *
 *               <XPMEM name server>
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

#define XPMEM_MAX_LINK_ID 16
#define PING_PERIOD       10

struct xpmem_fwd_state {
    int             initialized;     /* device initialization */
    spinlock_t      lock;            /* state lock */
    xpmem_link_t    ns_link;         /* link to the name server */
    xpmem_link_t    local_link;      /* link to our own domain */
    xpmem_domid_t   domid;           /* domid for this partition */
    atomic_t        uniq_link;       /* unique link generation */


    /* ping list */
    struct list_head  ping_list;
    int               ping_issued;

    /* domid list */
    struct list_head  domid_list;
    int               domid_issued;

    /* command list */
    struct list_head cmd_list;
    int              cmd_issued;

    /* list of outstanding domid requests for this domain. Requests that cannot
     * be immediately serviced are put on this list
     */
    struct list_head domid_req_list;

    /* map of XPMEM domids to local link ids (as specified above) */
    struct xpmem_hashtable * domid_map;

    /* map of link ids to connection structs */
    struct xpmem_hashtable * link_map;

    /* waitq for forwarding service */
    wait_queue_head_t    fwd_waitq;

    /* kernel thread for running the forwarding service */
    struct task_struct * fwd_thread;

    /* timer set off at state creation that pings the nameserver */
    struct timer_list ping_timer;
};


struct xpmem_cmd_ex_iter {
    struct xpmem_cmd_ex * cmd;
    xpmem_link_t          link;
    struct list_head      node;
};

struct xpmem_domid_req_iter {
    xpmem_link_t     link;
    struct list_head node;
};

struct xpmem_link_connection {
    int (*in_cmd_fn)(struct xpmem_cmd_ex *, void * priv_data); 
    void * priv_data;
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
        case XPMEM_PONG_NS:
            return "XPMEM_PONG_NS";
        case XPMEM_DOMID_REQUEST:
            return "XPMEM_DOMID_REQUEST";
        case XPMEM_DOMID_RESPONSE:
            return "XPMEM_DOMID_RESPONSE";
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


/* Send a command along a connection link */
static int
xpmem_send_cmd_link(struct xpmem_fwd_state * state,
                    xpmem_link_t             link, 
                    struct xpmem_cmd_ex    * cmd)
{
    struct xpmem_link_connection * conn = NULL;

    conn = (struct xpmem_link_connection *)
        htable_search(state->link_map, (uintptr_t)link);

    if (conn == NULL) {
        return -1;
    }

    return conn->in_cmd_fn(cmd, conn->priv_data);
}

/* Ping all of the connections we have looking for the nameserver, skipping id
 * 'skip'
 */
static void
xpmem_ping_ns(struct xpmem_fwd_state * state, 
              xpmem_link_t             skip)
{
    struct xpmem_cmd_ex ping_cmd;

    memset(&(ping_cmd), 0, sizeof(struct xpmem_cmd_ex));
    ping_cmd.type = XPMEM_PING_NS;

    {
        int i = 0;
        for (i = 0; i <= XPMEM_MAX_LINK_ID; i++) {
            xpmem_link_t search_id = (xpmem_link_t)i;

            if (search_id == skip) {
                continue;
            }

            /* Don't PING the local domain */
            if (search_id == state->local_link) {
                continue;
            }

            if (xpmem_send_cmd_link(state, search_id, &ping_cmd)) {
                printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", search_id);
            }
        }
    }
}

/* Pong all of the connections we have notifying path to the nameserver,
 * skipping id 'skip'
 */
static void
xpmem_pong_ns(struct xpmem_fwd_state * state,
              xpmem_link_t             skip)
{
    struct xpmem_cmd_ex pong_cmd;

    memset(&(pong_cmd), 0, sizeof(struct xpmem_cmd_ex));
    pong_cmd.type = XPMEM_PONG_NS;

    {
        int i = 0;
        for (i = 0; i <= XPMEM_MAX_LINK_ID; i++) {
            xpmem_link_t search_id = (xpmem_link_t)i;

            if (search_id == skip) {
                continue;
            }

            /* Don't PONG the local domain */
            if (search_id == state->local_link) {
                continue;
            }

            if (xpmem_send_cmd_link(state, search_id, &pong_cmd)) {
                printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", search_id);
            }
        }
    }
}


/* Do we have a link to the ns? */
static int
xpmem_have_ns_link(struct xpmem_fwd_state * state)
{
    unsigned long flags     = 0;
    int           have_link = 0;

    spin_lock_irqsave(&(state->lock), flags);
    {
        if (state->ns_link > 0) {
            have_link = 1;
        }
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    return have_link;
}


/* Process an XPMEM_PING/PONG_NS command */
static void
xpmem_fwd_process_ping(struct xpmem_fwd_state * state,
                       xpmem_link_t             link,
                       struct xpmem_cmd_ex    * cmd)
{
    unsigned long flags;

    switch (cmd->type) {
        case XPMEM_PING_NS: {
            /* Do we know the way to the nameserver that is not through the link
             * pinging us? 
             *
             * If we do, respond with a PONG. If not, broadcast the PING to all
             * our neighbors, except the link pinging us
             */
            if (xpmem_have_ns_link(state)) {
                /* Send PONG back to the source */
                cmd->type = XPMEM_PONG_NS;

                if (xpmem_send_cmd_link(state, link, cmd)) {
                    printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
                }
            } else {
                /* Broadcast the PING to everyone but the source */
                xpmem_ping_ns(state, link);
            }

            break;
        }

        case XPMEM_PONG_NS: {
            /* We received a PONG. So, the nameserver can be found through this
             * link
             */

            /* Remember the link */
            spin_lock_irqsave(&(state->lock), flags);
            {
                state->ns_link = link;
            }
            spin_unlock_irqrestore(&(state->lock), flags);

            /* Update the domid map to remember this link */
            {
                int ret = 0;

                ret = htable_insert(state->domid_map,
                        (uintptr_t)XPMEM_NS_DOMID,
                        (uintptr_t)link);

                if (ret == 0) {
                    printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                }
            }

            /* Broadcast the PONG to all our neighbors, except the source */
            xpmem_pong_ns(state, link);

            break;
        }

        default: {
            printk(KERN_ERR "XPMEM: unknown PING operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    
}

/* Process an XPMEM_DOMID_REQUEST/RESPONSE command */
static void
xpmem_fwd_process_domid(struct xpmem_fwd_state * state,
                        xpmem_link_t             link,
                        struct xpmem_cmd_ex    * cmd)
{
    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex * out_cmd  = cmd;
    xpmem_link_t          out_link = link;

    switch (cmd->type) {
        case XPMEM_DOMID_REQUEST: {
            /* A domid is requested by someone downstream from us on link
             * 'link'. If we can't reach the nameserver, just return failure,
             * because the request should not come through us unless we have a
             * route already
             */
            if (!xpmem_have_ns_link(state)) {
                out_cmd->domid_req.domid = -1;
                goto out_domid_req;
            }

            /* Buffer the request */
            {
                struct xpmem_domid_req_iter * iter = NULL;

                iter = kmalloc(sizeof(struct xpmem_domid_req_iter), GFP_KERNEL);
                if (!iter) {
                    printk(KERN_ERR "XPMEM: out of memory\n");
                    out_cmd->domid_req.domid = -1;
                    goto out_domid_req;
                }

                iter->link = link;
                list_add_tail(&(iter->node), &(state->domid_req_list));

                /* Forward request up to the nameserver */
                out_link = state->ns_link;
            }

            break;

            out_domid_req:
            {
                out_cmd->type   = XPMEM_DOMID_RESPONSE;
                out_cmd->src_dom = state->domid;
            }

            break;
        }

        case XPMEM_DOMID_RESPONSE: {
            /* We've been allocated a domid.
             *
             * If our domain has no domid, take it for ourselves it.
             * Otherwise, assign it to a link that has requested a domid from us
             */
             
            if (state->domid == 0) {
                state->domid = cmd->domid_req.domid;

                /* Update the domid map to remember our own domid */
                {
                    int ret = 0;

                    ret = htable_insert(state->domid_map,
                            (uintptr_t)state->domid,
                            (uintptr_t)state->local_link);

                    if (ret == 0) {
                        printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                    }
                }

                return;
            } else {
                struct xpmem_domid_req_iter * iter = NULL;

                if (list_empty(&(state->domid_req_list))) {
                    printk(KERN_ERR "XPMEM: we currently do not support the buffering of"
                        " XPMEM domids\n");
                    return;
                }

                iter = list_first_entry(&(state->domid_req_list),
                            struct xpmem_domid_req_iter,
                            node);
                list_del(&(iter->node));

                /* Forward the domid to this link */
                out_link = iter->link;
                kfree(iter);

                /* Update the domid map to remember who has this */
                {
                    int ret = 0;

                    ret = htable_insert(state->domid_map,
                            (uintptr_t)cmd->domid_req.domid,
                            (uintptr_t)out_link);

                    if (ret == 0) {
                        printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                        out_cmd->domid_req.domid = -1;
                    }
                }
            }

            break;
        }
        default: {
            printk(KERN_ERR "XPMEM: unknown DOMID operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    /* Send the response */
    if (xpmem_send_cmd_link(state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", out_link);
    }
}


/* Process a regular XPMEM command. If we get here we are connected to the name
 * server already and have a domid
 */
static void
xpmem_fwd_process_cmd(struct xpmem_fwd_state * state,
                     xpmem_link_t              link,
                     struct xpmem_cmd_ex     * cmd)
{
    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex * out_cmd  = cmd;
    xpmem_link_t          out_link = link;


    switch (cmd->type) {

        case XPMEM_MAKE:
        case XPMEM_REMOVE:
        case XPMEM_GET:
        case XPMEM_RELEASE:
        case XPMEM_ATTACH:
        case XPMEM_DETACH:
        case XPMEM_MAKE_COMPLETE:
        case XPMEM_REMOVE_COMPLETE:
        case XPMEM_GET_COMPLETE:
        case XPMEM_RELEASE_COMPLETE:
        case XPMEM_ATTACH_COMPLETE:
        case XPMEM_DETACH_COMPLETE: {
            out_link = htable_search(state->domid_map,
                (uintptr_t)cmd->dst_dom);

            if (out_link == 0) {
                printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable."
                    " This should be impossible\n", cmd->dst_dom);
                return;
            }

            break;
        }

        default: {
            printk(KERN_ERR "XPMEM: unknown operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    /* Send the response */
    if (xpmem_send_cmd_link(state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", out_link);
    }
}


/*
 * This is the kernel thread implementing the forwarding service
 *
 * Normal XPMEM commands are only processed if the domain has allocated a domid
 * from the nameserver. Without a domid, all commands will be buffered in the
 * queue until the domid is allocated.
 *
 * domids are allocated by sending special XPMEM commands. XPMEM_REQUEST_DOMID
 * will formulate a request and send it to the nameserver. Before this command
 * can be sent, however, the domain must know which link to send the command
 * on. This knowledge is gained by sending XPMEM_PING_NS commands along all
 * connected links and waiting for an XPMEM_PONG_NS on one of them.
 *
 * Thus, the kernel thread will always process XPMEM_PING/PONG_NS commands.
 * These commands are placed in the ping_list as opposed to the normal cmd_list.
 */
static int
xpmem_fwd_thread_fn(void * arg)
{
    struct xpmem_fwd_state * state = (struct xpmem_fwd_state *)arg;

    while (1) {
        unsigned long flags;

        spin_lock_irqsave(&(state->lock), flags);
        {
            state->ping_issued = !list_empty(&(state->ping_list));
            state->domid_issued = !list_empty(&(state->domid_list));
            state->cmd_issued = !list_empty(&(state->cmd_list));
        }
        spin_unlock_irqrestore(&(state->lock), flags);


        /* The condition for processing is:
         *  (1) PING/PONG in ping list
         *
         *              OR
         *
         *  (2) DOMID req/response in domid list
         *
         *              OR
         *
         *  (3) Command available on cmd list
         *              AND
         *      this domain has a domid
         */
        mb();
        wait_event_interruptible(state->fwd_waitq,
            ( (state->ping_issued  == 1) || 
              (state->domid_issued == 1) ||
                ( (state->cmd_issued == 1) &&
                  (state->domid       > 0)
                )
            )
        );
        

        if (state->ping_issued) {
            struct xpmem_cmd_ex_iter * iter = NULL;

            spin_lock_irqsave(&(state->lock), flags);
            {
                iter = list_first_entry(&(state->ping_list), struct xpmem_cmd_ex_iter, node);
                list_del(&(iter->node));
            }
            spin_unlock_irqrestore(&(state->lock), flags);

            xpmem_fwd_process_ping(state, iter->link, iter->cmd);

            kfree(iter->cmd);
            kfree(iter);
        } else if (state->domid_issued) {
            struct xpmem_cmd_ex_iter * iter = NULL;

            spin_lock_irqsave(&(state->lock), flags);
            {
                iter = list_first_entry(&(state->ping_list), struct xpmem_cmd_ex_iter, node);
                list_del(&(iter->node));
            }
            spin_unlock_irqrestore(&(state->lock), flags);

            xpmem_fwd_process_domid(state, iter->link, iter->cmd);

            kfree(iter->cmd);
            kfree(iter);
        } else {
            struct xpmem_cmd_ex_iter * iter = NULL;

            spin_lock_irqsave(&(state->lock), flags);
            {
                iter = list_first_entry(&(state->cmd_list), struct xpmem_cmd_ex_iter, node);
                list_del(&(iter->node));
            }
            spin_unlock_irqrestore(&(state->lock), flags);

            xpmem_fwd_process_cmd(state, iter->link, iter->cmd);

            kfree(iter->cmd);
            kfree(iter);
        }
    }

    return 0;
}



static xpmem_link_t
alloc_xpmem_link(struct xpmem_fwd_state * state)
{
    xpmem_link_t id = (xpmem_link_t)atomic_inc_return(&(state->uniq_link));

    if (id > XPMEM_MAX_LINK_ID) {
        return -1;
    }

    return id;
}


struct xpmem_partition *
xpmem_get_partition(void)
{
    extern struct xpmem_partition * xpmem_my_part;
    return xpmem_my_part;
}

EXPORT_SYMBOL(xpmem_get_partition);

xpmem_link_t
xpmem_add_connection(struct xpmem_partition * part,
                     xpmem_connection_t       type,
                     int (*in_cmd_fn)(struct xpmem_cmd_ex *, void * priv_data),
                     void                   * priv_data)
{
    struct xpmem_fwd_state * state = part->fwd_state;
    xpmem_link_t             link  = 0;        

    if (!state || !state->initialized) {
        return -1;
    }

    link = alloc_xpmem_link(state);

    if (link > 0) {
        struct xpmem_link_connection * conn  = NULL;
        unsigned long                  flags = 0;
        int                            error = 0;

        if (type == XPMEM_CONN_LOCAL) {
            state->local_link = link;
        }

        conn = kmalloc(sizeof(struct xpmem_link_connection), GFP_KERNEL);
        if (!conn) {
            printk(KERN_ERR "XPMEM: out of memory\n");
            return -ENOMEM;
        }

        conn->in_cmd_fn = in_cmd_fn;
        conn->priv_data = priv_data;

        spin_lock_irqsave(&(state->lock), flags);
        {
            if (htable_insert(state->link_map, (uintptr_t)link,
                        (uintptr_t)conn) == 0) {
                error = -1;
            }
        }
        spin_unlock_irqrestore(&(state->lock), flags);

        if (error) {
            printk(KERN_ERR "XPMEM: cannot insert into link hashtable\n");
            return error;
        }
    }

    return link;
}

EXPORT_SYMBOL(xpmem_add_connection);

int
xpmem_cmd_deliver(struct xpmem_partition * part,
                  xpmem_link_t             link,
                  struct xpmem_cmd_ex    * cmd)
{
    struct xpmem_fwd_state *   state = part->fwd_state;
    struct xpmem_cmd_ex_iter * iter  = NULL;
    unsigned long              flags = 0;

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

    iter->link = link;


    /* Put on the correct list */
    if ( (cmd->type == XPMEM_PING_NS) ||
         (cmd->type == XPMEM_PONG_NS)
       )
    {
        spin_lock_irqsave(&(state->lock), flags);
        {
            list_add_tail(&(iter->node), &(state->ping_list));
            state->ping_issued = 1;
        }
        spin_unlock_irqrestore(&(state->lock), flags);
    } else if ( (cmd->type == XPMEM_DOMID_REQUEST) ||
                (cmd->type == XPMEM_DOMID_RESPONSE)
              )
    {
        spin_lock_irqsave(&(state->lock), flags);
        {
            list_add_tail(&(iter->node), &(state->domid_list));
            state->domid_issued = 1;
        }
        spin_unlock_irqrestore(&(state->lock), flags);
    } else {
        spin_lock_irqsave(&(state->lock), flags);
        {
            list_add_tail(&(iter->node), &(state->cmd_list));
            state->cmd_issued = 1;
        }
        spin_unlock_irqrestore(&(state->lock), flags);
    }


    mb();
    wake_up_interruptible(&(state->fwd_waitq));

    return 0;
}

EXPORT_SYMBOL(xpmem_cmd_deliver);

/*
 * Timer function for pinging the name server
 *
 * The current policy is to periodically (every PING_PERIOD seconds) ping the
 * nameserver, trying to find a link from which we can access it.
 * 
 * Once we have a route, we request a domid and die
 */
static void
xpmem_ping_timer_fn(unsigned long data)
{
    struct xpmem_fwd_state * state = (struct xpmem_fwd_state *)data;

    /* It's possible that something killed the state during a request */
    if (!state || !state->initialized) {
        return;
    }

    if (xpmem_have_ns_link(state)) {
        struct xpmem_cmd_ex domid_req;
        memset(&(domid_req), 0, sizeof(struct xpmem_cmd_ex));

        domid_req.type = XPMEM_DOMID_REQUEST;

        if (xpmem_send_cmd_link(state, state->ns_link, &domid_req)) {
            printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", state->ns_link);
        }
    } else {
        /* Reset and restart the timer */
        state->ping_timer.expires = jiffies + (PING_PERIOD * HZ);
        add_timer(&(state->ping_timer));

        /* Send another PING */
        xpmem_ping_ns(state, 0);
    }
}


int
xpmem_fwd_init(struct xpmem_partition * part)
{

    struct xpmem_fwd_state * state = kzalloc(sizeof(struct xpmem_fwd_state), GFP_KERNEL);
    if (!state) {
        return -1; 
    }

    /* Create hashtables */
    state->domid_map = create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    if (!state->domid_map) {
        kfree(state);
        return -1;
    }

    state->link_map = create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    if (!state->link_map) {
        free_htable(state->domid_map, 0, 0);
        kfree(state);
        return -1;
    }

    /* Create everything else */
    INIT_LIST_HEAD(&(state->ping_list));
    INIT_LIST_HEAD(&(state->domid_list));
    INIT_LIST_HEAD(&(state->cmd_list));
    INIT_LIST_HEAD(&(state->domid_req_list));

    spin_lock_init(&(state->lock));
    atomic_set(&(state->uniq_link), 0);
    init_waitqueue_head(&(state->fwd_waitq));

    state->ping_issued  = 0;
    state->domid_issued = 0;
    state->cmd_issued   = 0;
    state->ns_link      = -1;
    state->local_link   = -1;
    state->domid        = -1;

    /* Set up the timer */
    init_timer(&(state->ping_timer));
    state->ping_timer.expires = jiffies + (PING_PERIOD * HZ);
    state->ping_timer.data = (unsigned long)state;
    state->ping_timer.function = xpmem_ping_timer_fn;
    
    /* Start the timer */
    add_timer(&(state->ping_timer));


    /* Create kernel thread */
    state->fwd_thread = kthread_create(xpmem_fwd_thread_fn, state, "kxpmem-fwd");
    if (!state->fwd_thread) {
        free_htable(state->domid_map, 0, 0);
        free_htable(state->link_map, 1, 0);
        kfree(state);
        return -1;
    }

    /* Start kernel thread */
    wake_up_process(state->fwd_thread);

    part->fwd_state = state;

    state->initialized  = 1;
    return 0;
}

int
xpmem_fwd_deinit(struct xpmem_partition * part)
{
    struct xpmem_fwd_state * state = part->fwd_state;

    if (!state) {
        return 0;
    }

    /* Free hashtables */
    free_htable(state->domid_map, 0, 0);
    free_htable(state->link_map, 1, 0);

    /* Free kernel threads */
    kthread_stop(state->fwd_thread);

    /* Free ping/domid/cmd lists */
    {
        struct xpmem_cmd_ex_iter * iter = NULL;
        struct xpmem_cmd_ex_iter * next = NULL;

        list_for_each_entry_safe(iter, next, &(state->ping_list), node) {
            list_del(&(iter->node));
            kfree(iter->cmd);
            kfree(iter);
        }

        list_for_each_entry_safe(iter, next, &(state->domid_list), node) {
            list_del(&(iter->node));
            kfree(iter->cmd);
            kfree(iter);
        }

        list_for_each_entry_safe(iter, next, &(state->cmd_list), node) {
            list_del(&(iter->node));
            kfree(iter->cmd);
            kfree(iter);
        }
    }


    /* Free domid req list */
    {
        struct xpmem_domid_req_iter * iter = NULL;
        struct xpmem_domid_req_iter * next = NULL;

        list_for_each_entry_safe(iter, next, &(state->domid_req_list), node) {
            list_del(&(iter->node));
            kfree(iter);
        }
    }

    kfree(state);
    part->fwd_state = NULL;

    return 0;
}
