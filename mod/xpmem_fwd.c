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
#include <linux/delay.h>

#include <asm/uaccess.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>
#include <xpmem_iface.h>
#include <xpmem_hashtable.h>


#define PING_PERIOD       10

struct xpmem_fwd_state {
    /* Lock for fwd state */
    spinlock_t                     lock;
    
    /* "Upstream" link to the nameserver */
    xpmem_link_t                   ns_link; 

    /* Have we requested a domid */
    int                            domid_requested;

    /* list of outstanding domid requests for this domain. Requests that cannot
     * be immediately serviced are put on this list
     */
    struct list_head               domid_req_list;

    /* kernel thread sending XPMEM pings */
    struct task_struct           * ping_thread;   
    int                            ping_should_exit;

    /* waitq for kernel thread */
    wait_queue_head_t              ping_waitq;
    int                            ping_condition;

    /* timer for waking up ping_thread */
    struct timer_list              ping_timer;
};


struct xpmem_domid_req_iter {
    xpmem_link_t     link;
    struct list_head node;
};


/* Ping all of the connections we have looking for the nameserver, skipping id
 * 'skip'
 */
static void
xpmem_ping_ns(struct xpmem_partition_state * part_state, 
              xpmem_link_t                   skip)
{
    struct xpmem_cmd_ex      ping_cmd;

    memset(&(ping_cmd), 0, sizeof(struct xpmem_cmd_ex));

    ping_cmd.type    = XPMEM_PING_NS;
    ping_cmd.req_dom = -1;
    ping_cmd.src_dom = -1;
    ping_cmd.dst_dom = XPMEM_NS_DOMID;

    {
        int i = 0;
        for (i = 0; i <= XPMEM_MAX_LINK_ID; i++) {
            xpmem_link_t search_id = (xpmem_link_t)i;

            if (search_id == skip) {
                continue;
            }

            /* Don't PING the local domain */
            if (search_id == part_state->local_link) {
                continue;
            }

            if (xpmem_search_link(part_state, search_id)) {
                if (xpmem_send_cmd_link(part_state, search_id, &ping_cmd)) {
                    printk(KERN_ERR "XPMEM: cannot send PING on link %lli\n", search_id);
                }
            }

        }
    }
}

/* Pong all of the connections we have notifying path to the nameserver,
 * skipping id 'skip'
 */
static void
xpmem_pong_ns(struct xpmem_partition_state * part_state,
              xpmem_link_t                   skip)
{
    struct xpmem_cmd_ex pong_cmd;

    memset(&(pong_cmd), 0, sizeof(struct xpmem_cmd_ex));

    pong_cmd.type    = XPMEM_PONG_NS;
    pong_cmd.req_dom = -1;
    pong_cmd.src_dom = -1;
    pong_cmd.dst_dom = -1;

    {
        int i = 0;
        for (i = 0; i <= XPMEM_MAX_LINK_ID; i++) {
            xpmem_link_t search_id = (xpmem_link_t)i;

            if (search_id == skip) {
                continue;
            }

            /* Don't PONG the local domain */
            if (search_id == part_state->local_link) {
                continue;
            }

            if (xpmem_search_link(part_state, search_id)) {
                if (xpmem_send_cmd_link(part_state, search_id, &pong_cmd)) {
                    printk(KERN_ERR "XPMEM: cannot send PONG on link %lli\n", search_id);
                }
            }
        }
    }
}


/* Do we have a link to the ns? */
static int
xpmem_have_ns_link(struct xpmem_fwd_state * fwd_state)
{
    unsigned long            flags     = 0;
    int                      have_link = 0;

    spin_lock_irqsave(&(fwd_state->lock), flags);
    {
        if (fwd_state->ns_link > 0) {
            have_link = 1;
        }
    }
    spin_unlock_irqrestore(&(fwd_state->lock), flags);

    return have_link;
}


/* Process an XPMEM_PING/PONG_NS command */
static void
xpmem_fwd_process_ping_cmd(struct xpmem_partition_state * part_state,
                           xpmem_link_t                   link,
                           struct xpmem_cmd_ex          * cmd)
{
    struct xpmem_fwd_state * fwd_state = part_state->fwd_state;

    switch (cmd->type) {
        case XPMEM_PING_NS: {
            /* Do we know the way to the nameserver that is not through the link
             * pinging us? If we do, respond with a PONG.
             */
            if (xpmem_have_ns_link(fwd_state)) {
                /* Send PONG back to the source */
                cmd->type = XPMEM_PONG_NS;

                if (xpmem_send_cmd_link(part_state, link, cmd)) {
                    printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
                }
            }

            break;
        }

        case XPMEM_PONG_NS: {
            unsigned long flags = 0;
            int           ret   = 0;
            int           req   = 0;

            /* We received a PONG. So, the nameserver can be found through this
             * link
             */

            /* Remember the link */
            spin_lock_irqsave(&(fwd_state->lock), flags);
            {
                fwd_state->ns_link = link;

                req = fwd_state->domid_requested;
                if (req == 0) {
                    fwd_state->domid_requested = 1;
                }
            }
            spin_unlock_irqrestore(&(fwd_state->lock), flags);

            /* Update the domid map to remember this link */
            ret = xpmem_add_domid(part_state, XPMEM_NS_DOMID, link);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot insert domid %lli into hashtable\n", (xpmem_domid_t)XPMEM_NS_DOMID);
            }

            /* Broadcast the PONG to all our neighbors, except the source */
            xpmem_pong_ns(part_state, link);

            /* Have we requested a domid? */
            if (req == 0) {
                struct xpmem_cmd_ex domid_req;
                memset(&(domid_req), 0, sizeof(struct xpmem_cmd_ex));

                domid_req.type    = XPMEM_DOMID_REQUEST;
                domid_req.req_dom = -1;
                domid_req.src_dom = -1;
                domid_req.dst_dom = XPMEM_NS_DOMID;

                if (xpmem_send_cmd_link(part_state, fwd_state->ns_link, &domid_req)) {
                    printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", fwd_state->ns_link);
                }
            }

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
xpmem_fwd_process_domid_cmd(struct xpmem_partition_state * part_state,
                            xpmem_link_t                   link,
                            struct xpmem_cmd_ex          * cmd)
{
    struct xpmem_fwd_state * fwd_state = part_state->fwd_state;

    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex    * out_cmd  = cmd;
    xpmem_link_t             out_link = link;

    switch (cmd->type) {
        case XPMEM_DOMID_REQUEST: {
            /* A domid is requested by someone downstream from us on link
             * 'link'. If we can't reach the nameserver, just return failure,
             * because the request should not come through us unless we have a
             * route already
             */
            if (!xpmem_have_ns_link(fwd_state)) {
                out_cmd->domid_req.domid = -1;
                goto out_domid_req;
            }

            /* Buffer the request */
            {
                struct xpmem_domid_req_iter * iter = NULL;
                unsigned long                 flags = 0;

                iter = kmalloc(sizeof(struct xpmem_domid_req_iter), GFP_KERNEL);
                if (!iter) {
                    printk(KERN_ERR "XPMEM: out of memory\n");
                    out_cmd->domid_req.domid = -1;
                    goto out_domid_req;
                }

                iter->link = link;

                spin_lock_irqsave(&(fwd_state->lock), flags);
                {
                    list_add_tail(&(iter->node), &(fwd_state->domid_req_list));
                }
                spin_unlock_irqrestore(&(fwd_state->lock), flags);

                /* Forward request up to the nameserver */
                out_link = fwd_state->ns_link;
            }

            break;

            out_domid_req:
            {
                out_cmd->type    = XPMEM_DOMID_RESPONSE;
                out_cmd->src_dom = part_state->domid;
            }

            break;
        }

        case XPMEM_DOMID_RESPONSE: {
            int ret = 0;
            /* We've been allocated a domid.
             *
             * If our domain has no domid, take it for ourselves it.
             * Otherwise, assign it to a link that has requested a domid from us
             */
             
            if (part_state->domid <= 0) {
                part_state->domid = cmd->domid_req.domid;

                /* Update the domid map to remember our own domid */
                ret = xpmem_add_domid(part_state, part_state->domid, part_state->local_link);

                if (ret == 0) {
                    printk(KERN_ERR "XPMEM: cannot insert domid %lli into hashtable\n", part_state->domid);
                }

                return;
            } else {
                struct xpmem_domid_req_iter * iter = NULL;
                unsigned long                 flags = 0;

                if (list_empty(&(fwd_state->domid_req_list))) {
                    printk(KERN_ERR "XPMEM: we currently do not support the buffering of XPMEM domids\n");
                    return;
                }

                spin_lock_irqsave(&(fwd_state->lock), flags);
                {
                    iter = list_first_entry(&(fwd_state->domid_req_list),
                                struct xpmem_domid_req_iter,
                                node);
                    list_del(&(iter->node));
                }
                spin_unlock_irqrestore(&(fwd_state->lock), flags);

                /* Forward the domid to this link */
                out_link = iter->link;
                kfree(iter);

                /* Update the domid map to remember who has this */
                ret = xpmem_add_domid(part_state, cmd->domid_req.domid, out_link);

                if (ret == 0) {
                    printk(KERN_ERR "XPMEM: cannot insert domid %lli into hashtable\n", cmd->domid_req.domid);
                    out_cmd->domid_req.domid = -1;
                }
            }

            break;
        }

        case XPMEM_DOMID_RELEASE:
            /* Someone downstream is releasing their domid: simply forward to the
             * namserver */
            out_link = xpmem_search_domid(part_state, out_cmd->dst_dom);

            if (out_link == 0) {
                printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable\n", out_cmd->dst_dom);
                return;
            }

            break;

        default: {
            printk(KERN_ERR "XPMEM: unknown domid operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    /* Send the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", out_link);
    }
}

static void
xpmem_set_failure(struct xpmem_cmd_ex * cmd)
{
    switch (cmd->type) {
        case XPMEM_MAKE:
            cmd->make.segid = -1;
            break;

        case XPMEM_REMOVE:
            break;

        case XPMEM_GET:
            cmd->get.apid = -1;
            break;

        case XPMEM_RELEASE:
            break;

        case XPMEM_ATTACH:
            cmd->attach.pfns = NULL;
            cmd->attach.num_pfns = 0;
            break;

        case XPMEM_DETACH:
            break;

        default:
            break;
    }
}

static void
xpmem_set_complete(struct xpmem_cmd_ex * cmd)
{
    switch (cmd->type) {
        case XPMEM_MAKE:
            cmd->type = XPMEM_MAKE_COMPLETE;
            break;

        case XPMEM_REMOVE:
            cmd->type = XPMEM_REMOVE_COMPLETE;
            break;

        case XPMEM_GET:
            cmd->type = XPMEM_GET_COMPLETE;
            break;

        case XPMEM_RELEASE:
            cmd->type = XPMEM_RELEASE_COMPLETE;
            break;

        case XPMEM_ATTACH:
            cmd->type = XPMEM_ATTACH_COMPLETE;
            break;

        case XPMEM_DETACH:
            cmd->type = XPMEM_DETACH_COMPLETE;
            break;

        default:
            break;
    }
}


/* Process a regular XPMEM command. If we get here we are connected to the name
 * server already and have a domid
 */
static void
xpmem_fwd_process_xpmem_cmd(struct xpmem_partition_state * part_state,
                           xpmem_link_t                    link,
                           struct xpmem_cmd_ex           * cmd)
{
    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex * out_cmd  = cmd;
    xpmem_link_t          out_link = link;

    /* If we don't have a domid, we need to fail */
    if (part_state->domid <= 0) {
        printk(KERN_ERR "This domain has no XPMEM domid. Are you running the nameserver anywhere?\n");

        xpmem_set_failure(out_cmd);
        xpmem_set_complete(out_cmd);

        if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
            printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", out_link);
        }
        return;
    }
    
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

            out_link = xpmem_search_domid(part_state, out_cmd->dst_dom);

            if (out_link == 0) {
                printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable\n", out_cmd->dst_dom);
                return;
            }

            break;
        }

        default: {
            printk(KERN_ERR "XPMEM: unknown operation: %s\n", cmd_to_string(cmd->type));
            return;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", out_link);
    }
}



static void 
prepare_domids(struct xpmem_partition_state * part_state,
               xpmem_link_t                   link,
               struct xpmem_cmd_ex          * cmd)
{
    /* If the source is local, we need to setup the domids for routing - otherwise we just
     * forward to what's already been set
     */
    if (link == part_state->local_link) {
        if (cmd->req_dom == 0) {
            /* The request is being generated here: set the req domid */
            cmd->req_dom = part_state->domid;
        } 

        /* Route to the NS */
        cmd->src_dom = part_state->domid;
        cmd->dst_dom = XPMEM_NS_DOMID;
    }
}

int
xpmem_fwd_deliver_cmd(struct xpmem_partition_state * part_state,
                      xpmem_link_t                   link,
                      struct xpmem_cmd_ex          * cmd)
{

    /* Prepare the domids for routing, if necessary */
    prepare_domids(part_state, link, cmd);

    switch (cmd->type) {
        case XPMEM_PING_NS:
        case XPMEM_PONG_NS:
            xpmem_fwd_process_ping_cmd(part_state, link, cmd);
            break;

        case XPMEM_DOMID_REQUEST:
        case XPMEM_DOMID_RESPONSE:
        case XPMEM_DOMID_RELEASE:
            xpmem_fwd_process_domid_cmd(part_state, link, cmd);
            break;

        default:
            xpmem_fwd_process_xpmem_cmd(part_state, link, cmd);
            break;
    }

    return 0;
}



/*
 * Kernel thread for pinging the name server
 *
 * The current policy is to ping periodically (every PING_PERIOD seconds) until
 * the name server is found
 */
static int
xpmem_ping_fn(void * private)
{
    struct xpmem_partition_state * part_state = (struct xpmem_partition_state *)private;
    struct xpmem_fwd_state       * fwd_state  = NULL;

    fwd_state = part_state->fwd_state;

    while (1) {

        /* Wait on waitq  */
        wait_event_interruptible(fwd_state->ping_waitq, 
            ((fwd_state->ping_condition   == 1) ||
             (fwd_state->ping_should_exit == 1))
        );    

        /* Exit criteria */
        if (fwd_state->ping_should_exit) {
            break;
        }

        /* Reset condition */
        fwd_state->ping_condition = 0;
        mb();

        /* If we have a link, we die */
        if (xpmem_have_ns_link(fwd_state)) {
            break;
        }

        /* Send a PING */
        xpmem_ping_ns(part_state, 0);

        /* Restart timer */
        mod_timer(&(fwd_state->ping_timer), jiffies + (HZ * PING_PERIOD));
    }

    /* Wait on waitq for exit signal */
    wait_event_interruptible(fwd_state->ping_waitq, 
         (fwd_state->ping_should_exit == 1)
    );    

    return 0;
}

/* 
 * Ping timer
 */
static void
xpmem_ping_timer_fn(unsigned long data)
{
    struct xpmem_partition_state * part_state = (struct xpmem_partition_state *)data;
    struct xpmem_fwd_state       * fwd_state  = NULL;

    if (!part_state || !part_state->initialized) {
        return;
    }

    fwd_state = part_state->fwd_state;

    if (!fwd_state) {
        return;
    }

    /* Wakeup waitq */
    fwd_state->ping_condition = 1;
    mb();

    wake_up_interruptible(&(fwd_state->ping_waitq));
}


int
xpmem_fwd_init(struct xpmem_partition_state * part_state)
{
    struct xpmem_fwd_state * fwd_state = kmalloc(sizeof(struct xpmem_fwd_state), GFP_KERNEL);
    if (!fwd_state) {
        return -1;
    }

    /* Save partition state pointer */
    part_state->fwd_state = fwd_state;

    spin_lock_init(&(fwd_state->lock));
    INIT_LIST_HEAD(&(fwd_state->domid_req_list));

    fwd_state->ns_link         = -1;
    fwd_state->domid_requested = 0;

    /* Ping thread waitqueue */
    init_waitqueue_head(&(fwd_state->ping_waitq));

    /* Waitqueue condition */
    fwd_state->ping_condition   = 0;
    fwd_state->ping_should_exit = 0;
    mb();

    /* Set up the ping thread */
    fwd_state->ping_thread = kthread_create(
            xpmem_ping_fn,
            part_state,
            "xpmem-ping"
    );

    if (fwd_state->ping_thread == NULL) {
        printk(KERN_ERR "XPMEM: cannot create kernel thread\n");
        kfree(fwd_state);
        return -1;
    }

    /* Start it */
    wake_up_process(fwd_state->ping_thread);

    /* Create timer */
    init_timer(&(fwd_state->ping_timer));

    /* Set it up */
    fwd_state->ping_timer.expires  = jiffies + HZ;
    fwd_state->ping_timer.function = xpmem_ping_timer_fn;
    fwd_state->ping_timer.data     = (unsigned long)part_state;

    /* Start the timer */
    add_timer(&(fwd_state->ping_timer));

    printk("XPMEM forwarding service initialized\n");

    return 0;
}

int
xpmem_fwd_deinit(struct xpmem_partition_state * part_state)
{
    struct xpmem_fwd_state * fwd_state = part_state->fwd_state;

    if (!fwd_state) {
        return 0;
    }

    /* Kill timer */
    del_timer_sync(&(fwd_state->ping_timer));

    /* Stop kernel thread, if it's running */
    fwd_state->ping_should_exit = 1;
    mb();

    wake_up_interruptible(&(fwd_state->ping_waitq));

    /* Send a domid release, if we have one */
    if (part_state->domid > 0) {
        struct xpmem_cmd_ex dom_cmd;

        memset(&(dom_cmd), 0, sizeof(struct xpmem_cmd_ex));

        dom_cmd.type            = XPMEM_DOMID_RELEASE;
        dom_cmd.req_dom         = part_state->domid;
        dom_cmd.src_dom         = part_state->domid;
        dom_cmd.dst_dom         = XPMEM_NS_DOMID;
        dom_cmd.domid_req.domid = part_state->domid;

        if (xpmem_send_cmd_link(part_state, fwd_state->ns_link, &dom_cmd)) {
            printk(KERN_ERR "XPMEM: cannot send DOMID_RELEASE on link %lli\n", fwd_state->ns_link);
        }
    }

    /* Delete domid cmd list */
    {
        struct xpmem_domid_req_iter * iter = NULL;
        struct xpmem_domid_req_iter * next = NULL;

        list_for_each_entry_safe(iter, next, &(fwd_state->domid_req_list), node) {
            list_del(&(iter->node));
            kfree(iter);
        }
    }

    kfree(fwd_state);
    part_state->fwd_state = NULL;

    printk("XPMEM forwarding service deinitialized\n");

    return 0;
}