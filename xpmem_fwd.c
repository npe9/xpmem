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
#include <xpmem_extended.h>
#include <xpmem_iface.h>
#include <xpmem_hashtable.h>


#define PING_PERIOD       10

struct xpmem_fwd_state {
    /* Lock for fwd state */
    spinlock_t                     lock;
    
    /* Have we requested a domid */
    int                            domid_requested;

    /* "Upstream" link to the nameserver */
    xpmem_link_t                   ns_link; 

    /* list of outstanding domid requests for this domain. Requests that cannot
     * be immediately serviced are put on this list
     */
    struct list_head               domid_req_list;

    /* timer set off at state creation that pings the nameserver */
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
    ping_cmd.type = XPMEM_PING_NS;

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
    pong_cmd.type = XPMEM_PONG_NS;

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

    printk("xpmem fwd ping\n");

    switch (cmd->type) {
        case XPMEM_PING_NS: {
            /* Do we know the way to the nameserver that is not through the link
             * pinging us? 
             *
             * If we do, respond with a PONG. If not, broadcast the PING to all
             * our neighbors, except the link pinging us
             */
            if (xpmem_have_ns_link(fwd_state)) {
                /* Send PONG back to the source */
                cmd->type = XPMEM_PONG_NS;

                if (xpmem_send_cmd_link(part_state, link, cmd)) {
                    printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
                }
            } else {
                /* Broadcast the PING to everyone but the source */
                xpmem_ping_ns(part_state, link);
            }

            break;
        }

        case XPMEM_PONG_NS: {
            unsigned long flags = 0;
            int           ret   = 0;

            /* We received a PONG. So, the nameserver can be found through this
             * link
             */

            /* Remember the link */
            spin_lock_irqsave(&(fwd_state->lock), flags);
            {
                fwd_state->ns_link = link;
            }
            spin_unlock_irqrestore(&(fwd_state->lock), flags);

            /* Update the domid map to remember this link */
            ret = xpmem_add_domid(part_state, XPMEM_NS_DOMID, link);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
            }

            /* Broadcast the PONG to all our neighbors, except the source */
            xpmem_pong_ns(part_state, link);

            /* Have we requested a domid */
            {
                unsigned long flags = 0;
                int domid_requested = 0;

                spin_lock_irqsave(&(fwd_state->lock), flags); 
                {
                    domid_requested = fwd_state->domid_requested;
                    if (!domid_requested) {
                        fwd_state->domid_requested = 1;
                    }
                }
                spin_unlock_irqrestore(&(fwd_state->lock), flags);


                if (!domid_requested) {
                    struct xpmem_cmd_ex domid_req;
                    memset(&(domid_req), 0, sizeof(struct xpmem_cmd_ex));

                    domid_req.type = XPMEM_DOMID_REQUEST;

                    printk("Sending DOMID request\n");

                    if (xpmem_send_cmd_link(part_state, fwd_state->ns_link, &domid_req)) {
                        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", fwd_state->ns_link);
                    }
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

    printk("xpmem fwd domid\n");

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
                    printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                }

                return;
            } else {
                struct xpmem_domid_req_iter * iter = NULL;
                unsigned long                 flags = 0;

                if (list_empty(&(fwd_state->domid_req_list))) {
                    printk(KERN_ERR "XPMEM: we currently do not support the buffering of"
                        " XPMEM domids\n");
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
                    printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                    out_cmd->domid_req.domid = -1;
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

    printk("xpmem fwd cmd\n");

    /* If we don't have a domid, we have to fail */
    if (part_state->domid <= 0) {
        printk(KERN_ERR "This domain has no XPMEM domid. Are you running the nameserver anywhere?\n");

        xpmem_set_failure(out_cmd);
        xpmem_set_complete(out_cmd);
        
        if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
            printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", out_link);
        }
        return;
    }
    
    /* If the command is coming from the local domain, it is routed to the NS,
     * regardless of whether it's a request or a completion. So, we set the
     * dst_dom field
     *
     * The src, however, is only set for requests
     */
    if (link == part_state->local_link) {
        cmd->dst_dom = XPMEM_NS_DOMID;
    }

    switch (cmd->type) {
        case XPMEM_MAKE:
        case XPMEM_REMOVE:
        case XPMEM_GET:
        case XPMEM_RELEASE:
        case XPMEM_ATTACH:
        case XPMEM_DETACH: {
            if (link == part_state->local_link) {
                cmd->src_dom = part_state->domid;
            }
        }
        case XPMEM_MAKE_COMPLETE:
        case XPMEM_REMOVE_COMPLETE:
        case XPMEM_GET_COMPLETE:
        case XPMEM_RELEASE_COMPLETE:
        case XPMEM_ATTACH_COMPLETE:
        case XPMEM_DETACH_COMPLETE: {

            out_link = xpmem_search_domid(part_state, cmd->dst_dom);

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

    /* Write the response */
    if (xpmem_send_cmd_link(part_state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", out_link);
    }
}


int
xpmem_fwd_deliver_cmd(struct xpmem_partition_state * part_state,
                      xpmem_link_t                   link,
                      struct xpmem_cmd_ex          * cmd)
{
    switch (cmd->type) {
        case XPMEM_PING_NS:
        case XPMEM_PONG_NS:
            xpmem_fwd_process_ping_cmd(part_state, link, cmd);
            break;

        case XPMEM_DOMID_REQUEST:
        case XPMEM_DOMID_RESPONSE:
            xpmem_fwd_process_domid_cmd(part_state, link, cmd);
            break;

        default:
            xpmem_fwd_process_xpmem_cmd(part_state, link, cmd);
            break;
    }

    return 0;
}



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
    struct xpmem_partition_state * part_state = (struct xpmem_partition_state *)data;
    struct xpmem_fwd_state       * fwd_state  = NULL;

    if (!part_state || !part_state->initialized) {
        return;
    }

    fwd_state = part_state->fwd_state;

    if (!xpmem_have_ns_link(fwd_state)) {
        /* Reset and restart the timer */
        fwd_state->ping_timer.expires = jiffies + (PING_PERIOD * HZ);
        add_timer(&(fwd_state->ping_timer));

        /* Send another PING */
        xpmem_ping_ns(part_state, 0);
    }
}


int
xpmem_fwd_init(struct xpmem_partition_state * part_state)
{
    struct xpmem_fwd_state * fwd_state = kmalloc(sizeof(struct xpmem_fwd_state), GFP_KERNEL);
    if (!fwd_state) {
        return -1;
    }

    spin_lock_init(&(fwd_state->lock));
    INIT_LIST_HEAD(&(fwd_state->domid_req_list));

    fwd_state->domid_requested = 0;
    fwd_state->ns_link         = -1;

    /* Set up the timer */
    init_timer(&(fwd_state->ping_timer));
    fwd_state->ping_timer.expires = jiffies + HZ;
    fwd_state->ping_timer.data = (unsigned long)part_state;
    fwd_state->ping_timer.function = xpmem_ping_timer_fn;
    
    /* Start the timer */
    add_timer(&(fwd_state->ping_timer));

    part_state->fwd_state = fwd_state;
    return 0;
}

int
xpmem_fwd_deinit(struct xpmem_partition_state * part_state)
{
    struct xpmem_fwd_state * fwd_state = part_state->fwd_state;

    if (!fwd_state) {
        return 0;
    }

    /* Stop timer */
    del_timer_sync(&(fwd_state->ping_timer));

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

    return 0;
}
