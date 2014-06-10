/*
 * XPMEM extensions for multiple domain support.
 *
 * xpmem_ns.c: The XPMEM name service
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
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
 * XPMEM domids accessible "down the tree" via those links. The map also
 * includes the "upstream" link through which the name server may be reached.
 *
 * For example, consider the following topology:
 *
 *               <XPMEM name server>
 *                       ^
 *                       |
 *                       |
 *                       v
 *                  <  Dom 2  >
 *                   ^       ^
 *                   |       |
 *                   |       |
 *                   v       v
 *                <Dom 3>  <Dom 4>
 *                   ^
 *                   |
 *                   |
 *                   v 
 *                <Dom 5>
 *
 * The maps look like:
 *
 * <Domain 1 (name server) map>
 *   [0: 1] (local processes are connected via link 1)
 *   [2: 2] (domid 2 is connected via link 2)
 *   [3: 2] (domid 3 is connected via link 2)
 *   [4: 2] (domid 4 is connected via link 2)
 *   [5: 2] (domid 5 is connected via link 2)
 *
 * <Domain 2 map>
 *   [0: 1] (local processes are connected via link 1)
 *   [1: 2] (domid 1 (name server) is connected via link 2)
 *   [3: 3] (domid 3 is connected via link 3)
 *   [4: 4] (domid 4 is connected via link 4)
 *   [5: 3] (domid 5 is connected via link 3)
 *
 * <Domain 3 map>
 *   [0: 1] (local processes are connected via link 1)
 *   [1: 2] (domid 1 (name server) is connected via link 2)
 *   [2: 2] (domid 2 is connected via link 2)
 *   [5: 3] (domid 5 is connected via link 3)
 *
 * <Domain 4 map>
 *   [0: 1] (local processes are connected via link 1)
 *   [1: 2] (domid 1 (name server) is connected via link 2)
 *   [2: 2] (domid 2 is connected via link 2)
 *
 * <Domain 5 map>
 *   [0: 1] (local processes are connected via link 1)
 *   [1: 2] (domid 1 (name server) is connected via link 2)
 *   [3: 2] (domid 3 is connected via link 2)
 *
 *
 *
 */

#define XPMEM_MAX_LINK_ID 16
#define MIN_UNIQ_SEGID    32
#define MIN_UNIQ_DOMID    32

struct xpmem_ns_state {
    int             initialized;     /* device initialization */
    spinlock_t      lock;            /* state lock */
    xpmem_link_t    local_link;      /* link to our own domain */
    xpmem_domid_t   domid;           /* domid for this partition */

    atomic_t        uniq_link;       /* unique link generation */
    atomic_t        uniq_segid;      /* unique segid generation */
    atomic_t        uniq_domid;      /* unique domid generation */


    /* map of XPMEM segids to XPMEM domids */
    struct xpmem_hashtable * segid_map;

    /* map of XPMEM domids to local link ids (as specified above) */
    struct xpmem_hashtable * domid_map;

    /* map of link ids to connection structs */
    struct xpmem_hashtable * link_map;
};


struct xpmem_link_connection {
    xpmem_connection_t conn_type;
    void             * priv_data;
    int (*in_cmd_fn)(struct xpmem_cmd_ex *, void * priv_data); 
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


static int
alloc_xpmem_segid(struct xpmem_ns_state * state, xpmem_segid_t * segid)
{
    struct xpmem_id * id   = NULL;
    int32_t           uniq = 0;

    uniq = atomic_inc_return(&(state->uniq_segid));

    if (uniq > XPMEM_MAX_UNIQ_SEGID) {
        return -1;
    }

    id       = (struct xpmem_id *)segid;
    id->uniq = (unsigned short)(uniq * XPMEM_MAX_UNIQ_APID);

    return 0;
}

static xpmem_domid_t
alloc_xpmem_domid(struct xpmem_ns_state * state)
{
    return (xpmem_domid_t)atomic_inc_return(&(state->uniq_domid));
}

static xpmem_link_t
alloc_xpmem_link(struct xpmem_ns_state * state)
{
    xpmem_link_t id = (xpmem_link_t)atomic_inc_return(&(state->uniq_link));

    if (id > XPMEM_MAX_LINK_ID) {
        return -1;
    }

    return id;
}


/* Hashtable helpers */
static int
xpmem_add_segid(struct xpmem_ns_state * state, 
                xpmem_segid_t           segid,
                xpmem_domid_t           domid)
{
    unsigned long flags  = 0;
    int           status = 0;

    spin_lock_irqsave(&(state->lock), flags);
    {
        printk("Inserting %lli (domid %lli) in map %p\n",
             segid, domid, (void *)state->segid_map);
        status = htable_insert(state->segid_map,
                    (uintptr_t)segid,
                    (uintptr_t)domid);
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    return status;
}

static int
xpmem_add_domid(struct xpmem_ns_state * state, 
                xpmem_domid_t           domid,
                xpmem_link_t            link)
{
    unsigned long flags  = 0;
    int           status = 0;

    spin_lock_irqsave(&(state->lock), flags);
    {
        status = htable_insert(state->domid_map,
                    (uintptr_t)domid,
                    (uintptr_t)link);
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    return status;
}

static int
xpmem_add_link(struct xpmem_ns_state        * state, 
               xpmem_link_t                   link,
               struct xpmem_link_connection * conn)
{
    unsigned long flags  = 0;
    int           status = 0;

    spin_lock_irqsave(&(state->lock), flags);
    {
        status = htable_insert(state->link_map,
                    (uintptr_t)link,
                    (uintptr_t)conn);
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    return status;
}

static xpmem_domid_t
xpmem_search_or_remove_segid(struct xpmem_ns_state * state,
                             xpmem_segid_t           segid,
                             int                     remove)
{
    unsigned long flags  = 0;
    xpmem_domid_t result = 0;

    spin_lock_irqsave(&(state->lock), flags);
    {
        if (remove) {
            result = (xpmem_domid_t)htable_remove(state->segid_map,
                        (uintptr_t)segid, 
                        0);
        } else {
            printk("Searching %lli in map %p\n",
                 segid, (void *)state->segid_map);
            result = (xpmem_domid_t)htable_search(state->segid_map,
                        (uintptr_t)segid); 
        }
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    return result;
}

static xpmem_domid_t
xpmem_search_segid(struct xpmem_ns_state * state,
                   xpmem_segid_t           segid)
{
    return xpmem_search_or_remove_segid(state, segid, 0);
}

static xpmem_domid_t
xpmem_remove_segid(struct xpmem_ns_state * state,
                   xpmem_segid_t           segid)
{
    return xpmem_search_or_remove_segid(state, segid, 1);
}

static xpmem_link_t
xpmem_search_or_remove_domid(struct xpmem_ns_state * state,
                             xpmem_domid_t           domid,
                             int                     remove)
{
    unsigned long flags  = 0;
    xpmem_link_t  result = 0;

    spin_lock_irqsave(&(state->lock), flags);
    {
        if (remove) {
            result = (xpmem_link_t)htable_remove(state->domid_map,
                        (uintptr_t)domid,
                        0);
        } else {
            result = (xpmem_link_t)htable_search(state->domid_map,
                        (uintptr_t)domid);
        }
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    return result;
}

static xpmem_link_t
xpmem_search_domid(struct xpmem_ns_state * state,
                  xpmem_link_t             link)
{
    return xpmem_search_or_remove_domid(state, link, 0);
}

static xpmem_link_t
xpmem_remove_domid(struct xpmem_ns_state * state,
                  xpmem_link_t             link)
{
    return xpmem_search_or_remove_domid(state, link, 1);
}


static struct xpmem_link_connection *
xpmem_search_or_remove_link(struct xpmem_ns_state * state,
                            xpmem_link_t            link,
                            int                     remove)
{
    unsigned long                  flags  = 0;
    struct xpmem_link_connection * result = NULL;

    spin_lock_irqsave(&(state->lock), flags);
    {
        if (remove) {
            result = (struct xpmem_link_connection *)htable_remove(state->link_map,
                        (uintptr_t)link,
                        1);
        } else {
            result = (struct xpmem_link_connection *)htable_search(state->link_map,
                        (uintptr_t)link);
        }
    }
    spin_unlock_irqrestore(&(state->lock), flags);

    return result;
}

static struct xpmem_link_connection *
xpmem_search_link(struct xpmem_ns_state * state,
                  xpmem_link_t            link)
{
    return xpmem_search_or_remove_link(state, link, 0);
}

static struct xpmem_link_connection *
xpmem_remove_link(struct xpmem_ns_state * state,
                  xpmem_link_t            link)
{
    return xpmem_search_or_remove_link(state, link, 1);
}

/* Send a command along a connection link */
static int
xpmem_send_cmd_link(struct xpmem_ns_state * state,
                    xpmem_link_t            link, 
                    struct xpmem_cmd_ex   * cmd)
{
    struct xpmem_link_connection * conn = xpmem_search_link(state, link);

    if (conn == NULL) {
        return -1;
    }

    return conn->in_cmd_fn(cmd, conn->priv_data);
}


/* Process an XPMEM_PING/PONG_NS command */
static void
xpmem_ns_process_ping(struct xpmem_ns_state * state,
                      xpmem_link_t            link,
                      struct xpmem_cmd_ex   * cmd)
{
    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex * out_cmd  = cmd;
    xpmem_link_t          out_link = link;

    printk("Process ns ping\n");

    switch (cmd->type) {
        case XPMEM_PING_NS: {
            /* Respond with a PONG to the source */
            out_cmd->type = XPMEM_PONG_NS;

            break;
        }

        case XPMEM_PONG_NS: {
            /* We received a PONG. WTF */
            printk(KERN_ERR "XPMEM: name server received a PONG?"
                " Are there multiple name servers running?\n");

            return;
        }

        default: {
            printk(KERN_ERR "XPMEM: unknown PING operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
    }
}


/* Process an XPMEM_DOMID_REQUEST/RESPONSE command */
static void
xpmem_ns_process_domid(struct xpmem_ns_state * state,
                       xpmem_link_t            link,
                       struct xpmem_cmd_ex   * cmd)
{
    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex * out_cmd  = cmd;
    xpmem_link_t          out_link = link;

    printk("Process ns domid\n");

    switch (cmd->type) {
        case XPMEM_DOMID_REQUEST: {
            int ret = 0;

            /* A domid is requested by someone downstream from us on 'link' */
            out_cmd->domid_req.domid = alloc_xpmem_domid(state);

            /* Update domid map */
            ret = xpmem_add_domid(state, out_cmd->domid_req.domid, link);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                out_cmd->domid_req.domid = -1;
                goto out_domid_req;
            }

            out_domid_req:
            {
                out_cmd->type    = XPMEM_DOMID_RESPONSE;
                out_cmd->src_dom = state->domid;
            }

            break;
        }

        case XPMEM_DOMID_RESPONSE: {
            /* We've been allocated a domid.
             *
             * If our domain has no domid, assign it.
             * Otherwise, assign it to a link that has requested a domid from us
             */

            printk(KERN_ERR "XPMEM: name server has been allocated a domid?"
                " Are there multiple name servers running?\n");

            return;
        }
        default: {
            printk(KERN_ERR "XPMEM: unknown DOMID operation: %s\n",
                cmd_to_string(cmd->type));
            return;
        }
    }

    /* Write the response */
    if (xpmem_send_cmd_link(state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
    }
}



/* Process a regular XPMEM command. If we get here we are connected to the name
 * server already and have a domid
 */
static void
xpmem_ns_process_cmd(struct xpmem_ns_state * state,
                    xpmem_link_t             link,
                    struct xpmem_cmd_ex    * cmd)
{
    /* There's no reason not to reuse the input command struct for responses */
    struct xpmem_cmd_ex * out_cmd  = cmd;
    xpmem_link_t          out_link = link;

    printk("Process ns command %s\n", cmd_to_string(cmd->type));

    /* If the command is coming from the local domain, it is routed to the NS,
     * regardless of whether it's a request or completion. So, we set the
     * dst_dom field
     *
     * The src, however, it only set for requests
     */
    if (link == state->local_link) {
        cmd->dst_dom = XPMEM_NS_DOMID;
    }

    /* Set the src dom if needed */
    switch (cmd->type) {
        case XPMEM_MAKE:
        case XPMEM_REMOVE:
        case XPMEM_GET:
        case XPMEM_RELEASE:
        case XPMEM_ATTACH:
        case XPMEM_DETACH:
            if (link == state->local_link) {
                cmd->src_dom = state->domid;
            }
            break;

        default:
            break;
    }

    /* If the command is coming from the local domain, it is routed to the NS,
     * regardless of whether it's a request or completion. So, we set the
     * dst_dom field
     *
     * The src, however, it only set for requests
     */
    if (link == state->local_link) {
        cmd->dst_dom = XPMEM_NS_DOMID;
    }

    /* Set the src dom if needed */
    switch (cmd->type) {
        case XPMEM_MAKE:
        case XPMEM_REMOVE:
        case XPMEM_GET:
        case XPMEM_RELEASE:
        case XPMEM_ATTACH:
        case XPMEM_DETACH:
            if (link == state->local_link) {
                cmd->src_dom = state->domid;
            }
            break;

        default:
            break;
    }

    switch (cmd->type) {
        case XPMEM_MAKE: {
            int ret = 0;

            /* Allocate a unique segid to this domain */
            if (alloc_xpmem_segid(state, &(cmd->make.segid))) {
                printk(KERN_ERR "XPMEM: cannot allocate segid. This is a problem\n");
                out_cmd->make.segid = -1;
                goto out_make;
            }

            /* Store in hashtable */
            ret = xpmem_add_segid(state, cmd->make.segid, cmd->src_dom);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot insert into segid hashtable\n");
                out_cmd->make.segid = -1;
                goto out_make;
            }

            printk("XPMEM: added segid %lli to hashtable\n", cmd->make.segid);


            out_make: 
            {
                out_cmd->type    = XPMEM_MAKE_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = state->domid;
            }

            break;

        }

        case XPMEM_REMOVE: {
            xpmem_domid_t domid = 0;

            /* Remove segid from map */
            domid = xpmem_remove_segid(state, cmd->remove.segid); 

            if (domid == 0) {
                printk(KERN_ERR "XPMEM: cannot remove segid %lli from hashtable\n",
                    cmd->remove.segid);
            }

            {
                out_cmd->type    = XPMEM_REMOVE_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = state->domid;
            }

            break;

        }

        case XPMEM_GET: {
            xpmem_domid_t domid = 0;

            /* Search segid map */
            domid = xpmem_search_segid(state, cmd->get.segid);

            if (domid == 0) {
                printk(KERN_ERR "XPMEM: cannot find segid %lli in hashtable\n",
                    cmd->get.segid);
                goto err_get;
            }

            /* Search domid map for link */
            out_link = xpmem_search_domid(state, domid);

            if (out_link == 0) {
                printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable."
                    " This should be impossible\n", domid);
                goto err_get;
            }

            out_cmd->dst_dom = domid;

            break;

            err_get:
            {
                out_cmd->get.apid = -1;
                out_cmd->type     = XPMEM_GET_COMPLETE;
                out_cmd->dst_dom  = cmd->src_dom;
                out_cmd->src_dom  = state->domid;
                out_link          = link;
            }

            break;
        }

        case XPMEM_RELEASE: {
            /* Extended apids are always allocated in the range [segid.uniq.
             * segid.uniq + XPMEM_MAX_UNIQ_APID), so we can simply reuse the
             * segid htable by flooring the apid uniq field. Yes, this is a hack
             */
            struct xpmem_id search_id;

            memcpy(&search_id, &(cmd->release.apid), sizeof(struct xpmem_id));
            search_id.uniq &= ~(XPMEM_MAX_UNIQ_APID - 1);

            {
                xpmem_domid_t domid = 0;

                /* Search segid map */
                domid = xpmem_search_segid(state, *((xpmem_segid_t *)&search_id));

                if (domid == 0) {
                    printk(KERN_ERR "XPMEM: cannot find apid %lli in hashtable\n",
                        cmd->release.apid);
                    goto err_release;
                }

                /* Search domid map for link */
                out_link = xpmem_search_domid(state, domid);

                if (out_link == 0) {
                    printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable."
                        " This should be impossible\n", domid);
                    goto err_release;
                }

                out_cmd->dst_dom = domid;
            }

            break;

            err_release:
            {
                out_cmd->type    = XPMEM_RELEASE_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = state->domid;
                out_link         = link;
            }

            break;
        }

        case XPMEM_ATTACH: {
            /* Extended apids are always allocated in the range [segid.uniq.
             * segid.uniq + XPMEM_MAX_UNIQ_APID), so we can simply reuse the
             * segid htable by flooring the apid uniq field. Yes, this is a hack
             */
            struct xpmem_id search_id;

            memcpy(&search_id, &(cmd->attach.apid), sizeof(struct xpmem_id));
            search_id.uniq &= ~(XPMEM_MAX_UNIQ_APID - 1);

            {
                xpmem_domid_t domid = 0;

                /* Search segid map */
                domid = xpmem_search_segid(state, *((xpmem_segid_t *)&search_id));

                if (domid == 0) {
                    printk(KERN_ERR "XPMEM: cannot find apid %lli in hashtable\n",
                        cmd->attach.apid);
                    goto err_attach;
                }

                /* Search domid map for link */
                out_link = xpmem_search_domid(state, domid);

                if (out_link == 0) {
                    printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable."
                        " This should be impossible\n", domid);
                    goto err_attach;
                }

                out_cmd->dst_dom = domid;
            }

            break;

            err_attach:
            {
                out_cmd->type    = XPMEM_ATTACH_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = state->domid;
                out_link         = link;
            }

            break;
        }

        case XPMEM_DETACH: {
            /* Ignore detaches for now, because it's not clear how to figure out
             * a destination domain from just a virtual address
             */
            {
                out_cmd->type    = XPMEM_DETACH_COMPLETE;
                out_cmd->dst_dom = cmd->src_dom;
                out_cmd->src_dom = state->domid;
                out_link         = link;
            }

            break;
        }

        case XPMEM_GET_COMPLETE: 
        case XPMEM_RELEASE_COMPLETE:
        case XPMEM_ATTACH_COMPLETE:
        case XPMEM_DETACH_COMPLETE: {
            /* The destination is now the original source */
            cmd->dst_dom = cmd->src_dom;

            /* Search for the appropriate link */
            out_link = xpmem_search_domid(state, cmd->dst_dom);

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

    printk("XPMEM: sending cmd %s to link %lli\n",
        cmd_to_string(out_cmd->type), out_link);

    /* Write the response */
    if (xpmem_send_cmd_link(state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
    }

}


/* Interface */

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
    struct xpmem_ns_state * state = part->ns_state;
    xpmem_link_t             link  = 0;        

    if (!state || !state->initialized) {
        return -1;
    }

    link = alloc_xpmem_link(state);

    if (link > 0) {
        struct xpmem_link_connection * conn  = NULL;
        int                            error = 0;

        if (type == XPMEM_CONN_LOCAL) {
            state->local_link = link;

            /* Update the domid map to remember our own domid */
            error = xpmem_add_domid(state, state->domid, state->local_link);

            if (error == 0) {
                printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                return -1;
            }
        }

        conn = kmalloc(sizeof(struct xpmem_link_connection), GFP_KERNEL);
        if (!conn) {
            printk(KERN_ERR "XPMEM: out of memory\n");
            return -ENOMEM;
        }

        conn->priv_data = priv_data;
        conn->conn_type = type;
        conn->in_cmd_fn = in_cmd_fn;

        /* Update the link map */
        error = xpmem_add_link(state, link, conn);

        if (error == 0) {
            printk(KERN_ERR "XPMEM: cannot insert into link hashtable\n");
            return -1;
        }
    }

    return link;
}

EXPORT_SYMBOL(xpmem_add_connection);


int
xpmem_remove_connection(struct xpmem_partition * part,
                        xpmem_link_t             link)
{
    struct xpmem_ns_state        * state = NULL;
    struct xpmem_link_connection * conn  = NULL;

    state = part->ns_state;
    conn  = xpmem_remove_link(state, link);

    if (!conn) {
        return -1; 
    }   

    if (conn->conn_type == XPMEM_CONN_LOCAL) {
        state->local_link = -1; 
    }   

    kfree(conn);

    return 0;
}

EXPORT_SYMBOL(xpmem_remove_connection);



int
xpmem_cmd_deliver(struct xpmem_partition * part,
                  xpmem_link_t             link,
                  struct xpmem_cmd_ex    * cmd)
{
    struct xpmem_ns_state * state = part->ns_state;

    if (!state || !state->initialized) {
        return -1;
    }

    switch (cmd->type) {
        case XPMEM_PING_NS:
        case XPMEM_PONG_NS:
            xpmem_ns_process_ping(state, link, cmd);
            break;

        case XPMEM_DOMID_REQUEST:
        case XPMEM_DOMID_RESPONSE:
            xpmem_ns_process_domid(state, link, cmd);
            break;

        default:
            xpmem_ns_process_cmd(state, link, cmd);
            break;
    }

    return 0;
}

EXPORT_SYMBOL(xpmem_cmd_deliver);


int
xpmem_ns_init(struct xpmem_partition * part)
{
    struct xpmem_ns_state * state = kzalloc(sizeof(struct xpmem_ns_state), GFP_KERNEL);
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

    state->segid_map = create_htable(0, xpmem_hash_fn, xpmem_eq_fn);
    if (!state->segid_map) {
        free_htable(state->domid_map, 0, 0);
        free_htable(state->link_map, 1, 0);
        kfree(state);
        return -1;
    }

    /* Create everything else */
    spin_lock_init(&(state->lock));
    atomic_set(&(state->uniq_link), 0);
    atomic_set(&(state->uniq_segid), MIN_UNIQ_SEGID);
    atomic_set(&(state->uniq_domid), MIN_UNIQ_DOMID);

    /* Name server gets a well-known domid */
    state->local_link   = -1;
    state->domid        = XPMEM_NS_DOMID;
    part->ns_state      = state;
    state->initialized  = 1;

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
    free_htable(state->domid_map, 0, 0);
    free_htable(state->link_map, 1, 0);
    free_htable(state->segid_map, 0, 0);

    kfree(state);
    part->ns_state = NULL;

    printk("XPMEM ns deinited\n");

    return 0;
}
