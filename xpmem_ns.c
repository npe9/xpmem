/*
 * XPMEM extensions for multiple domain support.
 *
 * xpmem_ns.c: The XPMEM name service
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

#define MIN_UNIQ_SEGID    32
#define MIN_UNIQ_DOMID    32

struct xpmem_ns_state {
    int             initialized;     /* device initialization */
    spinlock_t      lock;            /* state lock */
    xpmem_link_t    local_link;      /* link to our own domain */
    xpmem_domid_t   domid;           /* domid for this partition */
    atomic_t        uniq_link;       /* unique link generation */
    xpmem_segid_t   uniq_segid;      /* unique segid generation */
    xpmem_domid_t   uniq_domid;      /* unique domid generation */


    /* ping list */
    struct list_head  ping_list;
    int               ping_issued;

    /* domid list */
    struct list_head  domid_list;
    int               domid_issued;

    /* command list */
    struct list_head cmd_list;
    int              cmd_issued;


    /* map of XPMEM domids to local link ids (as specified above) */
    struct xpmem_hashtable * domid_map;

    /* map of link ids to connection structs */
    struct xpmem_hashtable * link_map;

    /* map of XPMEM segids to XPMEM domids */
    struct xpmem_hashtable * segid_map;

    /* waitq for name service */
    wait_queue_head_t    ns_waitq;

    /* kernel thread for running the name service */
    struct task_struct * ns_thread;
};


struct xpmem_cmd_ex_iter {
    struct xpmem_cmd_ex * cmd;
    xpmem_link_t          link;
    struct list_head      node;
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
xpmem_send_cmd_link(struct xpmem_ns_state * state,
                    xpmem_link_t            link, 
                    struct xpmem_cmd_ex   * cmd)
{
    struct xpmem_link_connection * conn = NULL;

    conn = (struct xpmem_link_connection *)
        htable_search(state->link_map, (uintptr_t)link);

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

static xpmem_domid_t
alloc_xpmem_domid(struct xpmem_ns_state * state)
{
    xpmem_domid_t domid = state->uniq_domid;
    state->uniq_domid++;
    return domid;
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

    switch (cmd->type) {
        case XPMEM_DOMID_REQUEST: {
            /* A domid is requested by someone downstream from us on 'link' */
            out_cmd->domid_req.domid = alloc_xpmem_domid(state);

            /* Update domid map */
            {
                int ret = 0;

                ret = htable_insert(state->domid_map,
                        (uintptr_t)out_cmd->domid_req.domid,
                        (uintptr_t)link);

                if (ret == 0) {
                    printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                    out_cmd->domid_req.domid = -1;
                    goto out_domid_req;
                }
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


static int
alloc_xpmem_segid(struct xpmem_ns_state * state, xpmem_segid_t * segid)
{
    struct xpmem_id * id   = NULL;
    int32_t           uniq = 0;

    uniq = state->uniq_segid;

    if (uniq > XPMEM_MAX_UNIQ_SEGID) {
        return -1;
    }

    state->uniq_segid++;

    id       = (struct xpmem_id *)segid;
    id->uniq = (unsigned short)(uniq * XPMEM_MAX_UNIQ_APID);

    return 0;
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
            ret = htable_insert(state->segid_map, 
                    (uintptr_t)cmd->make.segid, 
                    (uintptr_t)cmd->src_dom);

            if (ret == 0) {
                printk(KERN_ERR "XPMEM: cannot insert into segid hashtable\n");
                out_cmd->make.segid = -1;
                goto out_make;
            }


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
            domid = (xpmem_domid_t)htable_remove(state->segid_map, 
                    (uintptr_t)cmd->remove.segid, 
                    0);

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
            domid = (xpmem_domid_t)htable_search(state->segid_map, 
                    (uintptr_t)cmd->get.segid);

            if (domid == 0) {
                printk(KERN_ERR "XPMEM: cannot find segid %lli in hashtable\n",
                    cmd->get.segid);
                goto err_get;
            }

            out_link = (xpmem_link_t)htable_search(state->domid_map,
                    (uintptr_t)domid);

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

                domid = (xpmem_domid_t)htable_search(state->segid_map,
                        (uintptr_t)*((xpmem_segid_t *)&search_id));

                if (domid == 0) {
                    printk(KERN_ERR "XPMEM: cannot find apid %lli in hashtable\n",
                        cmd->release.apid);
                    goto err_release;
                }

                out_link = (xpmem_link_t)htable_search(state->domid_map,
                        (uintptr_t)domid);

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

                domid = (xpmem_domid_t)htable_search(state->segid_map,
                        (uintptr_t)*((xpmem_segid_t *)&search_id));

                if (domid == 0) {
                    printk(KERN_ERR "XPMEM: cannot find apid %lli in hashtable\n",
                        cmd->attach.apid);
                    goto err_attach;
                }

                out_link = (xpmem_link_t)htable_search(state->domid_map,
                        (uintptr_t)domid);

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
            /* Ignore detaches for now */
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
            out_link = (xpmem_link_t)htable_search(state->domid_map,
                    (uintptr_t)cmd->dst_dom);

            if (out_link == 0) {
                printk(KERN_ERR "XPMEM: cannot find domid %lli in hashtable."
                    " This should be impossible\n", cmd->dst_dom);
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
    if (xpmem_send_cmd_link(state, out_link, out_cmd)) {
        printk(KERN_ERR "XPMEM: cannot send command on link %lli\n", link);
    }

}


/*
 * This is the kernel thread implementing the name service
 */
static int
xpmem_ns_thread_fn(void * arg)
{
    struct xpmem_ns_state * state = (struct xpmem_ns_state *)arg;

    while (1) {
        unsigned long flags;
        
        printk("XPMEM name server\n");

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
         */

        printk("XPMEM: ns about to sleep\n");
        mb();
        wait_event_interruptible(state->ns_waitq,
            ( (state->ping_issued  == 1) || 
              (state->domid_issued == 1) ||
              (state->cmd_issued   == 1)
            )
        );
        printk("XPMEM: ns awake!\n");
        

        if (state->ping_issued) {
            struct xpmem_cmd_ex_iter * iter = NULL;

            spin_lock_irqsave(&(state->lock), flags);
            {
                iter = list_first_entry(&(state->ping_list), struct xpmem_cmd_ex_iter, node);
                list_del(&(iter->node));
            }
            spin_unlock_irqrestore(&(state->lock), flags);

            xpmem_ns_process_ping(state, iter->link, iter->cmd);

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

            xpmem_ns_process_domid(state, iter->link, iter->cmd);

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

            xpmem_ns_process_cmd(state, iter->link, iter->cmd);

            kfree(iter->cmd);
            kfree(iter);
        }
    }

    return 0;
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
        unsigned long                  flags = 0;
        int                            error = 0;

        if (type == XPMEM_CONN_LOCAL) {
            state->local_link = link;

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
    struct xpmem_ns_state *   state = part->ns_state;
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
        printk("XPMEM: command copied to ping list\n");
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
        printk("XPMEM: command copied to domid list\n");
        spin_lock_irqsave(&(state->lock), flags);
        {
            list_add_tail(&(iter->node), &(state->domid_list));
            state->domid_issued = 1;
        }
        spin_unlock_irqrestore(&(state->lock), flags);
    } else {
        printk("XPMEM: command copied to cmd list\n");
        spin_lock_irqsave(&(state->lock), flags);
        {
            list_add_tail(&(iter->node), &(state->cmd_list));
            state->cmd_issued = 1;
        }
        spin_unlock_irqrestore(&(state->lock), flags);
    }


    mb();
    wake_up_interruptible(&(state->ns_waitq));

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
    INIT_LIST_HEAD(&(state->ping_list));
    INIT_LIST_HEAD(&(state->domid_list));
    INIT_LIST_HEAD(&(state->cmd_list));

    spin_lock_init(&(state->lock));
    atomic_set(&(state->uniq_link), 0);
    init_waitqueue_head(&(state->ns_waitq));

    state->ping_issued  = 0;
    state->domid_issued = 0;
    state->cmd_issued   = 0;

    /* Name server gets a well-known domid */
    state->domid        = XPMEM_NS_DOMID;
    state->uniq_segid   = MIN_UNIQ_SEGID;
    state->uniq_domid   = MIN_UNIQ_DOMID;

    /* Create kernel thread */
    state->ns_thread = kthread_create(xpmem_ns_thread_fn, state, "kxpmem-ns");
    if (!state->ns_thread) {
        free_htable(state->domid_map, 0, 0);
        free_htable(state->link_map, 1, 0);
        free_htable(state->segid_map, 0, 0);
        kfree(state);
        return -1;
    }

    /* Start kernel thread */
    wake_up_process(state->ns_thread);

    part->ns_state = state;

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

    /* Free kernel threads */
    kthread_stop(state->ns_thread);

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

    kfree(state);
    part->ns_state = NULL;

    return 0;
}
