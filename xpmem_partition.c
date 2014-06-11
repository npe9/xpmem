/*
 * XPMEM extensions for multiple domain support
 *
 * xpmem_partition.c: Common functionality for name and forwarding partitions
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 */

#include <xpmem_partition.h>
#include <xpmem_private.h>
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

u32
xpmem_hash_fn(uintptr_t key) 
{
    return hash_long(key);
}

int
xpmem_eq_fn(uintptr_t key1, uintptr_t key2)
{
    return (key1 == key2);
}

char *
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


xpmem_link_t
alloc_xpmem_link(struct xpmem_partition_state * state)
{
    xpmem_link_t id = (xpmem_link_t)atomic_inc_return(&(state->uniq_link));

    if (id > XPMEM_MAX_LINK_ID) {
        return -1;
    }

    return id;
}


int
xpmem_add_domid(struct xpmem_partition_state * state,
                xpmem_domid_t                  domid,
                xpmem_link_t                   link)
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

static xpmem_link_t
xpmem_search_or_remove_domid(struct xpmem_partition_state * state,
                             xpmem_domid_t                  domid,
                             int                            remove)
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

xpmem_link_t
xpmem_search_domid(struct xpmem_partition_state * state,
                  xpmem_link_t                    link)
{
    return xpmem_search_or_remove_domid(state, link, 0);
}

xpmem_link_t
xpmem_remove_domid(struct xpmem_partition_state * state,
                  xpmem_link_t                    link)
{
    return xpmem_search_or_remove_domid(state, link, 1);
}



int
xpmem_add_link(struct xpmem_partition_state * state,
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

static struct xpmem_link_connection *
xpmem_search_or_remove_link(struct xpmem_partition_state * state,
                            xpmem_link_t                   link,
                            int                            remove)
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

struct xpmem_link_connection *
xpmem_search_link(struct xpmem_partition_state * state,
                  xpmem_link_t                   link)
{
    return xpmem_search_or_remove_link(state, link, 0);
}

struct xpmem_link_connection *
xpmem_remove_link(struct xpmem_partition_state * state,
                  xpmem_link_t                   link)
{
    return xpmem_search_or_remove_link(state, link, 1);
}



/* Send a command along a connection link */
int
xpmem_send_cmd_link(struct xpmem_partition_state * state,
                    xpmem_link_t                   link,
                    struct xpmem_cmd_ex          * cmd)
{
    struct xpmem_link_connection * conn = xpmem_search_link(state, link);

    if (conn == NULL) {
        return -1;
    }

    return conn->in_cmd_fn(cmd, conn->priv_data);
}



int
xpmem_partition_init(struct xpmem_partition_state * state, int is_ns)
{
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
    spin_lock_init(&(state->lock));
    atomic_set(&(state->uniq_link), 0); 

    state->local_link   = -1; 
    state->domid        = -1; 

    /* TODO: init palacios */
    /* TODO: init local domain */
    /* TODO: init fwd OR ns */

    state->initialized  = 1;
    return 0;

}


int
xpmem_partition_deinit(struct xpmem_partition_state * state)
{
    /* Free hashtables */
    free_htable(state->domid_map, 0, 0);
    free_htable(state->link_map, 1, 0);

    /* TODO: deinit palacios */
    /* TODO: deinit local domain */
    /* TODO: init fwd OR ns */

    state->initialized = 0;

    return 0;
}


struct xpmem_partition_state *
xpmem_get_partition(void)
{
    extern struct xpmem_partition * xpmem_my_part;
    return &(xpmem_my_part->part_state);
}

EXPORT_SYMBOL(xpmem_get_partition);


xpmem_link_t
xpmem_add_connection(struct xpmem_partition_state * part_state,
                     xpmem_connection_t             type,
                     int (*in_cmd_fn)(struct xpmem_cmd_ex * cmd, void * priv_data),
                     void                         * priv_data)
{
    xpmem_link_t link = 0;

    if (!part_state || !part_state->initialized) {
        return -1;
    }

    link = alloc_xpmem_link(part_state);

    if (link > 0) {
        struct xpmem_link_connection * conn  = NULL;

        if (type == XPMEM_CONN_LOCAL) {
            part_state->local_link = link;

            /* Associate the link with our domid, if we have one */
            if (part_state->domid > 0) {
                if (xpmem_add_domid(part_state, part_state->domid, part_state->local_link) == 0) {
                    printk(KERN_ERR "XPMEM: cannot insert into domid hashtable\n");
                    return -1;
                }
            }

            conn = kmalloc(sizeof(struct xpmem_link_connection), GFP_KERNEL);
            if (!conn) {
                printk(KERN_ERR "XPMEM: out of memory\n");
                return -1;
            }

            conn->conn_type = type;
            conn->in_cmd_fn = in_cmd_fn;
            conn->priv_data = priv_data;

            /* Update the link map */
            if (xpmem_add_link(part_state, link, conn) == 0) {
                printk(KERN_ERR "XPMEM: cannot insert into link hashtable\n");
                kfree(conn);
                return -1;
            }
        }
    }

    return link;
}

EXPORT_SYMBOL(xpmem_add_connection);


int
xpmem_remove_connection(struct xpmem_partition_state * part_state,
                        xpmem_link_t                   link)
{
    struct xpmem_link_connection * conn  = NULL;

    conn = xpmem_remove_link(part_state, link);

    if (!conn) {
        return -1; 
    }   

    if (conn->conn_type == XPMEM_CONN_LOCAL) {
        part_state->local_link = -1; 
    }   

    kfree(conn);

    return 0;
}

EXPORT_SYMBOL(xpmem_remove_connection);




int
xpmem_cmd_deliver(struct xpmem_partition_state * part_state,
                  xpmem_link_t                   link,
                  struct xpmem_cmd_ex          * cmd)
{
    if (!part_state || !part_state->initialized) {
        return -1;
    }

    if (part_state->is_nameserver) {
        return xpmem_ns_deliver_cmd(part_state, link, cmd);
    } else {
        return xpmem_fwd_deliver_cmd(part_state, link, cmd);
    }
}

EXPORT_SYMBOL(xpmem_cmd_deliver);
