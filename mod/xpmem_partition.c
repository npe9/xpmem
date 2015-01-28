/*
 * XPMEM extensions for multiple domain support
 *
 * xpmem_partition.c: Common functionality for the name and forwarding services
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 */

#include <linux/kref.h>

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

static int  get_conn(struct xpmem_link_connection * conn);
static void put_conn(struct xpmem_link_connection * conn);

struct xpmem_link_connection *
xpmem_get_link_conn(struct xpmem_partition_state * state,
                    xpmem_link_t                   link)
{
    struct xpmem_link_connection * conn = &(state->conn_map[link]);

    if (get_conn(conn))
        return conn;

    return NULL;
}

void
xpmem_put_link_conn(struct xpmem_partition_state * state,
                    xpmem_link_t                   link)
{
    struct xpmem_link_connection * conn = &(state->conn_map[link]);

    put_conn(conn);
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
        case XPMEM_DOMID_RELEASE:
            return "XPMEM_DOMID_RELEASE";
        default:
            return "UNKNOWN OPERATION";
    }
}

/* Send a command through a connection link */
int
xpmem_send_cmd_link(struct xpmem_partition_state * state,
                    xpmem_link_t                   link,
                    struct xpmem_cmd_ex          * cmd)
{
    struct xpmem_link_connection * conn  = NULL;    
    int                            ret   = 0;

    conn = xpmem_get_link_conn(state, link);
    if (conn == NULL) 
        return -1;

    DBUG_ON(conn->in_cmd_fn == NULL);

    ret = conn->in_cmd_fn(cmd, conn->priv_data);

    put_conn(conn);

    return ret;
}

void
xpmem_add_domid_link(struct xpmem_partition_state * state,
                     xpmem_domid_t                  domid,
                     xpmem_link_t                   link)
{
    spin_lock(&(state->lock));
    {
        state->link_map[domid] = link;
    }
    spin_unlock(&(state->lock));
}

xpmem_link_t
xpmem_get_domid_link(struct xpmem_partition_state * state,
                     xpmem_domid_t                  domid)
{
    xpmem_link_t link;

    spin_lock(&(state->lock));
    {
        link = state->link_map[domid];
    }
    spin_unlock(&(state->lock));

    return link;
}

void
xpmem_remove_domid_link(struct xpmem_partition_state * state,
                        xpmem_domid_t                  domid)
{
    spin_lock(&(state->lock));
    {
        state->link_map[domid] = 0;
    }
    spin_unlock(&(state->lock));
}



struct xpmem_partition_state *
xpmem_get_partition(void)
{
    extern struct xpmem_partition * xpmem_my_part;
    struct xpmem_partition_state  * part_state = &(xpmem_my_part->part_state);

    return part_state;
}

EXPORT_SYMBOL(xpmem_get_partition);



static xpmem_link_t
xpmem_get_free_link(struct xpmem_partition_state * state,
                    xpmem_connection_t             type)
{
    xpmem_link_t i, ret = 0;

    spin_lock(&(state->lock));
    {
        for (i = 1; i < XPMEM_MAX_LINK; i++) {
            struct xpmem_link_connection * conn = &(state->conn_map[i]);
            if (conn->conn_type == XPMEM_CONN_NONE) {
                conn->conn_type = type;
                ret = i;
                break;
            }
        }
    }
    spin_unlock(&(state->lock));

    return ret;
}

xpmem_link_t
xpmem_add_connection(struct xpmem_partition_state * part_state,
                     xpmem_connection_t             type,
                     int (*in_cmd_fn)(struct xpmem_cmd_ex * cmd, void * priv_data),
                     int (*in_irq_fn)(int                   irq, void * priv_data),
                     void                         * priv_data)
{
    struct xpmem_link_connection * conn  = NULL;
    xpmem_link_t                   link  = 0;

    if ((type != XPMEM_CONN_LOCAL) &&
        (type != XPMEM_CONN_REMOTE))
    {
        return -EINVAL;
    }

    link = xpmem_get_free_link(part_state, type);
    if (link < 0) {
        return -EBUSY;
    }

    if (type == XPMEM_CONN_LOCAL) {
        part_state->local_link = link;

        /* Associate the link with our domid, if we have one */
        if (part_state->domid > 0) {
            xpmem_add_domid_link(part_state, part_state->domid, link);
        }
    }

    /* Grab conn from the link map */
    conn = &(part_state->conn_map[link]);
    conn->state     = part_state;
    conn->link      = link;
    conn->conn_type = type;
    conn->in_cmd_fn = in_cmd_fn;
    conn->in_irq_fn = in_irq_fn;
    conn->priv_data = priv_data;
    kref_init(&(conn->refcnt));

    return link;
}

EXPORT_SYMBOL(xpmem_add_connection);


void
xpmem_remove_connection(struct xpmem_partition_state * part_state,
                        xpmem_link_t                   link)
{
    struct xpmem_link_connection * conn = &(part_state->conn_map[link]);
    put_conn(conn);
}

EXPORT_SYMBOL(xpmem_remove_connection);


int
xpmem_cmd_deliver(struct xpmem_partition_state * part_state,
                  xpmem_link_t                   link,
                  struct xpmem_cmd_ex          * cmd)
{
    int ret = 0;

    if (part_state->is_nameserver) {
        ret = xpmem_ns_deliver_cmd(part_state, link, cmd);
    } else {
        ret = xpmem_fwd_deliver_cmd(part_state, link, cmd);
    }

    return ret;
}

EXPORT_SYMBOL(xpmem_cmd_deliver);


static irqreturn_t
xpmem_irq_callback(int    irq,
                   void * priv_data)
{
    struct xpmem_link_connection * conn = (struct xpmem_link_connection *)priv_data;

    if (conn->in_irq_fn == NULL) {
        return IRQ_NONE;
    } 
    
    conn->in_irq_fn(irq, conn->priv_data);

    return IRQ_HANDLED;
}


int
xpmem_request_irq_link(struct xpmem_partition_state * part_state,
                       xpmem_link_t                   link)
{
    struct xpmem_link_connection * conn = NULL;
    int                            irq  = 0;

    conn = xpmem_get_link_conn(part_state, link);
    if (conn == NULL)
        return -1;

    DBUG_ON(conn->in_irq_fn == NULL);

    irq = xpmem_request_irq(part_state, xpmem_irq_callback, conn);

    /* If we got an irq, we don't put the conn until the irq is free'd */
    if (irq <= 0) {
        put_conn(conn);
    }

    return irq;
}

EXPORT_SYMBOL(xpmem_request_irq_link);


int
xpmem_release_irq_link(struct xpmem_partition_state * part_state,
                       xpmem_link_t                   link,
                       int                            irq)
{
    struct xpmem_link_connection * conn = xpmem_get_link_conn(part_state, link);
    int                            ret  = 0;

    conn = xpmem_get_link_conn(part_state, link);
    if (conn == NULL)
        return -1;

    DBUG_ON(conn->in_irq_fn == NULL);

    ret = xpmem_release_irq(part_state, irq, conn);
    if (ret == 0) {
        /* put the reference in the irq handler that we just free'd */
        put_conn(conn);
    }

    /* put this function's ref */
    put_conn(conn);

    return ret;
}

EXPORT_SYMBOL(xpmem_release_irq_link);


int
xpmem_irq_deliver(struct xpmem_partition_state * part_state,
                  xpmem_domid_t                  domid,
                  xpmem_sigid_t                  sigid)
{
    struct xpmem_link_connection * conn = NULL;
    struct xpmem_signal          * sig  = (struct xpmem_signal *)&sigid;
    xpmem_link_t                   link = xpmem_get_domid_link(part_state, domid);
    int                            ret  = 0;

    /* If we do not have a local link for this domid, send an IPI */
    if (link == 0) {
        xpmem_send_ipi_to_apic(sig->apic_id, sig->vector);
        return 0;
    }

    conn = xpmem_get_link_conn(part_state, link);
    if (conn == NULL)
        return -1;

    DBUG_ON(conn->in_irq_fn == NULL);

    ret = conn->in_irq_fn(sig->irq, conn->priv_data);

    put_conn(conn);
    
    return ret;
}

EXPORT_SYMBOL(xpmem_irq_deliver);


int
xpmem_partition_init(struct xpmem_partition_state * state, int is_ns)
{
    int status = 0;

    memset(state, 0, sizeof(struct xpmem_partition_state));

    state->local_link    = -1; 
    state->domid         = -1; 
    state->is_nameserver = is_ns;

    spin_lock_init(&(state->lock));

    /* Create ns/fwd state */
    if (is_ns) {
        status = xpmem_ns_init(state);
        if (status != 0) {
            XPMEM_ERR("Could not initialize name service");
            return status;
        }
    } else {
        status = xpmem_fwd_init(state);
        if (status != 0) {
            XPMEM_ERR("Could not initialize forwarding service");
            return status;
        }
    }

    /* Bring up palacios device driver / host OS interface */
    status = xpmem_palacios_init(state);
    if (status != 0) {
        XPMEM_ERR("Could not initialize Palacios XPMEM state");
        goto err_palacios;
    }

    /* Register a local domain */
    status = xpmem_domain_init(state);
    if (status != 0) {
        XPMEM_ERR("Could not initialize local domain XPMEM state");
        goto err_domain;
    }

    return 0;

err_domain:
    xpmem_palacios_deinit(state);

err_palacios:
    if (is_ns) {
        xpmem_ns_deinit(state);
    } else {
        xpmem_fwd_deinit(state);
    }

    return status;
}


int
xpmem_partition_deinit(struct xpmem_partition_state * state)
{
    xpmem_domain_deinit(state);
    xpmem_palacios_deinit(state);

    if (state->is_nameserver) {
        xpmem_ns_deinit(state);
    } else {
        xpmem_fwd_deinit(state);
    }
 
    return 0;
}

static int
get_conn(struct xpmem_link_connection * conn)
{
    return kref_get_unless_zero(&(conn->refcnt));
}

static void
put_conn_last(struct kref * kref)
{
    struct xpmem_link_connection * conn  = container_of(kref, struct xpmem_link_connection, refcnt);
    struct xpmem_partition_state * state = conn->state;

    /* Need to do two things:
     * (1) Remove all domains using this connection link in the link map 
     * (2) Set the conn to CONN_NONE in the conn map
     */
    spin_lock(&(state->lock));
    {
        int i;
        for (i = 0; i < XPMEM_MAX_DOMID; i++) {
            xpmem_link_t link = state->link_map[i];
            if (link == conn->link) {
                /* Update name server map */
                if (state->is_nameserver) {
                    xpmem_ns_kill_domain(state, i); 
                }

                state->link_map[i] = 0;
            }
        }
    }
    spin_unlock(&(state->lock));

    conn->conn_type = XPMEM_CONN_NONE;
}

static void
put_conn(struct xpmem_link_connection * conn)
{
    kref_put(&(conn->refcnt), put_conn_last);
}
