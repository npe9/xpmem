/*
 * XPMEM extensions for multiple domain support
 *
 * Common functionality for name and forwarding partitions
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 */

#ifndef _XPMEM_PARTITION_H
#define _XPMEM_PARTITION_H

#include <xpmem.h>
#include <xpmem_iface.h>
#include <xpmem_extended.h>

#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/kref.h>

#define XPMEM_MAX_LINK  128
#define XPMEM_MIN_DOMID 32
#define XPMEM_MAX_DOMID 128

/* The well-known name server's domid */
#define XPMEM_NS_DOMID    1



struct xpmem_link_connection {
    struct xpmem_partition_state * state;
    xpmem_link_t                   link;
    xpmem_connection_t             conn_type;
    struct kref                    refcnt;
    int (*in_cmd_fn)(struct xpmem_cmd_ex * cmd, void * priv_data);
    int (*in_irq_fn)(int                   irq, void * priv_data);
    void                         * priv_data;
};


struct xpmem_partition_state {
    /* spinlock for state */
    spinlock_t    lock;

    /* link to our own domain */
    xpmem_link_t  local_link;

    /* domid for this partition */
    xpmem_domid_t domid;

    /* table mapping link ids to connection structs */
    struct xpmem_link_connection conn_map[XPMEM_MAX_DOMID];

    /* table mappings domids to link ids */
    xpmem_link_t                 link_map[XPMEM_MAX_LINK];

    /* are we running the nameserver? */
    int is_nameserver; 

    /* this partition's internal state */
    union {
        struct xpmem_ns_state  * ns_state;
        struct xpmem_fwd_state * fwd_state;
    };  

    /* private data */
    void * palacios_priv;
    void * domain_priv;
};


int
xpmem_partition_init(struct xpmem_partition_state * state,
                     int                            is_nameserver);

int
xpmem_partition_deinit(struct xpmem_partition_state * state);

/* Functions used internally by fwd/ns */
char *
cmd_to_string(xpmem_op_t op);

int
xpmem_send_cmd_link(struct xpmem_partition_state * state,
                    xpmem_link_t                   link,
                    struct xpmem_cmd_ex          * cmd);

void
xpmem_add_domid_link(struct xpmem_partition_state * state,
                     xpmem_domid_t                  domid,
                     xpmem_link_t                   link);

xpmem_link_t
xpmem_get_domid_link(struct xpmem_partition_state * state,
                     xpmem_domid_t                  domid);

void
xpmem_remove_domid_link(struct xpmem_partition_state * state,
                        xpmem_domid_t                   domid);

struct xpmem_link_connection *
xpmem_get_link_conn(struct xpmem_partition_state * state,
                    xpmem_link_t                   link);

void
xpmem_put_link_conn(struct xpmem_partition_state * state,
                    xpmem_link_t                   link);

#endif /* _XPMEM_PARTITION_H */
