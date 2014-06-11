/*
 * XPMEM extensions for multiple domain support
 *
 * xpmem_iface.h: The interface to the XPMEM name and forwarding services
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */

#ifndef _XPMEM_NS_H
#define _XPMEM_NS_H

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_partition.h>


struct xpmem_partition_state *
xpmem_get_partition(void);
 

xpmem_link_t
xpmem_add_connection(struct xpmem_partition_state * part,
                     xpmem_connection_t             type,
                     int (*in_cmd_fn) (struct xpmem_cmd_ex *, void * priv_data),
                     void                         * priv_data);

int
xpmem_remove_connection(struct xpmem_partition_state * part,
                        xpmem_link_t                   link);

int
xpmem_cmd_deliver(struct xpmem_partition_state * part,
                  xpmem_link_t                   link,
                  struct xpmem_cmd_ex          * cmd);

#endif