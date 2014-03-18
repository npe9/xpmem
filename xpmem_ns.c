/*
 * XPMEM extensions for multiple domain support.
 *
 * This file implements XPMEM requests for local processes executing with
 * the NS. 
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/interrupt.h>

#include <xpmem.h>
#include <xpmem_private.h>
#include <xpmem_extended.h>



/* These will pack commands into request structures and write them to the NS
 * command list
 */


static int xpmem_make_ns(xpmem_segid_t * segid_p) {
    return 0;
}

static int xpmem_remove_ns(xpmem_segid_t segid) {
    return 0;
}

static int xpmem_get_ns(xpmem_segid_t segid, int flags, int permit_type, u64 permit_value,
            xpmem_apid_t * apid_p) {
    return 0;
}

static int xpmem_release_ns(xpmem_apid_t apid) {
    return 0;
}

static int xpmem_attach_ns(xpmem_apid_t apid, off_t off, size_t size, u64 * vaddr) {
    return 0;
}

static int xpmem_detach_ns(u64 vaddr) {
    return 0;
}

struct xpmem_extended_ops ns_ops = {
    .make       = xpmem_make_ns,
    .remove     = xpmem_remove_ns,
    .get        = xpmem_get_ns,
    .release    = xpmem_release_ns,
    .attach     = xpmem_attach_ns,
    .detach     = xpmem_detach_ns,
};
