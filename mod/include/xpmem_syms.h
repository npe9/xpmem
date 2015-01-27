/*
 * XPMEM extensions for multiple domain support
 *
 * xpmem_syms.h: Linux kernel symbols needed for module functionality
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */

#ifndef _XPMEM_SYMS_H
#define _XPMEM_SYMS_H


int xpmem_linux_symbol_init(void);

extern int  (*linux_create_irq) (void);
extern void (*linux_destroy_irq)(unsigned int);

#endif /* _XPMEM_SYMS_H */
