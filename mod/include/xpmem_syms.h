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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
extern int  (*linux_create_irq) (void);
extern void (*linux_destroy_irq)(unsigned int);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
extern unsigned long (*linux_do_mmap_pgoff)(
        struct file *,
        unsigned long,
        unsigned long,
        unsigned long,
        unsigned long,
        unsigned long);
#else
extern unsigned long (*linux_do_mmap_pgoff)(
        struct file *,
        unsigned long,
        unsigned long,
        unsigned long,
        unsigned long,
        unsigned long,
        unsigned long *);
#endif
extern int (*linux_do_munmap)(
        struct mm_struct *,
        unsigned long,
        size_t);
#endif


#endif /* _XPMEM_SYMS_H */
