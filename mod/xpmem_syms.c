/*
 * XPMEM extensions for multiple domain support.
 *
 * xpmem_syms.c: Lookup Linux kernel symbols needed for module functionality
 *
 * Author: Brian Kocoloski <briankoco@cs.pitt.edu>
 *
 */


#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>

#include <xpmem_private.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
int  (*linux_create_irq) (void);
void (*linux_destroy_irq)(unsigned int);
#endif


int
xpmem_linux_symbol_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
    unsigned long symbol_addr = 0;

    /* Symbol:
     *  --  create_irq
     */
    {   
        symbol_addr = kallsyms_lookup_name("create_irq");
    
        if (symbol_addr == 0) {
            printk(KERN_WARNING "Linux symbol create_irq not found.\n");
            return -1; 
        }

        linux_create_irq = (int (*)(void))symbol_addr;
    }   

    /* Symbol:
     *  --  destroy_irq
     */
    {   
        symbol_addr = kallsyms_lookup_name("destroy_irq");
    
        if (symbol_addr == 0) {
            printk(KERN_WARNING "Linux symbol destroy_irq not found.\n");
            return -1; 
        }

        linux_destroy_irq = (void (*)(unsigned int))symbol_addr;
    }   
#endif

    return 0;
}
