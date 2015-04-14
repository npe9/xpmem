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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
void (*linux_handle_edge_irq)(unsigned int, struct irq_desc *);
struct irq_desc * (*linux_irq_to_desc)(unsigned int);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
void (*linux_tlb_gather_mmu)(struct mmu_gather *, struct mm_struct *, bool);
#else
void (*linux_tlb_gather_mmu)(struct mmu_gather *, struct mm_struct *, 
            unsigned long, unsigned long);
#endif
void (*linux_tlb_flush_mmu)(struct mmu_gather *);
void (*linux_tlb_finish_mmu)(struct mmu_gather *, unsigned long, unsigned long);


int
xpmem_linux_symbol_init(void)
{
    unsigned long symbol_addr = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
    /* Symbol:
     *  --  handle_edge_irq
     */
    {   
        symbol_addr = kallsyms_lookup_name("handle_edge_irq");
    
        if (symbol_addr == 0) {
            printk(KERN_WARNING "Linux symbol handle_edge_irq not found.\n");
            return -1; 
        }

        linux_handle_edge_irq = (void (*)(unsigned int, struct irq_desc *))symbol_addr;
    }   

    /* Symbol:
     *
     *  --  irq_to_desc
     */
    {   
        symbol_addr = kallsyms_lookup_name("irq_to_desc");
    
        if (symbol_addr == 0) {
            printk(KERN_WARNING "Linux symbol irq_to_desc not found.\n");
            return -1; 
        }

        linux_irq_to_desc = (struct irq_desc * (*)(unsigned int))symbol_addr;
    }   
#endif

    /* Symbol:
     *  --  tlb_gather_mmu
     */
    {   
        symbol_addr = kallsyms_lookup_name("tlb_gather_mmu");
    
        if (symbol_addr == 0) {
            printk(KERN_WARNING "Linux symbol tlb_gather_mmu not found.\n");
            return -1; 
        }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
        linux_tlb_gather_mmu = 
            (void (*)(struct mmu_gather *, struct mm_struct *, bool))
        symbol_addr;
#else
        linux_tlb_gather_mmu = 
            (void (*)(struct mmu_gather *, struct mm_struct *,
            unsigned long, unsigned long))
        symbol_addr;
#endif
    }   

    /* Symbol:
     *  --  tlb_flush_mmu
     */
    {   
        symbol_addr = kallsyms_lookup_name("tlb_flush_mmu");
    
        if (symbol_addr == 0) {
            printk(KERN_WARNING "Linux symbol tlb_flush_mmu not found.\n");
            return -1; 
        }

        linux_tlb_flush_mmu = (void (*)(struct mmu_gather *))symbol_addr;
    }   

    /* Symbol:
     *  --  tlb_finish_mmu
     */
    {   
        symbol_addr = kallsyms_lookup_name("tlb_finish_mmu");
    
        if (symbol_addr == 0) {
            printk(KERN_WARNING "Linux symbol tlb_finish_mmu not found.\n");
            return -1; 
        }

        linux_tlb_finish_mmu = 
            (void (*)(struct mmu_gather *, unsigned long, unsigned long))
        symbol_addr;
    }

    return 0;
}
