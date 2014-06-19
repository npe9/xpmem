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

#include <xpmem_syms.h>


void (*tlb_finish_mmu_fn)(struct mmu_gather * tlb, unsigned long start, unsigned long end);
void (*tlb_flush_mmu_fn)(struct mmu_gather * tlb, unsigned long start, unsigned long end);
void (*tlb_gather_mmu_fn)(struct mmu_gather * tlb, struct mm_struct *, unsigned long start, unsigned long end);
pte_t * (*huge_pte_offset_fn)(struct mm_struct * mm, unsigned long addr);
void (*zap_page_range_fn)(struct vm_area_struct *, unsigned long, unsigned long, struct zap_details *); 

void tlb_gather_mmu(struct mmu_gather * tlb, 
                    struct mm_struct  * mm,
                    unsigned long       start, 
                    unsigned long       end)
{
    return tlb_gather_mmu_fn(tlb, mm, start, end);
}

void tlb_finish_mmu(struct mmu_gather * tlb, 
                    unsigned long       start, 
                    unsigned long       end)
{
    return tlb_finish_mmu_fn(tlb, start, end);
}

void tlb_flush_mmu(struct mmu_gather * tlb, 
                   unsigned long       start, 
                   unsigned long       end)
{
    return tlb_flush_mmu_fn(tlb, start, end);
}

pte_t * huge_pte_offset(struct mm_struct * mm,
                        unsigned long      addr) 
{
    return huge_pte_offset_fn(mm, addr);
}

void zap_page_range(struct vm_area_struct * vma,
                    unsigned long           start,
                    unsigned long           end, 
                    struct zap_details    * details)
{
    return zap_page_range_fn(vma, start, end, details);
}


//EXPORT_SYMBOL(tlb_gather_mmu);
//EXPORT_SYMBOL(tlb_finish_mmu);
//EXPORT_SYMBOL(tlb_flush_mmu);
//EXPORT_SYMBOL(huge_pte_offset);
//EXPORT_SYMBOL(zap_page_range);



int
xpmem_linux_symbol_init(void)
{
    unsigned long symbol_addr = 0;

    /* Symbol:
     * --  tlb_gather_mmu
     */
    {
        symbol_addr = kallsyms_lookup_name("tlb_gather_mmu");

        if (symbol_addr == 0) {
            printk(KERN_ERR "XPMEM: Linux symbol tlb_gather_mmu not found.\n");
            return -1;
        }

        tlb_gather_mmu_fn = (void (*)(struct mmu_gather *, struct mm_struct *, unsigned long, unsigned long))symbol_addr;
    }


    /* Symbol:
     * --  tlb_finish_mmu
     */
    {
        symbol_addr = kallsyms_lookup_name("tlb_finish_mmu");

        if (symbol_addr == 0) {
            printk(KERN_ERR "XPMEM: Linux symbol tlb_finish_mmu not found.\n");
            return -1;
        }

        tlb_finish_mmu_fn = (void (*)(struct mmu_gather *, unsigned long, unsigned long))symbol_addr;
    }

    /* Symbol:
     * --  tlb_flush_mmu
     */
    {
        symbol_addr = kallsyms_lookup_name("tlb_flush_mmu");

        if (symbol_addr == 0) {
            printk(KERN_ERR "XPMEM: Linux symbol tlb_flush_mmu not found.\n");
            return -1;
        }

        tlb_flush_mmu_fn = (void (*)(struct mmu_gather *, unsigned long, unsigned long))symbol_addr;
    }

    /* Symbol:
     * --  huge_pte_offset
     */
    {
        symbol_addr = kallsyms_lookup_name("huge_pte_offset");

        if (symbol_addr == 0) {
            printk(KERN_ERR "XPMEM: Linux symbol huge_pte_offset not found.\n");
            return -1;
        }

        huge_pte_offset_fn = (pte_t * (*)(struct mm_struct * mm, unsigned long addr))symbol_addr;
    }

    /* Symbol:
     * --  zap_page_range
     */
    {
        symbol_addr = kallsyms_lookup_name("zap_page_range");

        if (symbol_addr == 0) {
            printk(KERN_ERR "XPMEM: Linux symbol zap_page_range not found.\n");
            return -1;
        }

        zap_page_range_fn = (void (*)(struct vm_area_struct *, unsigned long, unsigned long, struct zap_details *))symbol_addr;
    }


    return 0;
}
