/*
 * silkhook - miniature arm hooking lib
 * apr.c    - async page remapping
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

#include "apr.h"
#include "ksyms.h"
#include "pgtable.h"
#include "../../include/status.h"


static int __apr_initialised = 0;
static struct mm_struct *__init_mm;


/* ─────────────────────────────────────────────────────────────────────────────
 * pte helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static pte_t *__apr_get_pte(unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    if (!__init_mm)
        return NULL;

    pgd = pgd_offset(__init_mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd))
    {
        pr_err("silkhook: [apr] pmd_none for %lx\n", addr);
        return NULL;
    }

    if (!(pmd_val(*pmd) & 0x2))
    {
        pr_err("silkhook: [apr] %lx uses block mapping,  not PTE!!\n", addr);
        return NULL;
    }


    pte = pte_offset_kernel(pmd, addr);
    if (! pte || pte_none(*pte))
        return NULL;

    return pte;
}

static inline void __apr_flush_tlb(unsigned long addr)
{
    asm volatile(
        "dsb ishst\n"
        "tlbi vmalle1is\n"
        "dsb ish\n"
        "isb\n"
        : : : "memory"
    );
}

static inline void __apr_flush_icache(void *addr, size_t len)
{
    unsigned long start = (unsigned long) addr;
    unsigned long end = start + len;
    unsigned long line;

    for (line = start; line < end; line += 4)
        asm volatile("dc cvau, %0" : : "r"(line) : "memory");
    asm volatile("dsb ish" : : : "memory");

    for (line = start; line < end; line += 4)
        asm volatile("ic ivau, %0" : : "r"(line) : "memory");
    asm volatile("dsb ish\nisb" : : : "memory");
}


/* ─────────────────────────────────────────────────────────────────────────────
 * pte manipulation
 * ───────────────────────────────────────────────────────────────────────────── */

static void __apr_set_pte_pfn(pte_t *ptep, unsigned long pfn)
{
    pte_t old_pte, new_pte;
    pteval_t val;

    old_pte = READ_ONCE(*ptep);
    val = pte_val(old_pte);

    val &= ~PTE_ADDR_MASK;
    val |= (pfn << PAGE_SHIFT) & PTE_ADDR_MASK;

    new_pte = __pte(val);
    set_pte(ptep, new_pte);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * init & exit functs
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__apr_init(void)
{
    if (__apr_initialised)
        return SILKHOOK_OK;

    __init_mm = (struct mm_struct *) silkhook_ksym("init_mm");
    if (!__init_mm)
    {
        pr_err("silkhook: [apr] cannot resolve init_mm\n");
        return SILKHOOK_ERR_RESOLVE;
    }

    __apr_initialised = 1;
    pr_info("silkhook: apr initialised (init_mm @ %px)\n", __init_mm);

    return SILKHOOK_OK;
}

void silkhook__apr_exit(void)
{
    __apr_initialised = 0;
    __init_mm = NULL;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * install & remove functs
 * ───────────────────────────────────────────────────────────────────────────── */

 int silkhook__apr_install(struct silkhook_apr_hook *h, void *targ,
                           void *hook_func, size_t func_len)
 {
     unsigned long targ_addr;
     unsigned long page_offset;
     pte_t *ptep;
     struct page *shadow_page;
     void *shadow_va;

     if (!h || !targ || !hook_func)
         return SILKHOOK_ERR_INVAL;

     if (! __apr_initialised)
         return SILKHOOK_ERR_STATE;

     if (func_len > PAGE_SIZE)
         return SILKHOOK_ERR_INVAL;

     memset(h, 0, sizeof(*h));

     targ_addr = (unsigned long) targ;
     page_offset = targ_addr & ~PAGE_MASK;

     ptep = __apr_get_pte(targ_addr & PAGE_MASK);
     if (!ptep)
     {
         pr_err("silkhook: [apr] cannot find PTE for %px\n", targ);
         return SILKHOOK_ERR_RESOLVE;
     }

     shadow_page = alloc_page(GFP_KERNEL);
     if (!shadow_page)
     {
         pr_err("silkhook: [apr] shadow page alloc failure\n");
         return SILKHOOK_ERR_NOMEM;
     }

     shadow_va = page_address(shadow_page);

     memcpy(shadow_va, (void *)(targ_addr & PAGE_MASK), PAGE_SIZE);
     memcpy(shadow_va + page_offset, hook_func, func_len);
     __apr_flush_icache(shadow_va + page_offset, func_len);

     h->targ = targ;
     h->shadow = shadow_va;
     h->ptep = ptep;
     h->orig_pte = READ_ONCE(*ptep);
     h->pfn_orig = pte_pfn(h->orig_pte);
     h->pfn_hook = page_to_pfn(shadow_page);
     h->orig_phys = h->pfn_orig << PAGE_SHIFT;
     h->hook_phys = h->pfn_hook << PAGE_SHIFT;
     h->active = 0;
     h->installed = 1;

     pr_info("silkhook: apr installed @ %px (orig_pfn=%lx hook_pfn=%lx)\n",
             targ, h->pfn_orig, h->pfn_hook);

     return SILKHOOK_OK;
 }


int silkhook__apr_remove(struct silkhook_apr_hook *h)
{
    struct page *shadow_page;

    if (!h || !h->installed)
        return SILKHOOK_ERR_INVAL;

    if (h->active)
        silkhook__apr_disable(h);

    if (h->shadow)
    {
        shadow_page = virt_to_page(h->shadow);
        __free_page(shadow_page);
    }

    h->installed = 0;
    pr_info("silkhook: apr removed\n");

    return SILKHOOK_OK;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * enable / disable
 * ───────────────────────────────────────────────────────────────────────────── */

void silkhook__apr_enable(struct silkhook_apr_hook *h)
{
    unsigned long addr;

    if (!h || !h->installed || h->active)
        return;

    addr = (unsigned long) h->targ & PAGE_MASK;

    __apr_set_pte_pfn(h->ptep, h->pfn_hook);
    __apr_flush_tlb(addr);

    h->active = 1;
    pr_info("silkhook: [apr] enabled\n");
}

void silkhook__apr_disable(struct silkhook_apr_hook *h)
{
    unsigned long addr;

    if (!h || !h->installed || !h->active)
        return;

    addr = (unsigned long)h->targ & PAGE_MASK;

    __apr_set_pte_pfn(h->ptep, h->pfn_orig);
    __apr_flush_tlb(addr);

    h->active = 0;
    pr_info("silkhook: [apr] disabled\n");
}

int silkhook__apr_is_active(struct silkhook_apr_hook *h)
{
    return h ?  h->active : 0;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * technique:
 *   enable hook,  but DON'T flush TLB
 *   curr cpu keeps execing orig  (cached tlb)
 *   next tlb miss on any cpu -> sees hooked version
 *   after hook runs, it can call apr_disable to revertt
 * ───────────────────────────────────────────────────────────────────────────── */

void silkhook__apr_oneshot(struct silkhook_apr_hook *h)
{
    if (!h || !h->installed || h->active)
        return;

    /*  swap PTE but DON'T flush tlb  */
    __apr_set_pte_pfn(h->ptep, h->pfn_hook);

    /*  no tlb flush!!
     *  cpus with stale tlb: orig
     *  cpus with TLB miss: hooked
     *  creates async activation  */

    h->active = 1;
}
