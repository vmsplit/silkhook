/*
 * silkhook  - miniature arm hooking lib
 * pgtable.c - page tbl manipulation
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

#include "pgtable.h"
#include "ksyms.h"
#include "../../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * resolved syms
 * ───────────────────────────────────────────────────────────────────────────── */

static int (*__set_memory_rw)(unsigned long, int);
static int (*__set_memory_ro)(unsigned long, int);
static int (*__set_memory_nx)(unsigned long, int);
static int (*__set_memory_x) (unsigned long, int);
static struct mm_struct *__init_mm;

static int __resolve_pgtable_syms(void)
{
	if (!__set_memory_rw)
	{
		__set_memory_rw = silkhook_ksym("set_memory_rw");
		__set_memory_ro = silkhook_ksym("set_memory_ro");
		__set_memory_nx = silkhook_ksym("set_memory_nx");
		__set_memory_x  = silkhook_ksym("set_memory_x");
		__init_mm       = silkhook_ksym("init_mm");
	}
	return (__set_memory_rw && __set_memory_ro &&
		    __set_memory_nx && __set_memory_x  && __init_mm) ? 0 : -ENOENT;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * pt walk
 *
 * 64-bit (4l):   PGD -> PUD -> PMD -> PTE
 * 32-bit (3/2l): PGD -> PMD -> PTE
 * ───────────────────────────────────────────────────────────────────────────── */

pte_t *silkhook__virt_to_pte(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (__resolve_pgtable_syms())
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
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte || pte_none(*pte))
		return NULL;

	return pte;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * permission manipulation
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__set_page_rw(unsigned long addr)
{
	if (__resolve_pgtable_syms())
		return SILKHOOK_ERR_PROT;

	return __set_memory_rw(addr & PAGE_MASK, 1) ?  SILKHOOK_ERR_PROT : SILKHOOK_OK;
}

int silkhook__set_page_ro(unsigned long addr)
{
	if (__resolve_pgtable_syms())
		return SILKHOOK_ERR_PROT;

	return __set_memory_ro(addr & PAGE_MASK, 1) ? SILKHOOK_ERR_PROT : SILKHOOK_OK;
}

int silkhook__set_page_nx(unsigned long addr)
{
	if (__resolve_pgtable_syms())
		return SILKHOOK_ERR_PROT;

	return __set_memory_nx(addr & PAGE_MASK, 1) ?  SILKHOOK_ERR_PROT : SILKHOOK_OK;
}

int silkhook__set_page_x(unsigned long addr)
{
	if (__resolve_pgtable_syms())
		return SILKHOOK_ERR_PROT;

	return __set_memory_x(addr & PAGE_MASK, 1) ?  SILKHOOK_ERR_PROT : SILKHOOK_OK;
}
