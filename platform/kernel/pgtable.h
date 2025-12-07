/*
 * silkhook  - miniature arm hooking lib
 * pgtable.h - page tbl manipulation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_PGTABLE_H_
#define _SILKHOOK_PGTABLE_H_

#include <linux/types.h>
#include <linux/mm_types.h>
#include <asm/pgtable.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * page table API
 * ───────────────────────────────────────────────────────────────────────────── */

pte_t *silkhook__virt_to_pte(unsigned long addr);
int silkhook__set_page_rw(unsigned long addr);
int silkhook__set_page_ro(unsigned long addr);
int silkhook__set_page_nx(unsigned long addr);
int silkhook__set_page_x (unsigned long addr);


#endif /* _SILKHOOK_PGTABLE_H_ */
