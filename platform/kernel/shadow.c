/*
 * silkhook  - miniature arm hooking lib
 * shadow.c  - shadow syscall table
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <asm/unistd.h>

#include "shadow.h"
#include "ksyms.h"
#include "../../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * shadow table creation
 *
 * alloc a copy of sys_call_table to modify
 * orig tbl untouched
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__shadow_create(struct silkhook_shadow_tbl *tbl)
{
	void   **sct;
	size_t tbl_size;

	if (!tbl)
		return SILKHOOK_ERR_INVAL;

	sct = silkhook_ksym("sys_call_table");
	if (!sct)
		return SILKHOOK_ERR_RESOLVE;

	tbl->orig = sct;
	tbl->nr_syscalls = __NR_syscalls;
	tbl_size = sizeof(void *) * tbl->nr_syscalls;

	tbl->shadow = vmalloc(tbl_size);
	if (!tbl->shadow)
		return SILKHOOK_ERR_NOMEM;

	memcpy(tbl->shadow, tbl->orig, tbl_size);

	pr_info("silkhook: shadow tbl @ %px (%zu entries)\n",
		tbl->shadow, tbl->nr_syscalls);

	return SILKHOOK_OK;
}

int silkhook__shadow_destroy(struct silkhook_shadow_tbl *tbl)
{
	if (!tbl)
		return SILKHOOK_ERR_INVAL;

	if (tbl->shadow)
	{
		vfree(tbl->shadow);
		tbl->shadow = NULL;
	}

	return SILKHOOK_OK;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * hook shadow tbl
 *
 * replace entry in shadow tbl only
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__shadow_hook(struct silkhook_shadow_tbl *tbl, unsigned int nr,
			 void *detour, void **orig)
{
	if (!tbl || ! tbl->shadow || !detour)
		return SILKHOOK_ERR_INVAL;

	if (nr >= tbl->nr_syscalls)
		return SILKHOOK_ERR_INVAL;

	if (orig)
		*orig = tbl->shadow[nr];

	tbl->shadow[nr] = detour;

	pr_info("silkhook: shadow hooked syscall %u !!!\n", nr);

	return SILKHOOK_OK;
}

int silkhook__shadow_unhook(struct silkhook_shadow_tbl *tbl, unsigned int nr)
{
	if (!tbl || !tbl->shadow || !tbl->orig)
		return SILKHOOK_ERR_INVAL;

	if (nr >= tbl->nr_syscalls)
		return SILKHOOK_ERR_INVAL;

	tbl->shadow[nr] = tbl->orig[nr];

	return SILKHOOK_OK;
}
