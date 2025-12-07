/*
 * silkhook  - miniature arm hooking lib
 * shadow.h  - shadow syscall tbl
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_SHADOW_H_
#define _SILKHOOK_SHADOW_H_

#include <linux/types.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * shadow table context
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_shadow_tbl {
	void		**orig;
	void		**shadow;
	size_t		nr_syscalls;
};


/* ─────────────────────────────────────────────────────────────────────────────
 * shadow table API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__shadow_create(struct silkhook_shadow_tbl *tbl);
int silkhook__shadow_destroy(struct silkhook_shadow_tbl *tbl);
int silkhook__shadow_hook(struct silkhook_shadow_tbl *tbl, unsigned int nr,
			             void *detour, void **orig);
int silkhook__shadow_unhook(struct silkhook_shadow_tbl *tbl, unsigned int nr);


#endif /* _SILKHOOK_SHADOW_H_ */
