/*
 * silkhook - miniature arm hooking lib
 * hide.h   - trivial process/module hiding
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_HIDE_H_
#define _SILKHOOK_HIDE_H_

#include <linux/module.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * hide state
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_hidden_mod
{
    struct list_head *prev;
    struct list_head *next;
    struct module    *mod;
    int              hidden;
};


/* ─────────────────────────────────────────────────────────────────────────────
 * hide API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__hide_mod(struct module *mod, struct silkhook_hidden_mod *state);
int silkhook__unhide_mod(struct silkhook_hidden_mod *state);


#endif /* _SILKHOOK_HIDE_H_ */
