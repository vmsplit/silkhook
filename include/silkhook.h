/*
 * silkhook   - miniature arm64 hooking lib
 * silkhook.h - public API
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_H_
#define _SILKHOOK_H_

#ifdef __KERNEL__
    #include <linux/types.h>
    #include <linux/stddef.h>
#endif

#include "types.h"
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * lifecycle
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_init(void);
void silkhook_shutdown(void);


/* ─────────────────────────────────────────────────────────────────────────────
 * core hook API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_hook(void *targ, void *detour, struct silkhook_hook *h, void **orig);
int silkhook_unhook(struct silkhook_hook *h);


/* ─────────────────────────────────────────────────────────────────────────────
 * staged API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_create(void *targ, void *detour, struct silkhook_hook *h, void **orig);
int silkhook_enable(struct silkhook_hook *h);
int silkhook_disable(struct silkhook_hook *h);
int silkhook_destroy(struct silkhook_hook *h);


/* ─────────────────────────────────────────────────────────────────────────────
 * batch API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_hook_batch(struct silkhook_desc *descs, size_t n, struct silkhook_hook *hooks);
int silkhook_unhook_batch(struct silkhook_hook *hooks, size_t n);


/* ─────────────────────────────────────────────────────────────────────────────
 * query API
 * ───────────────────────────────────────────────────────────────────────────── */

size_t silkhook_count(void);
int silkhook_unhook_all(void);
struct silkhook_hook *silkhook_find(void *targ);
bool silkhook_is_active(struct silkhook_hook *h);

static inline void *silkhook_get_trampoline(const struct silkhook_hook *h)
{
    return h ?  (void *)h->trampoline : NULL;
}


#ifdef __KERNEL__
/* ─────────────────────────────────────────────────────────────────────────────
 * kernel symbol resolution
 * ───────────────────────────────────────────────────────────────────────────── */

void *silkhook_ksym(const char *name);
void *silkhook_ksym_mod(const char *mod, const char *name);

#endif /* __KERNEL__ */


#ifdef __cplusplus
}
#endif

#endif /* _SILKHOOK_H_ */
