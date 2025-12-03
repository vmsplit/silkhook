/*
 * hookie   - miniature arm64 hooking lib
 * hookie.h - public API
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_H_
#define _SILKHOOK_H_

#include "types.h"
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * API
 *
 *   struct hook h;
 *   void *orig;
 *
 *   hook(targ, detour, &h, &orig);
 *   unhook(&h);
 *
 * simple:                    staged:
 *   init()                     init()
 *       │                          │
 *   hook()                     hook_create()
 *       │                          │
 *       │                      hook_install() <──┐
 *       │                          │             │
 *       │                      hook_remove() ────┘
 *       │                          │
 *   unhook()                   hook_destroy()
 *       │                          │
 *   shutdown()                 shutdown()
 * ───────────────────────────────────────────────────────────────────────────── */

int init(void);
void shutdown(void);

int hook_create(void *targ, void *detour, struct hook *h, void **orig);
int hook_install(struct hook *h);
int hook_remove(struct hook *h);
int hook_destroy(struct hook *h);

int hook(void *targ, void *detour, struct hook *h, void **orig);
int unhook(struct hook *h);


/* ─────────────────────────────────────────────────────────────────────────────
 * batch API
 *
 *   struct hook_desc descs[] = {
 *       { (void *) open,  _hooked_open,  &orig_open  },
 *       { (void *) read,  _hooked_read,  &orig_read  },
 *       { (void *) write, _hooked_write, &orig_write },
 *   };
 *   struct hook hooks[3];
 *   hook_batch(descs, 3, hooks);
 *   ...
 *   unhook_batch(hooks, 3);
 * ───────────────────────────────────────────────────────────────────────────── */

int hook_batch(struct hook_desc *descs, size_t count, struct hook *hooks);
int unhook_batch(struct hook *hooks, size_t count);


#ifdef __cplusplus
}
#endif

#endif /* _SILKHOOK_H_ */
