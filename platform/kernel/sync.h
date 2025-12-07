/*
 * silkhook - miniature arm hooking lib
 * sync.h   - cross-CPU synchronisation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_SYNC_H_
#define _SILKHOOK_SYNC_H_

#include <linux/types.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * sync context
 *
 * passed to stop_machine callback,  contains everythin needed for atomic patch
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_sync_ctx
{
    void       *dst;
    const void *src;
    size_t     len;
    int        result;
};


/* ─────────────────────────────────────────────────────────────────────────────
 * sync API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_patch_sync(void *dst, const void *src, size_t len);


#endif /* _SILKHOOK_SYNC_H_ */
