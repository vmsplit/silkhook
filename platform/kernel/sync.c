/*
 * silkhook - miniature arm hooking lib
 * sync.c   - cross-CPU synchronisation
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>

#include "sync.h"
#include "../memory.h"
#include "../../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * stop_machine callb
 *
 * exec with interrupts disabled on all cpus
 * ───────────────────────────────────────────────────────────────────────────── */

static int __silkhook_patch_cb(void *dat)
{
    struct silkhook_sync_ctx *ctx = dat;

    ctx->result = __mem_write_text(ctx->dst, ctx->src, ctx->len);
    if (ctx->result == SILKHOOK_OK)
        flush_icache_range((unsigned long) ctx->dst,
                             (unsigned long) ctx->dst + ctx->len);

    return 0;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_patch_sync(void *dst, const void *src, size_t len)
{
    struct silkhook_sync_ctx ctx = {
        .dst    = dst,
        .src    = src,
        .len    = len,
        .result = SILKHOOK_OK,
    };

    stop_machine(__silkhook_patch_cb, &ctx, NULL);
    return ctx.result;
}
