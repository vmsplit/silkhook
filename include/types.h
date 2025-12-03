/*
 * silkhook - miniature arm64 hooking lib
 * types.h  - core type definitions
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _TYPES_H_
#define _TYPES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * constants
 *
 * hook sequence (16 bytes):
 *   ldr x16, [pc, #8]    <- load addr from literal pool
 *   br  x16              <- branch to detour
 *   <addr_lo>            ┐
 *   <addr_hi>            ┴─ 64-bit absolute address
 * ───────────────────────────────────────────────────────────────────────────── */

#define INSTR_SIZE          4u
#define HOOK_INSTR_COUNT    4u
#define HOOK_SIZE           (INSTR_SIZE * HOOK_INSTR_COUNT)
#define TRAMPOLINE_MAX      64u


/* ─────────────────────────────────────────────────────────────────────────────
 * hook context
 *
 *       targ ──────> detour ──────> trampoline ──────> targ+16
 *        │                              │
 *        └──────────────────────────────┘
 *                  (call orig)
 * ───────────────────────────────────────────────────────────────────────────── */

struct hook {
    uintptr_t   targ;
    uintptr_t   detour;
    uintptr_t   trampoline;

    uint32_t    orig_instrs[HOOK_INSTR_COUNT];
    size_t      orig_size;

    bool        active;
    struct hook *next;
};


/* ─────────────────────────────────────────────────────────────────────────────
 * hook descriptor
 *
 *      struct hook_desc descs[] = {
 *          { func_a, detour_a, NULL },
 *          { func_b, dotour_b, NULL },
 *      };
 *      hook_batch(descs, 2, hooks);
 * ───────────────────────────────────────────────────────────────────────────── */

struct hook_desc {
    void *targ;
    void *detour;
    void **orig;
};


#endif /* _TYPES_H_ */
