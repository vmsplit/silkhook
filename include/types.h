/*
 * silkhook - miniature arm64 hooking lib
 * types.h  - core type definitions
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_TYPES_H_
#define _SILKHOOK_TYPES_H_

#ifdef __KERNEL__
    #include <linux/types.h>
    #include <linux/stddef.h>
    typedef _Bool bool;
    #define true  1
    #define false 0
#else
    #include <stdint.h>
    #include <stddef.h>
    #include <stdbool.h>
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * constants
 *
 * hook sequence (16 bytes):
 *   ldr x16, [pc, #8]    <- load addr from literal pool
 *   br  x16              <- branch to detour
 *   <addr_low>            ┐
 *   <addr_high>           ┴─ 64-bit absolute addr
 *
 * safe hook sequence (36 bytes):
 *   b       . +8             <- skip ret (for prefetch trick)
 *   ret                      <- never exec'd normally
 *   str     x0, [sp, #-16]!  <- push x0
 *   movz    x0, #...         <- load targ addr
 *   movk    x0, #...
 *   movk    x0, #...
 *   movk    x0, #...
 *   br      x0               <- jump
 *   ldr     x0, [sp], #16    <- pop x0 (exec'd in detour entry)
 *
 * trampoline sizing:
 *      worst case per instr:  cbz -> inverted + abs jump = 5 instrs (20 bytes)
 *      4 hook instrs * 20 = 80 bytes + jump back (16) = 96 bytes
 *      round up to 128 just incase
 * ───────────────────────────────────────────────────────────────────────────── */

#define SILKHOOK_INSTR_SIZE         4u
#define SILKHOOK_HOOK_N_INSTR       4u
#define SILKHOOK_HOOK_N_BYTE        (SILKHOOK_INSTR_SIZE * SILKHOOK_HOOK_N_INSTR)
#define SILKHOOK_TRAMPOLINE_MAX     128u

#define SILKHOOK_SAFE_HOOK_N_INSTR  9u
#define SILKHOOK_SAFE_HOOK_N_BYTE   (SILKHOOK_INSTR_SIZE * SILKHOOK_SAFE_HOOK_N_INSTR)
#define SILKHOOK_POP_N_BYTE         (SILKHOOK_INSTR_SIZE * 1u)


/* ─────────────────────────────────────────────────────────────────────────────
 * pt_regs - register context for kernel hooks
 *
 * 272 bytes, 16-byte aligned
 *
 *   x0-x30  (31 regs * 8)  = 248 bytes
 *   sp                     =   8 bytes
 *   pc                     =   8 bytes
 *   pstate                 =   8 bytes
 *                          = 272 bytes
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_pt_regs {
    uint64_t x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7;
    uint64_t x8,  x9,  x10, x11, x12, x13, x14, x15;
    uint64_t x16, x17, x18, x19, x20, x21, x22, x23;
    uint64_t x24, x25, x26, x27, x28, x29, x30;

    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

#define SILKHOOK_PT_REGS_SIZE       272u


/* ─────────────────────────────────────────────────────────────────────────────
 * hook context
 *
 *   targ ──> detour ──> trampoline ──> targ + HOOK_N_BYTE
 *     │                     │
 *     └─────────────────────┘
 *           (call orig)
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_hook {
    uintptr_t   targ;
    uintptr_t   detour;
    uintptr_t   trampoline;

    uint32_t    orig[SILKHOOK_HOOK_N_INSTR];
    size_t      orig_size;

    bool        active;

    struct silkhook_hook *next;
};


/* ─────────────────────────────────────────────────────────────────────────────
 * batch descriptor
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_desc {
    void    *targ;
    void    *detour;
    void    **orig;
};


#endif /* _SILKHOOK_TYPES_H_ */
