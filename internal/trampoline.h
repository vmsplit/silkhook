/*
 * silkhook     - miniature arm64 hooking lib
 * trampoline.h - trampoline gen
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _TRAMPOLINE_H_
#define _TRAMPOLINE_H_

#include <stdint.h>
#include <stddef.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * trampoline layout
 *
 * orig func (post-hook):
 *   [0] ldr    x16, #8         ─┐
 *   [1] br     x16              ├─> jump to detour
 *   [2] <detour_lo>             │
 *   [3] <detour_hi>            ─┘
 *   [4] ...  rest of func ...
 *
 * trampoline:
 *   [0] <relocated instr 0>    ─┐
 *   [1] <relocated instr 1>     ├─> orig prologue
 *   [2] <relocated instr 2>     │
 *   [3] <relocated instr 3>    ─┘
 *   [4] ldr    x16, #8         ─┐
 *   [5] br     x16              ├─> jump back to targ+16
 *   [6] <targ+16 lo>            │
 *   [7] <targ+16 hi>           ─┘
 *
 * exec flow:
 *   caller -> targ -> detour -> trampoline -> targ+16 -> ...
 * ───────────────────────────────────────────────────────────────────────────── */

int trampoline_create(uintptr_t targ, size_t hook_size, uintptr_t *out);
int trampoline_destroy(uintptr_t trampoline);


#endif /* _TRAMPOLINE_H_ */
