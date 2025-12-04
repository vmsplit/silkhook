/*
 * silkhook     - miniature arm64 hooking lib
 * trampoline.h - trampoline management
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_TRAMPOLINE_H_
#define _SILKHOOK_TRAMPOLINE_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    #include <stddef.h>
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * trampoline layout
 *
 *   [0.. n]   relocated orig instrs
 *   [n+1]     ldr x16, [pc, #8]
 *   [n+2]     br  x16
 *   [n+3]     <targ + HOOK_N_BYTE low>
 *   [n+4]     <targ + HOOK_N_BYTE high>
 * ───────────────────────────────────────────────────────────────────────────── */

int __trampoline_create(uintptr_t targ, size_t n_bytes, uintptr_t *out);
int __trampoline_destroy(uintptr_t tramp);


#endif /* _SILKHOOK_TRAMPOLINE_H_ */
