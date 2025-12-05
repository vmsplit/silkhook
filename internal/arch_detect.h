/*
 * silkhook      - miniature arm hooking lib
 * arch_detect.h - arch detection and selection
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_ARCH_DETECT_H_
#define _SILKHOOK_ARCH_DETECT_H_


/* ─────────────────────────────────────────────────────────────────────────────
 * core arch detection
 * ───────────────────────────────────────────────────────────────────────────── */

#if defined(__aarch64__) || defined(_M_ARM64)
    #define SILKHOOK_ARCH_ARM64        1
    #define SILKHOOK_ARCH_NAME         "arm64"
#elif defined(__arm__) || defined(_M_ARM)
    #define SILKHOOK_ARCH_ARM32        1
    #define SILKHOOK_ARCH_NAME         "arm32"
#else
    #error "silkhook: unsupported architecture !!!"
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * unified constants
 * ───────────────────────────────────────────────────────────────────────────── */

#ifdef SILKHOOK_ARCH_ARM64
    #include "arch.h"
    #define SILKHOOK_INSTR_SIZE         4u
    #define SILKHOOK_HOOK_N_INSTR       4u
    #define SILKHOOK_HOOK_N_BYTE        16u
    #define SILKHOOK_TRAMPOLINE_MAX     128u
#endif

#ifdef SILKHOOK_ARCH_ARM32
    #include "arch_arm32.h"
    #define SILKHOOK_INSTR_SIZE         4u
    #define SILKHOOK_HOOK_N_INSTR       3u
    #define SILKHOOK_HOOK_N_BYTE        12u
    #define SILKHOOK_TRAMPOLINE_MAX     64u
#endif


#endif /* _SILKHOOK_ARCH_DETECT_H_ */
