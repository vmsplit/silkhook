/*
 * silkhook    - miniature arm64 hooking lib
 * relocator.h - instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_RELOCATOR_H_
#define _SILKHOOK_RELOCATOR_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
#endif

#include "arch.h"
#include "assembler.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * relocation
 *
 * pc-relative instrs break when moved.   can just rewrite them as absolute.
 *
 *   orig @ [0x1000]:            tramp @ [0x5000]:
 *   ┌──────────────┐            ┌────────────────┐
 *   │ adr x0, loc  │   ----->   │ movz x0, ...   │
 *   └──────────────┘            │ movk x0, ...   │
 *                               │ movk x0, ...   │
 *                               │ movk x0, ...   │
 *                               └────────────────┘
 * ───────────────────────────────────────────────────────────────────────────── */

enum __instr_kind {
    INSTR_OTHER,
    INSTR_B,
    INSTR_BL,
    INSTR_B_COND,
    INSTR_CBZ,
    INSTR_CBNZ,
    INSTR_TBZ,
    INSTR_TBNZ,
    INSTR_ADR,
    INSTR_ADRP,
    INSTR_LDR_LIT,
};


/* ─────────────────────────────────────────────────────────────────────────────
 * classification
 * ───────────────────────────────────────────────────────────────────────────── */

#define __CLASSIFY(instr) ( \
    (((instr) & __B_MASK) == __B_OP)             ?  INSTR_B :       \
    (((instr) & __B_MASK) == __BL_OP)            ? INSTR_BL :       \
    (((instr) & __B_COND_MASK) == __B_COND_OP)   ? INSTR_B_COND :   \
    (((instr) & __CBZ_MASK) == __CBZ_OP)         ?  INSTR_CBZ :      \
    (((instr) & __CBZ_MASK) == __CBNZ_OP)        ?  INSTR_CBNZ :     \
    (((instr) & __TBZ_MASK) == __TBZ_OP)         ?  INSTR_TBZ :     \
    (((instr) & __TBZ_MASK) == __TBNZ_OP)        ? INSTR_TBNZ :     \
    (((instr) & __ADR_MASK) == __ADR_OP)         ? INSTR_ADR :      \
    (((instr) & __ADR_MASK) == __ADRP_OP)        ?  INSTR_ADRP :     \
    (((instr) & __LDR_LIT_MASK) == __LDR_LIT_OP) ?  INSTR_LDR_LIT : \
    INSTR_OTHER \
)


int __relocate(uint32_t instr, uintptr_t pc, struct __codebuf *cb);


#endif /* _SILKHOOK_RELOCATOR_H_ */
