/*
 * silkhook          - miniature arm hooking lib
 * relocator_arm32.h - arm32 instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_RELOCATOR_ARM32_H_
#define _SILKHOOK_RELOCATOR_ARM32_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
#endif

#include "arch_arm32.h"
#include "assembler.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * arm32 classification
 * ───────────────────────────────────────────────────────────────────────────── */

enum __arm32_instr_kind {
    ARM32_INSTR_OTHER,
    ARM32_INSTR_B,
    ARM32_INSTR_BL,
    ARM32_INSTR_LDR_LIT,
    ARM32_INSTR_ADR,
};


/* ─────────────────────────────────────────────────────────────────────────────
 * classification macro
 *
 * only handling arm for now
 * TODO: thumb also
 * ───────────────────────────────────────────────────────────────────────────── */

#define __ARM32_CLASSIFY(instr) ( \
    (((instr) & 0x0F000000u) == 0x0A000000u)   ?  ARM32_INSTR_B :  \
    (((instr) & 0x0F000000u) == 0x0B000000u)   ?  ARM32_INSTR_BL : \
    (((instr) & __ARM32_LDR_LIT_MASK) == __ARM32_LDR_LIT_OP) ?  ARM32_INSTR_LDR_LIT : \
    ((((instr) & 0x0FFF0000u) == 0x028F0000u) ||                   \
    (((instr) & 0x0FFF0000u) == 0x024F0000u)) ? ARM32_INSTR_ADR :  \
    ARM32_INSTR_OTHER \
)


int __arm32_reloc(uint32_t instr, uintptr_t pc, struct __codebuf *cb);


#endif /* _SILKHOOK_RELOCATOR_ARM32_H_ */
