/*
 * silkhook    - miniature arm64 hooking lib
 * relocator.h - instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _RELOCATOR_H_
#define _RELOCATOR_H_

#include <stdint.h>
#include "assembler.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * why relocate?
 *
 * some instrs are pc-relative.   moving them breaks things.
 *
 *   orig @ 0x1000:              trampoline @ 0x5000:
 *   ┌──────────────────┐        ┌──────────────────┐
 *   │ adr  x0, #0x100  │  --->  │ adr  x0, #0x100  │  <- wrong!
 *   └──────────────────┘        └──────────────────┘
 *          |                           |
 *          v                           v
 *       0x1100                      0x5100
 *
 * solution: convert pc-relative to absolute (movz/movk sequence)
 * ───────────────────────────────────────────────────────────────────────────── */

enum instr_kind {
    INSTR_NORMAL,
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


enum instr_kind classify_instr(uint32_t instr);
int relocate_instr(uint32_t instr, uintptr_t from_pc, struct codebuf *cb);


#endif /* _RELOCATOR_H_ */
