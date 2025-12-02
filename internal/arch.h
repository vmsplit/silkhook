/*
 * silkhook - miniature arm64 hooking lib
 * arch.h   - arm64 arch definitions
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ARCH_H_
#define _ARCH_H_

#include <stdint.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * branch instructions
 *
 * https://developer.arm.com/documentation/ddi0602/2024-06/Base-Instructions/B--Branch-
 *
 * B encoding:
 * 0 0 0 1 0 1 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 * ------------|------------------------------------------------------
 * opcode      | imm26
 *
 *
 * https://developer.arm. com/documentation/ddi0602/2024-06/Base-Instructions/BL--Branch-with-link-
 *
 * BL encoding:
 * 1 0 0 1 0 1 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 * ------------|------------------------------------------------------
 * opcode      | imm26
 *
 *
 * https://developer.arm.com/documentation/ddi0602/2024-06/Base-Instructions/B-cond--Branch-conditionally-
 *
 * B. cond encoding:
 * 0 1 0 1 0 1 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 | 0 0 0 0
 * ----------------|---------------------------------------|---|--------
 * opcode          | imm19                                 | 0 | cond
 *
 * ───────────────────────────────────────────────────────────────────────────── */

#define ARM64_B_MASK            0xFC000000u
#define ARM64_B_OPCODE          0x14000000u
#define ARM64_BL_OPCODE         0x94000000u
#define ARM64_B_COND_MASK       0xFF000010u
#define ARM64_B_COND_OPCODE     0x54000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * compare & branch
 *
 * https://documentation-service.arm.com/static/6839d7585475b403d943b4dc
 * ^^^ encodings not listed on arm docs
 *
 * CBZ/CBNZ encoding:
 * 0 | 0 1 1 0 1 0 | 0  | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
 * --|-------------|----|---------------------------------------|----------
 * sf| opcode      | op | imm19                                 | Rt
 *                   ^
 *                   └─ 0=CBZ, 1=CBNZ
 * ───────────────────────────────────────────────────────────────────────────── */

#define ARM64_CBZ_MASK          0x7F000000u
#define ARM64_CBZ_OPCODE        0x34000000u
#define ARM64_CBNZ_OPCODE       0x35000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * test & branch
 *
 * https://documentation-service.arm.com/static/6839d7585475b403d943b4dc
 * ^^^ encodings not listed on arm docs
 *
 * TBZ/TBNZ encoding:
 * 0 | 0 1 1 0 1 1 | 0 | 0 0 0 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
 * --|-------------|---|---------|------------------------------|----------
 * b5| opcode      |op | b40     | imm14                        | Rt
 *
 * bit number = b5:b40 (6 bits)
 * ───────────────────────────────────────────────────────────────────────────── */

#define ARM64_TBZ_MASK          0x7F000000u
#define ARM64_TBZ_OPCODE        0x36000000u
#define ARM64_TBNZ_OPCODE       0x37000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * pc-relative addressing
 *
 * https://documentation-service.arm. com/static/6630d3330ef2dd574a067f43
 * ^^^ encodings not listed on arm docs
 *
 * ADR/ADRP encoding:
 * 0   | 0 0   | 1 0 0 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
 * ----|-------|-----------|---------------------------------------|----------
 * op  | immlo | opcode    | immhi                                 | Rd
 * ^
 * └─ 0=ADR, 1=ADRP
 *
 * ADR:  offset = immhi:immlo (signed, byte aligned)
 * ADRP: offset = immhi:immlo << 12 (signed, page aligned)
 * ───────────────────────────────────────────────────────────────────────────── */

#define ARM64_ADR_MASK          0x9F000000u
#define ARM64_ADR_OPCODE        0x10000000u
#define ARM64_ADRP_OPCODE       0x90000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * load literal
 *
 * https://developer.arm.com/documentation/111182/2025-09_ASL1/Base-Instructions/LDR--literal---Load-register--literal--
 *
 * LDR (literal) encoding:
 * 0 0 | 0 1 1 | 0 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
 * ----|-------|-------|---------------------------------------|----------
 * opc | 0 1 1 | V     | imm19                                 | Rt
 *
 * opc: 00=32bit, 01=64bit, 10=signed 32bit
 * ───────────────────────────────────────────────────────────────────────────── */

#define ARM64_LDR_LIT_MASK      0x3B000000u
#define ARM64_LDR_LIT_OPCODE    0x18000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * instruction encoding helpers
 *
 * we use x16 (IP0) as scratch - it's the intra-procedure-call reg
 *
 * x0-x7   : args/return     x16-x17 : scratch  (we use these)
 * x8      : indirect result x18     : platform
 * x9-x15  : caller-saved    x19-x28 : callee-saved
 *                           x29     : frame pointer
 *                           x30     : link register
 * ───────────────────────────────────────────────────────────────────────────── */

// https://developer.arm. com/documentation/111182/2025-09_ASL1/Base-Instructions/LDR--literal---Load-register--literal--
// ldr (literal) encoding:
// 0 1 | 0 1 1 | 0 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
// ----|-------|-------|---------------------------------------|----------
// opc | 0 1 1 | V     | imm19                                 | Rt
static inline uint32_t assemble_ldr_literal(unsigned reg, int32_t offset)
{
    int32_t imm19 = (offset >> 2) & 0x7FFFF;
    return 0x58000000u | (imm19 << 5) | reg;
}


// https://developer. arm.com/documentation/111182/2025-09_ASL1/Base-Instructions/BR--Branch-to-register-
// br encoding:
// 1 1 0 1 0 1 1 0 0 0 0 1 1 1 1 1 0 0 0 0 0 0 | 0 0 0 0 0 | 0 0 0 0 0
// --------------------------------------------|-----------|----------
// opcode                                      | Rn        | (zero)
static inline uint32_t assemble_br(unsigned reg)
{
    return 0xD61F0000u | (reg << 5);
}


// https://developer.arm.com/documentation/111108/2025-09/Base-Instructions/BLR--Branch-with-link-to-register-
// blr encoding:
// 1 1 0 1 0 1 1 0 0 0 1 1 1 1 1 1 0 0 0 0 0 0 | 0 0 0 0 0 | 0 0 0 0 0
// --------------------------------------------|-----------|----------
// opcode                                      | Rn        | (zero)
static inline uint32_t assemble_blr(unsigned reg)
{
    return 0xD63F0000u | (reg << 5);
}


// ret = br x30
static inline uint32_t assemble_ret(void)
{
    return 0xD65F03C0u;
}

static inline uint32_t assemble_nop(void)
{
    return 0xD503201Fu;
}


// https://developer. arm.com/documentation/111182/2025-09_ASL1/Base-Instructions/MOVZ--Move-wide-with-zero-
// https://ohyaan. github.io/assembly/arm64_registers_and_basic_instructions/#data-movement-instructions
//
// movz encoding:
// 1 | 1 0 1 0 0 1 0 1 | 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
// --|-----------------|-----|--------------------------------|----------
// sf| opc             | hw  | imm16                          | Rd
static inline uint32_t assemble_movz(unsigned reg, uint16_t imm16, unsigned shift)
{
    unsigned hw = shift / 16;
    return 0xD2800000u | (hw << 21) | ((uint32_t)imm16 << 5) | reg;
}


// https://developer.arm.com/documentation/111182/2025-09_ASL1/Base-Instructions/MOVK--Move-wide-with-keep-
// https://ohyaan.github. io/assembly/arm64_registers_and_basic_instructions/#data-movement-instructions
//
// movk encoding:
// 1 | 1 1 1 0 0 1 0 1 | 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
// --|-----------------|-----|--------------------------------|----------
// sf| opc             | hw  | imm16                          | Rd
//
// build 64-bit immediate:
//   movz x0, #0x1234           -> [0x0000000000001234]
//   movk x0, #0x5678, lsl 16   -> [0x0000000056781234]
//   movk x0, #0x9ABC, lsl 32   -> [0x00009ABC56781234]
//   movk x0, #0xDEF0, lsl 48   -> [0xDEF09ABC56781234]
static inline uint32_t assemble_movk(unsigned reg, uint16_t imm16, unsigned shift)
{
    unsigned hw = shift / 16;
    return 0xF2800000u | (hw << 21) | ((uint32_t)imm16 << 5) | reg;
}


#endif /* _ARCH_H_ */
