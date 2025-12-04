/*
 * silkhook - miniature arm64 hooking lib
 * arch.h   - arm64 arch definitions
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_ARCH_H_
#define _SILKHOOK_ARCH_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
#endif

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
 * https://developer.arm.com/documentation/ddi0602/2024-06/Base-Instructions/BL--Branch-with-link-
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

#define __B_MASK            0xFC000000u
#define __B_OP              0x14000000u
#define __BL_OP             0x94000000u
#define __B_COND_MASK       0xFF000010u
#define __B_COND_OP         0x54000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * compare & branch
 *
 * https://documentation-service.arm.com/static/6839d7585475b403d943b4dc
 *
 * CBZ/CBNZ encoding:
 * 0 | 0 1 1 0 1 0 | 0  | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
 * --|-------------|----|---------------------------------------|----------
 * sf| opcode      | op | imm19                                 | Rt
 *                   ^
 *                   └─ 0=CBZ, 1=CBNZ
 * ───────────────────────────────────────────────────────────────────────────── */

#define __CBZ_MASK          0x7F000000u
#define __CBZ_OP            0x34000000u
#define __CBNZ_OP           0x35000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * test & branch
 *
 * https://documentation-service.arm.com/static/6839d7585475b403d943b4dc
 *
 * TBZ/TBNZ encoding:
 * 0 | 0 1 1 0 1 1 | 0 | 0 0 0 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
 * --|-------------|---|---------|------------------------------|----------
 * b5| opcode      |op | b40     | imm14                        | Rt
 *
 * bit number = b5:b40 (6 bits)
 * ───────────────────────────────────────────────────────────────────────────── */

#define __TBZ_MASK          0x7F000000u
#define __TBZ_OP            0x36000000u
#define __TBNZ_OP           0x37000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * pc-relative addressing
 *
 * https://documentation-service.arm. com/static/6630d3330ef2dd574a067f43
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

#define __ADR_MASK          0x9F000000u
#define __ADR_OP            0x10000000u
#define __ADRP_OP           0x90000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * load literal
 *
 * LDR (literal) encoding:
 * opc | 011 | V | imm19 | Rt
 * ───────────────────────────────────────────────────────────────────────────── */

#define __LDR_LIT_MASK      0x3B000000u
#define __LDR_LIT_OP        0x18000000u


/* ─────────────────────────────────────────────────────────────────────────────
 * BTI  (ARMv8.5+)
 *
 * BTI-enabled code requires landing pads @ indirect branch targs:
 *   bti j  - valid targ for BR   (jump)
 *   bti c  - valid targ for BLR  (call)
 *   bti jc - valid for both j, c
 *
 * trampoline is called via BLR,  so we can use BTI_C.
 * on non-BTI devices these could decode as HINT  (nop)
 * ───────────────────────────────────────────────────────────────────────────── */

/*  bti c  */
#define __BTI_C() \
    (0xD503245Fu)

/*  bti j  */
#define __BTI_J() \
    (0xD50324DFu)

/* bti jc  */
#define __BTI_JC() \
    (0xD50324FFu)


/* ─────────────────────────────────────────────────────────────────────────────
 * instruction encoding macros
 *
 * we use x16 (IP0) as scratch - it's the intra-procedure-call reg
 *
 * x0-x7   : args/return     x16-x17 : scratch  (we use these)
 * x8      : indirect result x18     : platform
 * x9-x15  : caller-saved    x19-x28 : callee-saved
 *                           x29     : frame pointer
 *                           x30     : link register
 * ───────────────────────────────────────────────────────────────────────────── */

/*  ldr x<reg> , [pc, #<off>]  */
#define __LDR_LIT(reg, off) \
    (0x58000000u | ((((off) >> 2) & 0x7FFFF) << 5) | (reg))

/*  br x<reg>  */
#define __BR(reg) \
    (0xD61F0000u | ((reg) << 5))

/*  blr x<reg>  */
#define __BLR(reg) \
    (0xD63F0000u | ((reg) << 5))

/*  ret (br x30)  */
#define __RET() \
    (0xD65F03C0u)

/*  nop  */
#define __NOP() \
    (0xD503201Fu)

/*  str x<reg>, [sp, #-16]! (push)  */
#define __PUSH(reg) \
    (0xF81F0FE0u | (reg))

/*  ldr x<reg>, [sp], #16 (pop)  */
#define __POP(reg) \
    (0xF84107E0u | (reg))

/*  movz x<reg>, #<imm16>, lsl #<shift>
 *  1 | 1 0 1 0 0 1 0 1 | hw | imm16 | Rd  */
#define __MOVZ(reg, imm, shift) \
    (0xD2800000u | (((shift) / 16) << 21) | (((uint32_t)(imm) & 0xFFFF) << 5) | (reg))

/*  movk x<reg>, #<imm16>, lsl #<shift>
 *  1 | 1 1 1 0 0 1 0 1 | hw | imm16 | Rd
 *
 *  build 64-bit immediate:
 *    movz x0, #0x1234           -> [0x0000000000001234]
 *    movk x0, #0x5678, lsl 16   -> [0x0000000056781234]
 *    movk x0, #0x9ABC, lsl 32   -> [0x00009ABC56781234]
 *    movk x0, #0xDEF0, lsl 48   -> [0xDEF09ABC56781234]  */
#define __MOVK(reg, imm, shift) \
    (0xF2800000u | (((shift) / 16) << 21) | (((uint32_t)(imm) & 0xFFFF) << 5) | (reg))

/*  b <off> (pc-relative, signed, 4-byte aligned)
    * 0 0 0 1 0 1 | imm26  */
#define __B(off) \
    (0x14000000u | (((off) >> 2) & 0x3FFFFFF))

/*  adr x<reg>, <off>
    * 0 | immlo | 10000 | immhi | Rd  */
#define __ADR(reg, off) \
    (0x10000000u | ((((off) & 0x3) << 29)) | (((((off) >> 2) & 0x7FFFF) << 5)) | (reg))

/* ─────────────────────────────────────────────────────────────────────────────
 * multi-instr sequences
 *
 * these would emit into an array
 * ───────────────────────────────────────────────────────────────────────────── */

/*  simpleload 64-bit immediate val into reg using movz/movk seq
*   usage: uint32_t buf[4]; __MOV64(buf, reg, imm);  */
#define __MOV64(buf, reg, imm) do { \
    (buf)[0] = __MOVZ((reg), ((imm) >>  0) & 0xFFFF,  0); \
    (buf)[1] = __MOVK((reg), ((imm) >> 16) & 0xFFFF, 16); \
    (buf)[2] = __MOVK((reg), ((imm) >> 32) & 0xFFFF, 32); \
    (buf)[3] = __MOVK((reg), ((imm) >> 48) & 0xFFFF, 48); \
} while (0)

/*  absolute jump seq (16 bytes)
*   usage: uint32_t buf[4]; __ABS_JMP(buf, targ);  */
#define __ABS_JMP(buf, targ) do { \
    (buf)[0] = __LDR_LIT(16, 8); \
    (buf)[1] = __BR(16); \
    (buf)[2] = (uint32_t)((targ) & 0xFFFFFFFF); \
    (buf)[3] = (uint32_t)((targ) >> 32); \
} while (0)


/*  safe jump seq - should preserve x0  (36 bytes)
 *  usage: uint32_t buf[9]; __SAFE_JMP(buf, targ);
 *
 *   b       . +8              <- skip ret (for prefetch trick)
 *   ret                       <- never exec'd normally
 *   str     x0, [sp, #-16]!   <- push x0
 *   movz    x0, #...          <- load targ addr
 *   movk    x0, #...
 *   movk    x0, #...
 *   movk    x0, #...
 *   br      x0                <- jump
 *   ldr     x0, [sp], #16     <- pop x0 (exec'd in detour entry)  */
#define __SAFE_JMP(buf, targ) do { \
    (buf)[0] = __B(8);    \
    (buf)[1] = __RET();   \
    (buf)[2] = __PUSH(0); \
    (buf)[3] = __MOVZ(0,  ((targ) >>  0) & 0xFFFF,  0); \
    (buf)[4] = __MOVK(0,  ((targ) >> 16) & 0xFFFF, 16); \
    (buf)[5] = __MOVK(0,  ((targ) >> 32) & 0xFFFF, 32); \
    (buf)[6] = __MOVK(0,  ((targ) >> 48) & 0xFFFF, 48); \
    (buf)[7] = __BR(0);   \
    (buf)[8] = __POP(0);  \
} while (0)


/* ─────────────────────────────────────────────────────────────────────────────
 * decode helpers
 * ───────────────────────────────────────────────────────────────────────────── */

#define __SEXT(val, bits) \
    ((int64_t)(((uint64_t)(val) ^ (1ull << ((bits) - 1))) - (1ull << ((bits) - 1))))

#define __DEC_B(instr) \
    (__SEXT((instr) & 0x3FFFFFF, 26) << 2)

#define __DEC_B_COND(instr) \
    (__SEXT(((instr) >> 5) & 0x7FFFF, 19) << 2)

#define __DEC_CB(instr) \
    (__SEXT(((instr) >> 5) & 0x7FFFF, 19) << 2)

#define __DEC_TB(instr) \
    (__SEXT(((instr) >> 5) & 0x3FFF, 14)  << 2)

#define __DEC_LDR_LIT(instr) \
    (__SEXT(((instr) >> 5) & 0x7FFFF, 19) << 2)

#define __DEC_ADR(instr) \
    (__SEXT(((((instr) >> 5) & 0x7FFFF) << 2) | (((instr) >> 29) & 0x3), 21))

#define __DEC_ADRP(instr) \
    (__DEC_ADR(instr) << 12)


/* ─────────────────────────────────────────────────────────────────────────────
 * instr fields
 * ───────────────────────────────────────────────────────────────────────────── */

#define __RD(instr)     ((instr) & 0x1F)
#define __RT(instr)     ((instr) & 0x1F)
#define __RN(instr)     (((instr) >> 5)  & 0x1F)
#define __OPC(instr)    (((instr) >> 30) & 0x3)
#define __V(instr)      (((instr) >> 26) & 0x1)


#endif /* _SILKHOOK_ARCH_H_ */
