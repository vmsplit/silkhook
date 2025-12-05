/*
 * silkhook          - miniature arm hooking lib
 * relocator_thumb.h - thumb instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_RELOCATOR_THUMB_H_
#define _SILKHOOK_RELOCATOR_THUMB_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
#endif

#include "assembler.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * thumb classification
 *
 * thumb & thunb2 16/32-bit instructions
 * 32-bit instrs  will start with 0b11101 / 0b11110 / 0b11111
 * ───────────────────────────────────────────────────────────────────────────── */

enum __thumb_instr_kind
{
    THUMB_INSTR_OTHER,
    THUMB_INSTR_B_T1,
    THUMB_INSTR_B_T2,
    THUMB_INSTR_BL_T1,
    THUMB_INSTR_B_T3,
    THUMB_INSTR_B_T4,
    THUMB_INSTR_LDR_LIT,
    THUMB_INSTR_LDR_LIT_W,
    THUMB_INSTR_ADR_T1,
    THUMB_INSTR_ADR_T2,
    THUMB_INSTR_ADR_T3,
    THUMB_INSTR_CBZ,
};

/*  is the instruction thumb2 ?   */
#define __THUMB_IS_32BIT(hw) \
    (((hw) & 0xE000u) == 0xE000u && ((hw) & 0x1800u) != 0x0000u)


/* ─────────────────────────────────────────────────────────────────────────────
 * 16-bit emission thumb code buf helpers
 * ───────────────────────────────────────────────────────────────────────────── */

struct __thumb_codebuf
{
    uint16_t    *buf;
    size_t      cap;
    size_t      len;
    uintptr_t   pc;
};

#define __THUMB_CODEBUF_INIT(cb, b, c, p) do { \
    (cb)->buf = (b); \
    (cb)->cap = (c); \
    (cb)->len = 0;   \
    (cb)->pc = (p);  \
} while (0)

#define __THUMB_CODEBUF_EMIT16(cb, hw) do { \
    if ((cb)->len < (cb)->cap) \
        (cb)->buf[(cb)->len++] = (uint16_t) (hw); \
} while (0)

#define __THUMB_CODEBUF_EMIT32(cb, w) do { \
    __THUMB_CODEBUF_EMIT16((cb), (uint16_t) ((w) & 0xFFFFu)); \
    __THUMB_CODEBUF_EMIT16((cb), (uint16_t) (((w) >> 16) & 0xFFFFu)); \
} while (0)

#define __THUMB_CODEBUF_SIZE(cb)        ((cb)->len * 2)
#define __THUMB_CODEBUF_PC(cb)          ((cb)->pc + (cb)->len * 2)


/* ─────────────────────────────────────────────────────────────────────────────
 * instruction encoding for thumb
 * ───────────────────────────────────────────────────────────────────────────── */

/*  thumb nop  */
#define __THUMB_NOP16       0xBF00u

/*  push/pop regs  */
#define __THUMB_PUSH_R(r)   (0xB400u | (1u << (r)))
#define __THUMB_POP_R(r)    (0xBC00u | (1u << (r)))

/*  mov  Rd, Rn (high regs)  */
#define __THUMB_MOV_RD_RM(rd, rm) \
    (0x4600u | (((rd) & 8) << 4) | (((rm) & 8) << 3) | (((rm) & 7) << 3) | ((rd) & 7))

/*  bx Rn  */
#define __THUMB_BX(rm)      (0x4700u | ((rm) << 3))

/*  ldr Rt, [pc, #imm8*4]  */
#define __THUMB_LDR_PC(rt, imm8) \
    (0x4800u | ((rt) << 8) | ((imm8) & 0xFFu))


/* ─────────────────────────────────────────────────────────────────────────────
 * instruction encoding for thumb2
 * ───────────────────────────────────────────────────────────────────────────── */

/*  movw Rd, #imm16
 *  encoding:
 *  1 1 1 1 0 | i | 10 | 0 | 1 | 0 | 0 | imm4 | 0 | imm3 | Rd | imm8 */
static inline uint32_t __thumb2_movw(unsigned rd, uint16_t imm)
{
    uint32_t i      = (imm >> 11) & 1;
    uint32_t imm4   = (imm >> 12) & 0xF;
    uint32_t imm3   = (imm >> 8)  & 7;
    uint32_t imm8   = imm & 0xFF;

    uint16_t hw1 = 0xF240u | (i << 10) | imm4;
    uint16_t hw2 = (imm3 << 12) | (rd << 8) | imm8;

    return ((uint32_t) hw2 << 16) | hw1;
}

/*  movt Rd, #imm16
 *  encoding:
 *  1 1 1 1 0 | i | 10 | 1 | 1 | 0 | 0 | imm4 | 0 | imm3 | Rd | imm8 */
static inline uint32_t __thumb2_movt(unsigned rd, uint16_t imm)
{
    uint32_t i      = (imm >> 11) & 1;
    uint32_t imm4   = (imm >> 12) & 0xF;
    uint32_t imm3   = (imm >> 8)  & 7;
    uint32_t imm8   = imm & 0xFF;

    uint16_t hw1 = 0xF2C0u | (i << 10) | imm4;
    uint16_t hw2 = (imm3 << 12) | (rd << 8) | imm8;

    return ((uint32_t) hw2 << 16) | hw1;
}


#define __THUMB2_LDR_RN_0(rt, rn) \
    (((uint32_t) (0x8000u | ((rt) << 12)) << 16) | (0xF8D0u | (rn)))


static inline void __thumb_emit_abs_jmp(struct __thumb_codebuf *cb, uint32_t targ)
{
    __THUMB_CODEBUF_EMIT16(cb, 0xB410u);
    __THUMB_CODEBUF_EMIT16(cb, 0x4C01u);
    __THUMB_CODEBUF_EMIT16(cb, 0x4720u);
    __THUMB_CODEBUF_EMIT16(cb, 0xBC10u);
    __THUMB_CODEBUF_EMIT16(cb, targ & 0xFFFFu);
    __THUMB_CODEBUF_EMIT16(cb, (targ >> 16) & 0xFFFFu);
}


int __thumb_reloc(const uint16_t *src, size_t n_bytes, uintptr_t src_pc,
                     struct __thumb_codebuf *cb);


#endif /* _SILKHOOK_RELOCATOR_THUMB_H_ */
