/*
 * silkhook          - miniature arm64 hooking lib
 * relocator_thumb.c - thumb instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

#include "relocator_thumb.h"
#include "arch_arm32.h"
#include "../include/status.h"


static inline int32_t __sext(uint32_t val, unsigned bits)
{
    uint32_t sign = 1u << (bits - 1);
    return (int32_t) ((val ^ sign) - sign);
}


static enum __thumb_instr_kind __classify_thumb16(uint16_t hw)
{
    if ((hw & 0xF000u) == 0xD000u)
    {
        uint16_t cond = (hw >> 8) & 0xF;
        if (cond < 0xE)
            return THUMB_INSTR_B_T1;
    }

    if ((hw & 0xF800u) == 0xE000u)
        return THUMB_INSTR_B_T2;

    if ((hw & 0xF800u) == 0x4800u)
        return THUMB_INSTR_LDR_LIT;

    if ((hw & 0xF800u) == 0xA000u)
        return THUMB_INSTR_ADR_T1;

    if ((hw & 0xF500u) == 0xB100u)
        return THUMB_INSTR_CBZ;

    return THUMB_INSTR_OTHER;
}

static enum __thumb_instr_kind __classify_thumb32(uint16_t hw1, uint16_t hw2)
{
    uint32_t op1 = (hw1 >> 11) & 0x3;
    uint32_t op2 = (hw1 >> 4)  & 0x7F;
    uint32_t op  = (hw2 >> 12) & 0x7;

    if (op1 == 2 && (hw2 & 0xD000u) == 0xD000u)
        return THUMB_INSTR_BL_T1;

    if (op1 == 2 && (hw2 & 0xD000u) == 0x8000u)
    {
        uint16_t cond = (hw1 >> 6) & 0xF;
        if (cond < 0xE)
            return THUMB_INSTR_B_T3;
    }

    if (op1 == 2 && (hw2 & 0xD000u) == 0x9000u)
        return THUMB_INSTR_B_T4;

    if ((hw1 & 0xFF7Fu) == 0xF85Fu)
        return THUMB_INSTR_LDR_LIT_W;

    if ((hw1 & 0xFBFFu) == 0xF2AFu && (hw2 & 0x8000u) == 0)
        return THUMB_INSTR_ADR_T2;

    if ((hw1 & 0xFBFFu) == 0xF20Fu && (hw2 & 0x8000u) == 0)
        return THUMB_INSTR_ADR_T3;

    (void) op2;
    (void) op;

    return THUMB_INSTR_OTHER;
}

static void __emit_mov32(struct __thumb_codebuf *cb, unsigned rd, uint32_t imm)
{
    __THUMB_CODEBUF_EMIT32(cb, __thumb2_movw(rd, imm & 0xFFFF));
    __THUMB_CODEBUF_EMIT32(cb, __thumb2_movt(rd, (imm >> 16) & 0xFFFF));
}

static int __reloc_thumb16(uint16_t hw, uintptr_t pc, struct __thumb_codebuf *cb)
{
    enum __thumb_instr_kind k = __classify_thumb16(hw);
    int32_t off;
    uintptr_t targ;

    switch(k)
    {
    case THUMB_INSTR_B_T1:
        off = __sext(hw & 0xFF, 8) * 2;
        targ = pc + 4 + off;
        {
            uint16_t cond = (hw >> 8) & 0xF;
            uint16_t inv_cond = cond  ^ 1;

            __THUMB_CODEBUF_EMIT16(cb, 0xD000u | (inv_cond << 8) | 5);
            __thumb_emit_abs_jmp(cb, targ | 1);
        }
        break;
    case THUMB_INSTR_B_T2:
        off = __sext(hw & 0x7FF, 11) * 2;
        targ = pc + 4 + off;
        __thumb_emit_abs_jmp(cb, targ | 1);
        break;
    case THUMB_INSTR_LDR_LIT:
        {
            unsigned rt = (hw >> 8) & 7;
            uint32_t imm8 = hw & 0xFF;
            targ = ((pc + 4) & ~3u) + (imm8 * 4);
            __emit_mov32(cb, rt, targ);
            __THUMB_CODEBUF_EMIT32(cb, __THUMB2_LDR_RN_0(rt, rt));
        }
        break;
    case THUMB_INSTR_ADR_T1:
        {
            unsigned rd = (hw >> 8) & 7;
            uint32_t imm8 = hw & 0xFF;
            targ = ((pc + 4) & ~3u) + (imm8 * 4);
            __emit_mov32(cb, rd, targ);
        }
        break;
    case THUMB_INSTR_CBZ:
        {
            unsigned rn = hw & 7;
            unsigned op = (hw >> 11) & 1;
            uint32_t i = (hw >> 9) & 1;
            uint32_t imm5 = (hw >> 3) & 0x1F;
            off = (i << 6) | (imm5 << 1);
            targ = pc + 4 + off;

            __THUMB_CODEBUF_EMIT16(cb, 0x2800u | (rn << 8));
            uint16_t cond = op ? 0x0 : 0x1;
            __THUMB_CODEBUF_EMIT16(cb, 0xD000u | (cond << 8) | 5);
            __thumb_emit_abs_jmp(cb, targ | 1);
        }
        break;
    case THUMB_INSTR_OTHER:
    default:
        __THUMB_CODEBUF_EMIT16(cb, hw);
        break;
    }
    return SILKHOOK_OK;
}


static int __reloc_thumb32(uint16_t hw1, uint16_t hw2, uintptr_t pc,
                           struct __thumb_codebuf *cb)
{
    enum __thumb_instr_kind k = __classify_thumb32(hw1, hw2);
    int32_t off;
    uintptr_t targ;

    switch (k)
    {
    case THUMB_INSTR_BL_T1:
        {
            uint32_t S  = (hw1 >> 10) & 1;
            uint32_t J1 = (hw2 >> 13) & 1;
            uint32_t J2 = (hw2 >> 11) & 1;
            uint32_t imm10 = hw1 & 0x3FF;
            uint32_t imm11 = hw2 & 0x7FF;
            uint32_t I1 = ~(J1 ^ S) & 1;
            uint32_t I2 = ~(J2 ^ S) & 1;

            off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1);
            off = __sext(off, 25);
            targ = pc + 4 + off;

            uintptr_t ret_pc = __THUMB_CODEBUF_PC(cb) + 4 + 12;
            __emit_mov32(cb, 14, (ret_pc | 1));
            __thumb_emit_abs_jmp(cb, targ | 1);
        }
        break;
    case THUMB_INSTR_B_T3:
        {
            uint32_t S = (hw1 >> 10)   & 1;
            uint32_t cond = (hw1 >> 6) & 0xF;
            uint32_t imm6 = hw1 & 0x3F;
            uint32_t J1 = (hw2 >> 13)  & 1;
            uint32_t J2 = (hw2 >> 11)  & 1;
            uint32_t imm11 = hw2 & 0x7FF;

            off = (S << 20) | (J2 << 19) | (J1 << 18) | (imm6 << 12) | (imm11 << 1);
            off = __sext(off, 21);
            targ = pc + 4 + off;

            uint16_t inv_cond = cond ^ 1;
            __THUMB_CODEBUF_EMIT16(cb, 0xD000u | (inv_cond << 8) | 5);
            __thumb_emit_abs_jmp(cb, targ | 1);
        }
        break;
    case THUMB_INSTR_B_T4:
        {
            uint32_t S = (hw1 >> 10)  & 1;
            uint32_t J1 = (hw2 >> 13) & 1;
            uint32_t J2 = (hw2 >> 11) & 1;
            uint32_t imm10 = hw1 & 0x3FF;
            uint32_t imm11 = hw2 & 0x7FF;
            uint32_t I1 = ~(J1 ^ S) & 1;
            uint32_t I2 = ~(J2 ^ S) & 1;

            off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1);
            off = __sext(off, 25);
            targ = pc + 4 + off;

            __thumb_emit_abs_jmp(cb, targ | 1);
        }
        break;
    case THUMB_INSTR_LDR_LIT_W:
        {
            unsigned rt = (hw2 >> 12) & 0xF;
            uint32_t imm12 = hw2 & 0xFFF;
            uint32_t U = (hw1 >> 7)   & 1;
            if (U)
                targ = ((pc + 4) & ~3u) + imm12;
            else
                targ = ((pc + 4) & ~3u) - imm12;

            __emit_mov32(cb, rt, targ);
            __THUMB_CODEBUF_EMIT32(cb, __THUMB2_LDR_RN_0(rt, rt));
        }
        break;
    case THUMB_INSTR_ADR_T2:
    case THUMB_INSTR_ADR_T3:
        {
            unsigned rd = (hw2 >> 8)  & 0xF;
            uint32_t i  = (hw1 >> 10) & 1;
            uint32_t imm3 = (hw2 >> 12) & 7;
            uint32_t imm8 = hw2 & 0xFF;
            uint32_t imm  = (i << 11) | (imm3 << 8) | imm8;

            if (k == THUMB_INSTR_ADR_T2)
                targ = ((pc + 4) & ~3u) - imm;
            else
                targ = ((pc + 4) & ~3u) + imm;

            __emit_mov32(cb, rd, targ);
        }
        break;
    case THUMB_INSTR_OTHER:
    default:
        __THUMB_CODEBUF_EMIT16(cb, hw1);
        __THUMB_CODEBUF_EMIT16(cb, hw2);
        break;
    }
    return SILKHOOK_OK;
}

int __thumb_reloc(const uint16_t *src, size_t n_bytes, uintptr_t src_pc,
                     struct __thumb_codebuf *cb)
{
    size_t pos = 0;
    int status;

    while (pos < n_bytes)
    {
        uint16_t hw1 = src[pos / 2];
        uintptr_t pc = src_pc + pos;

        if (__THUMB_IS_32BIT(hw1))
        {
            if (pos + 4 > n_bytes)
                return SILKHOOK_ERR_INSTR;

            uint16_t hw2 = src[pos / 2 + 1];
            status = __reloc_thumb32(hw1, hw2, pc, cb);
            if (status != SILKHOOK_OK)
                return status;
            pos += 4;
        }
        else {
            status = __reloc_thumb16(hw1, pc, cb);
            if (status != SILKHOOK_OK)
                return status;
            pos += 2;
        }
    }

    return SILKHOOK_OK;
}
