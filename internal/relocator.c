/*
 * silkhook    - miniature arm64 hooking lib
 * relocator.c - instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

#include "relocator.h"
#include "arch.h"
#include "assembler.h"
#include "../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * internal helpers - decoding
 * ───────────────────────────────────────────────────────────────────────────── */

static inline int64_t _sign_extend(uint64_t val, unsigned bits)
{
    uint64_t sign_bit = 1ull << (bits - 1);
    return (int64_t)((val ^ sign_bit) - sign_bit);
}
static inline int64_t _decode_b_offset(uint32_t instr)
{
    int64_t imm26 = _sign_extend(instr & 0x3FFFFFF, 26);
    return imm26 << 2;
}
static inline int64_t _decode_adr_offset(uint32_t instr)
{
    uint32_t immlo = (instr >> 29) & 0x3;
    uint32_t immhi = (instr >> 5)  & 0x7FFFF;
    int64_t imm = _sign_extend((immhi << 2) | immlo, 21);
    return imm;
}
static inline int64_t _decode_adrp_offset(uint32_t instr)
{
    return _decode_adr_offset(instr) << 12;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */

enum instr_kind classify_instr(uint32_t instr)
{
    /* b / bl */
    if ((instr & ARM64_B_MASK) == ARM64_B_OPCODE)             return INSTR_B;
    if ((instr & ARM64_B_MASK) == ARM64_BL_OPCODE)            return INSTR_BL;
    /* b.cond */
    if ((instr & ARM64_B_COND_MASK) == ARM64_B_COND_OPCODE)   return INSTR_B_COND;
    /* cbz / cbnz */
    if ((instr & ARM64_CBZ_MASK) == ARM64_CBZ_OPCODE)         return INSTR_CBZ;
    if ((instr & ARM64_CBZ_MASK) == ARM64_CBNZ_OPCODE)        return INSTR_CBNZ;
    /* tbz / tbnz */
    if ((instr & ARM64_TBZ_MASK) == ARM64_TBZ_OPCODE)         return INSTR_TBZ;
    if ((instr & ARM64_TBZ_MASK) == ARM64_TBNZ_OPCODE)        return INSTR_TBNZ;
    /* adr / adrp */
    if ((instr & ARM64_ADR_MASK) == ARM64_ADR_OPCODE)         return INSTR_ADR;
    if ((instr & ARM64_ADR_MASK) == ARM64_ADRP_OPCODE)        return INSTR_ADRP;
    /* ldr literal */
    if ((instr & ARM64_LDR_LIT_MASK) == ARM64_LDR_LIT_OPCODE) return INSTR_LDR_LIT;
    return INSTR_NORMAL;
}


int relocate_instr(uint32_t instr, uintptr_t from_pc, struct codebuf *cb)
{
    enum instr_kind kind = classify_instr(instr);
    uintptr_t target;
    unsigned rd;

    switch (kind)
    {
        case INSTR_NORMAL:
            codebuf_emit(cb, instr);
            break;
        case INSTR_B:
            target = from_pc + _decode_b_offset(instr);
            emit_absolute_jump(cb, target);
            break;
        case INSTR_BL:
            target = from_pc + _decode_b_offset(instr);
            codebuf_emit(cb, 0x100000FE);
            emit_absolute_jump(cb, target);
            break;
        case INSTR_ADR:
            rd = instr & 0x1F;
            target = from_pc + _decode_adr_offset(instr);
            codebuf_emit(cb, assemble_movz(rd, (target >>  0) & 0xFFFF,  0));
            codebuf_emit(cb, assemble_movk(rd, (target >> 16) & 0xFFFF, 16));
            codebuf_emit(cb, assemble_movk(rd, (target >> 32) & 0xFFFF, 32));
            codebuf_emit(cb, assemble_movk(rd, (target >> 48) & 0xFFFF, 48));
            break;
        case INSTR_ADRP:
            rd = instr & 0x1F;
            target = (from_pc & ~0xFFFull) + _decode_adrp_offset(instr);
            codebuf_emit(cb, assemble_movz(rd, (target >>  0) & 0xFFFF,  0));
            codebuf_emit(cb, assemble_movk(rd, (target >> 16) & 0xFFFF, 16));
            codebuf_emit(cb, assemble_movk(rd, (target >> 32) & 0xFFFF, 32));
            codebuf_emit(cb, assemble_movk(rd, (target >> 48) & 0xFFFF, 48));
            break;
        case INSTR_B_COND:
        case INSTR_CBZ:
        case INSTR_CBNZ:
        case INSTR_TBZ:
        case INSTR_TBNZ:
        case INSTR_LDR_LIT:
            return ERR_BAD_INSTR;

        default:
            codebuf_emit(cb, instr);
            break;
    }

    return OK;
}
