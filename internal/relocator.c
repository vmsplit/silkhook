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
static inline int64_t _decode_b_cond_offset(uint32_t instr)
{
    int64_t imm19 = _sign_extend((instr >> 5) & 0x7FFFF, 19);
    return imm19 << 2;
}
static inline int64_t _decode_cbz_offset(uint32_t instr)
{
    int64_t imm19 = _sign_extend((instr >> 5) & 0x7FFFF, 19);
    return imm19 << 2;
}
static inline int64_t _decode_tbz_offset(uint32_t instr)
{
    int64_t imm14 = _sign_extend((instr >> 5) & 0x3FFFF, 14);
    return imm14 << 2;
}
static inline int64_t _decode_ldr_lit_offset(uint32_t instr)
{
    int64_t imm19 = _sign_extend((instr >> 5) & 0x7FFFF, 19);
    return imm19 << 2;
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
 * internal helpers - encoding
 *
 * b. cond / cbz / tbz have limited range,  so we invert the cond
 * and jump over an absolute branch to the orig  target
 *
 *   orig:                 relocated:
 *   ┌──────────────┐      ┌──────────────────────┐
 *   │ cbz x0, #off │      │ cbnz x0, #skip       │ <- invertd
 *   └──────────────┘      │ ldr  x16, [pc, #8]   │
 *                         │ br   x16             │
 *                         │ <target_low>         │
 *                         │ <target_high>        │
 *                         │ skip: ...            │ <- continue
 *                         └──────────────────────┘
 * ───────────────────────────────────────────────────────────────────────────── */

static inline uint32_t _invert_b_cond(uint32_t instr)
{
    return instr ^ 0x1;
}
static inline uint32_t _invert_cbz_cbnz(uint32_t instr)
{
    return instr ^ (1u << 24);
}
static inline uint32_t _invert_tbz_tbnz(uint32_t instr)
{
    return instr ^ (1u << 24);
}
static inline uint32_t _make_b_cond_skip(uint32_t instr, int32_t skip_instrs)
{
    uint32_t cond = instr & 0xF;
    uint32_t imm19 = (skip_instrs & 0x7FFFF) << 5;
    return ARM64_B_COND_OPCODE | imm19 | cond;
}
static inline uint32_t _make_cbz_skip(uint32_t instr, int32_t skip_instrs)
{
    uint32_t sf    = instr & (1u << 31);
    uint32_t op    = instr & (1u << 24);
    uint32_t rt    = instr & 0x1F;
    uint32_t imm19 = (skip_instrs & 0x7FFFF) << 5;
    return 0x34000000u | sf | op | imm19 | rt;
}
static inline uint32_t _make_tbz_skip(uint32_t instr, int32_t skip_instrs)
{
    uint32_t b5    = instr & (1u << 31);
    uint32_t op    = instr & (1u << 24);
    uint32_t b40   = instr & (0x1F << 19);
    uint32_t rt    = instr & 0x1F;
    uint32_t imm14 = (skip_instrs & 0x3FFFF) << 5;
    return 0x36000000u | b5 | op | b40 | imm14 | rt;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * relocation emitters
 * ───────────────────────────────────────────────────────────────────────────── */

static void _emit_mov_imm64(struct codebuf *cb, unsigned reg, uint64_t imm)
{
    codebuf_emit(cb, assemble_movz(reg, (imm >>  0) & 0xFFFF,  0));
    codebuf_emit(cb, assemble_movk(reg, (imm >> 16) & 0xFFFF, 16));
    codebuf_emit(cb, assemble_movk(reg, (imm >> 32) & 0xFFFF, 32));
    codebuf_emit(cb, assemble_movk(reg, (imm >> 48) & 0xFFFF, 48));
}

static void _relocate_b_cond(uint32_t instr, uintptr_t targ, struct codebuf *cb)
{
    /*
     * b. cond <targ> ──> b. ! cond skip
     *                    ldr   x16, [pc, #8]
     *                    br    x16
     *                    <target_low>
     *                    <target_high>
     *                skip:
     */
    uint32_t inverted = _invert_b_cond(instr);
    uint32_t skip = _make_b_cond_skip(inverted, 5);
    codebuf_emit(cb, skip);
    emit_absolute_jump(cb, targ);
}

static void _relocate_cbz(uint32_t instr, uintptr_t targ, struct codebuf *cb)
{
    /*
     * cbz xN, <targ> ──> cbnz   xN, skip
     *                    ldr    x16, [pc, #8]
     *                    br     x16
     *                    <target_low>
     *                    <target_high>
     *                skip:
     */
    uint32_t inverted = _invert_cbz_cbnz(instr);
    uint32_t skip = _make_cbz_skip(inverted, 5);
    codebuf_emit(cb, skip);
    emit_absolute_jump(cb, targ);
}

static void _relocate_tbz(uint32_t instr, uintptr_t targ, struct codebuf *cb)
{
    /*
     * tbz xN, #bit, <targ> ──> tbnz   xN, #bit, skip
     *                           ldr    x16, [pc, #8]
     *                           br     x16
     *                           <target_low>
     *                           <target_high>
     *                       skip:
     */
    uint32_t inverted = _invert_tbz_tbnz(instr);
    uint32_t skip = _make_tbz_skip(inverted, 5);
    codebuf_emit(cb, skip);
    emit_absolute_jump(cb, targ);
}

static void _relocate_ldr_lit(uint32_t instr, uintptr_t targ, struct codebuf *cb)
{
    unsigned rt  = instr & 0x1F;
    uint32_t opc = (instr >> 30) & 0x3;
    uint32_t v   = (instr >> 26) & 0x1;

    _emit_mov_imm64(cb, 16, targ);

    if (v)
    {
        uint32_t size = (opc == 0) ? 2: (opc == 1) ? 3 : 4;
        codebuf_emit(cb, 0x3C400200u | (size << 30) | ( 16 << 5) | rt);
    } else {
        if (opc == 0)
        {
            codebuf_emit(cb, 0xB9400200u | (16 << 5) | rt);
        } else {
            codebuf_emit(cb, 0xF9400200u | (16 << 5) | rt);
        }
    }
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
    uintptr_t targ;
    unsigned rd;

    switch (kind)
    {
        case INSTR_NORMAL:
            codebuf_emit(cb, instr);
            break;
        case INSTR_B:
            targ = from_pc + _decode_b_offset(instr);
            emit_absolute_jump(cb, targ);
            break;
        case INSTR_BL:
            targ = from_pc + _decode_b_offset(instr);
            codebuf_emit(cb, 0x100000FE);
            emit_absolute_jump(cb, targ);
            break;
        case INSTR_B_COND:
            targ = from_pc + _decode_b_cond_offset(instr);
            _relocate_b_cond(instr, targ, cb);
            break;
        case INSTR_CBZ:
        case INSTR_CBNZ:
            targ = from_pc + _decode_cbz_offset(instr);
            _relocate_cbz(instr, targ, cb);
            break;
        case INSTR_TBZ:
        case INSTR_TBNZ:
            targ = from_pc + _decode_tbz_offset(instr);
            _relocate_tbz(instr, targ, cb);
            break;
        case INSTR_ADR:
            rd = instr & 0x1F;
            targ = from_pc + _decode_adr_offset(instr);
            _emit_mov_imm64(cb, rd, targ);
            break;
        case INSTR_ADRP:
            rd = instr & 0x1F;
            targ = (from_pc & ~0xFFFull) + _decode_adrp_offset(instr);
            _emit_mov_imm64(cb, rd, targ);
            break;
        case INSTR_LDR_LIT:
            targ = from_pc + _decode_ldr_lit_offset(instr);
            _relocate_ldr_lit(instr, targ, cb);
            break;
        default:
            codebuf_emit(cb, instr);
            break;
    }

    return OK;
}
