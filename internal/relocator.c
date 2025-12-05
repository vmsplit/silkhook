/*
 * silkhook    - miniature arm64 hooking lib
 * relocator.c - instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

#include "relocator.h"
#include "../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * relocation emitters
 *
 * b. cond / cbz / tbz have limited range,  so we invert the cond
 * and jump over an absolute branch to the orig targ
 *
 *   orig:                 reloc'd:
 *   ┌──────────────┐      ┌──────────────────────┐
 *   │ cbz x0, #off │      │ cbnz x0, #skip       │ <- invertd
 *   └──────────────┘      │ ldr  x16, [pc, #8]   │
 *                         │ br   x16             │
 *                         │ <target_low>         │
 *                         │ <target_high>        │
 *                         │ skip: ...            │ <- continue
 *                         └──────────────────────┘
 * ───────────────────────────────────────────────────────────────────────────── */

static void __reloc_b_cond(uint32_t instr, uintptr_t targ, struct __codebuf *cb)
{
    uint32_t inv = instr ^ 0x1;
    uint32_t cond = inv  & 0xF;
    uint32_t skip = __B_COND_OP | ((5 & 0x7FFFF) << 5) | cond;
    __CODEBUF_EMIT(cb, skip);
    __EMIT_ABS_JMP(cb, targ);
}

static void __reloc_cb(uint32_t instr, uintptr_t targ, struct __codebuf *cb)
{
    uint32_t inv = instr ^ (1u << 24);
    uint32_t sf  = inv   & (1u << 31);
    uint32_t op  = inv   & (1u << 24);
    uint32_t rt  = __RT(inv);
    uint32_t skip = 0x34000000u | sf | op | ((5 & 0x7FFFF) << 5) | rt;
    __CODEBUF_EMIT(cb, skip);
    __EMIT_ABS_JMP(cb, targ);
}

static void __reloc_tb(uint32_t instr, uintptr_t targ, struct __codebuf *cb)
{
    uint32_t inv = instr ^ (1u << 24);
    uint32_t b5  = inv   & (1u << 31);
    uint32_t op  = inv   & (1u << 24);
    uint32_t b40 = inv   & (0x1F << 19);
    uint32_t rt  = __RT(inv);
    uint32_t skip = 0x36000000u | b5 | op | b40 | ((5 & 0x3FFF) << 5) | rt;
    __CODEBUF_EMIT(cb, skip);
    __EMIT_ABS_JMP(cb, targ);
}

static void __reloc_ldr_lit(uint32_t instr, uintptr_t targ, struct __codebuf *cb)
{
    unsigned rt  = __RT(instr);
    uint32_t opc = __OPC(instr);
    uint32_t v   = __V(instr);

    __EMIT_MOV64_OPT(cb, 16, targ);

    if (v)
    {
        uint32_t sz = (opc == 0) ? 2   : (opc == 1) ? 3 : 4;
        __CODEBUF_EMIT(cb, 0x3C400200u | (sz << 30) | (16 << 5) | rt);
    }
    else {
        __CODEBUF_EMIT(cb, (opc ?  0xF9400200u : 0xB9400200u) | (16 << 5) | rt);
    }
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public
 * ───────────────────────────────────────────────────────────────────────────── */

int __reloc(uint32_t instr, uintptr_t pc, struct __codebuf *cb)
{
    enum __instr_kind k = __CLASSIFY(instr);
    uintptr_t targ;

    switch (k)
    {
    case INSTR_OTHER:
        __CODEBUF_EMIT(cb, instr);
        break;
    case INSTR_B:
        targ = pc + __DEC_B(instr);
        __EMIT_ABS_JMP(cb, targ);
        break;
    case INSTR_BL:
        targ = pc + __DEC_B(instr);
        __CODEBUF_EMIT(cb, __ADR(30, 8));
        __EMIT_ABS_JMP(cb, targ);
        break;
    case INSTR_B_COND:
        targ = pc + __DEC_B_COND(instr);
        __reloc_b_cond(instr, targ, cb);
        break;
    case INSTR_CBZ:
    case INSTR_CBNZ:
        targ = pc + __DEC_CB(instr);
        __reloc_cb(instr, targ, cb);
        break;
    case INSTR_TBZ:
    case INSTR_TBNZ:
        targ = pc + __DEC_TB(instr);
        __reloc_tb(instr, targ, cb);
        break;
    case INSTR_ADR:
        targ = pc + __DEC_ADR(instr);
        __EMIT_MOV64_OPT(cb, __RD(instr), targ);
        break;
    case INSTR_ADRP:
        targ = (pc & ~0xFFFull) + __DEC_ADRP(instr);
        __EMIT_MOV64_OPT(cb, __RD(instr), targ);
        break;
    case INSTR_LDR_LIT:
        targ = pc + __DEC_LDR_LIT(instr);
        __reloc_ldr_lit(instr, targ, cb);
        break;
    }
    return SILKHOOK_OK;
}
