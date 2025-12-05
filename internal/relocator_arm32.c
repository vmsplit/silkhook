/*
 * silkhook          - miniature arm hooking lib
 * relocator_arm32.c - arm32 instruction relocation
 *
 * SPDX-License-Identifier: MIT
 */

 #include "relocator_arm32.h"
 #include "../include/status.h"


 /* ─────────────────────────────────────────────────────────────────────────────
  * arm32 code buffer helpers
  *
  * reuse codebuf from assembler.h but with arm32-specific emittrs
  * ───────────────────────────────────────────────────────────────────────────── */

#define __ARM32_CODEBUF_EMIT(b, instr) __CODEBUF_EMIT((cb), (instr))

static inline void __arm32_emit_mov32(struct __codebuf *cb, unsigned reg, uint32_t imm)
{
    __ARM32_CODEBUF_EMIT(cb, __ARM32_MOVW(reg, imm & 0xFFFFu));
    __ARM32_CODEBUF_EMIT(cb, __ARM32_MOVT(reg, (imm >> 16) & 0xFFFFu));
}

static inline void __arm32_emit_abs_jmp(struct __codebuf *cb, uint32_t targ)
{
    __ARM32_CODEBUF_EMIT(cb, 0xEA000000u);
    __ARM32_CODEBUF_EMIT(cb, targ);
    __ARM32_CODEBUF_EMIT(cb, 0xE51FF00Cu);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * reloc handlers
 * ───────────────────────────────────────────────────────────────────────────── */

static void __arm32_reloc_ldr_lit(uint32_t instr, uintptr_t targ, struct __codebuf *cb)
{
    unsigned rt = __ARM32_RD(instr);

    /*  orig:   ldr Rt, [pc, #off]
     *  reloc: movw Rt, #(targ & 0xFFFF)
     *         movt Rt, #(targ >> 16)
     *         ldr  Rt, [Rt]  */
    __arm32_emit_mov32(cb, rt, (uint32_t) targ);
    __ARM32_CODEBUF_EMIT(cb, 0xE5900000u | (rt << 16) | (rt << 12));
}

static void __arm32_reloc_adr(uint32_t instr, uintptr_t targ, struct __codebuf *cb)
{
    unsigned rd   = __ARM32_RD(instr);
    uint32_t cond = instr & 0xF0000000u;

    /*  orig:  adr Rd, label  (add/sub Rd, pc, #imm)
     *  reloc: movw Rd, #(targ &0xFFFF)
     *         movt Rd, #(targ >> 16)  */
    __ARM32_CODEBUF_EMIT(cb, cond | (__ARM32_MOVW(rd, targ & 0xFFFFu) & 0x0FFFFFFFu));
    __ARM32_CODEBUF_EMIT(cb, cond | (__ARM32_MOVT(rd, (targ >> 16) & 0xFFFu)));
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public
 * ───────────────────────────────────────────────────────────────────────────── */

int __arm32_reloc(uint32_t instr, uintptr_t pc, struct __codebuf *cb)
{
    enum __arm32_instr_kind k = __ARM32_CLASSIFY(instr);
    uintptr_t targ;
    uint32_t cond;

    switch (k)
        {
        case ARM32_INSTR_OTHER:
            __ARM32_CODEBUF_EMIT(cb, instr);
            break;
        case ARM32_INSTR_B:
            targ = pc + __ARM32_DEC_B(instr);
            cond = instr & 0xF0000000u;
            if ((cond >> 28) == 0xE)
            {
                /*  just absolute jump here  */
                __arm32_emit_abs_jmp(cb, (uint32_t) targ);
            }
            else {
                /*  invert & skip here  */
                uint32_t inv_cond = cond ^ 0x10000000u;
                __ARM32_CODEBUF_EMIT(cb, inv_cond | 0x0A000002u);
                __arm32_emit_abs_jmp(cb, (uint32_t) targ);
            }
            break;
        case ARM32_INSTR_BL:
            targ = pc + __ARM32_DEC_B(instr);
            cond = instr & 0xF0000000u;
            __ARM32_CODEBUF_EMIT(cb, cond | 0x028FE00Cu);
            __arm32_emit_abs_jmp(cb, (uint32_t)targ);
            break;
        case ARM32_INSTR_LDR_LIT:
            targ = pc + __ARM32_DEC_LDR_LIT(instr);
            __arm32_reloc_ldr_lit(instr, targ, cb);
            break;
        case ARM32_INSTR_ADR:
            /*  decode ADR  (ADD Rd, PC, #imm /
             *               SUB Rd, PC,  #imm)  */
            {
                uint32_t imm = instr & 0xFFu;
                uint32_t rot = ((instr >> 8) & 0xFu) * 2;
                int32_t off = (imm >> rot) | (imm << (32 - rot));

                if ((instr & 0x00F00000u) == 0x00400000u)
                    off = -off;

                targ = pc + 8 + off;
            }
            __arm32_reloc_adr(instr, targ, cb);
            break;
        }
        return SILKHOOK_OK;
}
