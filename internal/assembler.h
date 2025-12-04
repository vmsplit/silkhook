/*
 * silkhook    - miniature arm64 hooking lib
 * assembler. h - code generation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_ASSEMBLER_H_
#define _SILKHOOK_ASSEMBLER_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    #include <stddef.h>
#endif

#include "arch.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * code buffer
 * ───────────────────────────────────────────────────────────────────────────── */

struct __codebuf {
    uint32_t    *buf;
    size_t      cap;
    size_t      len;
    uintptr_t   pc;
};

#define __CODEBUF_INIT(cb, _buf, _cap, _pc) do { \
    (cb)->buf = (_buf); \
    (cb)->cap = (_cap); \
    (cb)->len = 0; \
    (cb)->pc  = (_pc);  \
} while (0)

#define __CODEBUF_EMIT(cb, instr) do { \
    if ((cb)->len < (cb)->cap)         \
        (cb)->buf[(cb)->len++] = (instr); \
} while (0)

#define __CODEBUF_EMIT_ADDR(cb, addr) do { \
    __CODEBUF_EMIT((cb), (uint32_t)((addr)  & 0xFFFFFFFF)); \
    __CODEBUF_EMIT((cb), (uint32_t)((addr) >> 32));         \
} while (0)

#define __CODEBUF_PC(cb) \
    ((cb)->pc + ((cb)->len * 4))

#define __CODEBUF_SIZE(cb) \
    ((cb)->len * 4)


/* ─────────────────────────────────────────────────────────────────────────────
 * emitters
 * ───────────────────────────────────────────────────────────────────────────── */

#define __EMIT_MOV64(cb, reg, imm) do { \
    __CODEBUF_EMIT((cb), __MOVZ((reg), ((imm) >>  0) & 0xFFFF,  0)); \
    __CODEBUF_EMIT((cb), __MOVK((reg), ((imm) >> 16) & 0xFFFF, 16)); \
    __CODEBUF_EMIT((cb), __MOVK((reg), ((imm) >> 32) & 0xFFFF, 32)); \
    __CODEBUF_EMIT((cb), __MOVK((reg), ((imm) >> 48) & 0xFFFF, 48)); \
} while (0)

#define __EMIT_MOV64_OPT(cb, reg, imm) \
    __emit_mov64_opt((cb), (reg), (imm))

#define __EMIT_ABS_JMP(cb, targ) do {  \
    __CODEBUF_EMIT((cb), __LDR_LIT(16, 8)); \
    __CODEBUF_EMIT((cb), __BR(16));    \
    __CODEBUF_EMIT_ADDR((cb), (targ)); \
} while (0)

#define __EMIT_SAFE_JMP(cb, targ) do { \
    __CODEBUF_EMIT((cb), __B(8));      \
    __CODEBUF_EMIT((cb), __RET());     \
    __CODEBUF_EMIT((cb), __PUSH(0));   \
    __CODEBUF_EMIT((cb), __MOVZ(0, ((targ) >>  0) & 0xFFFF,  0)); \
    __CODEBUF_EMIT((cb), __MOVK(0, ((targ) >> 16) & 0xFFFF, 16)); \
    __CODEBUF_EMIT((cb), __MOVK(0, ((targ) >> 32) & 0xFFFF, 32)); \
    __CODEBUF_EMIT((cb), __MOVK(0, ((targ) >> 48) & 0xFFFF, 48)); \
    __CODEBUF_EMIT((cb), __BR(0));     \
    __CODEBUF_EMIT((cb), __POP(0));    \
} while (0)

static inline void __emit_mov64_opt(struct __codebuf *cb, unsigned reg, uint64_t imm)
{
    int first = 1;
    unsigned shift;

    if (imm == 0) {
        __CODEBUF_EMIT(cb, __MOVZ(reg, 0, 0));
        return;
    }

    for (shift = 0; shift < 64; shift += 16) {
        uint16_t chunk = (imm >> shift) & 0xFFFF;
        if (chunk != 0) {
            if (first) {
                __CODEBUF_EMIT(cb, __MOVZ(reg, chunk, shift));
                first = 0;
            } else {
                __CODEBUF_EMIT(cb, __MOVK(reg, chunk, shift));
            }
        }
    }
}


#endif /* _SILKHOOK_ASSEMBLER_H_ */
