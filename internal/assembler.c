/*
 * silkhook    - miniature arm64 hooking lib
 * assembler.c - code buffer
 *
 * SPDX-License-Identifier: MIT
 */

#include "assembler.h"
#include "arch.h"
#include "../include/types.h"


void codebuf_init(struct codebuf *cb, uint32_t *buf, size_t capacity, uintptr_t base)
{
    cb->code     = buf;
    cb->capacity = capacity;
    cb->count    = 0;
    cb->base     = base;
}

void codebuf_emit(struct codebuf *cb, uint32_t instr)
{
    if (cb->count < cb->capacity)
    {
        cb->code[cb->count++] = instr;
    }
}

void codebuf_emit_addr(struct codebuf *cb, uintptr_t addr)
{
    codebuf_emit(cb, (uint32_t)(addr & 0xFFFFFFFF));
    codebuf_emit(cb, (uint32_t)(addr >> 32));
}

uintptr_t codebuf_pc(const struct codebuf *cb)
{
    return cb->base + (cb->count * INSTR_SIZE);
}

size_t codebuf_size(const struct codebuf *cb)
{
    return cb->count * INSTR_SIZE;
}

void emit_absolute_jump(struct codebuf *cb, uintptr_t target)
{
    /*
     * ldr x16, [pc, #8]
     * br  x16
     * <target_low>
     * <target_high>
     */
    codebuf_emit(cb, assemble_ldr_literal(16, 8));
    codebuf_emit(cb, assemble_br(16));
    codebuf_emit_addr(cb, target);
}
