/*
 * silkhook    - miniature arm64 hooking lib
 * assembler.h - code gen utils
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ASSEMBLER_H_
#define _ASSEMBLER_H_

#include <stdint.h>
#include <stddef.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * code buffer - tiny code emitter
 * ───────────────────────────────────────────────────────────────────────────── */

struct codebuf {
    uint32_t    *code;
    size_t      capacity;
    size_t      count;
    uintptr_t   base;
};


void codebuf_init(struct codebuf *cb, uint32_t *buf, size_t capacity, uintptr_t base);
void codebuf_emit(struct codebuf *cb, uint32_t instr);
void codebuf_emit_addr(struct codebuf *cb, uintptr_t addr);

uintptr_t codebuf_pc(const struct codebuf *cb);
size_t codebuf_size(const struct codebuf *cb);

void emit_absolute_jump(struct codebuf *cb, uintptr_t target);


#endif /* _ASSEMBLER_H_ */
