/*
 * silkhook     - miniature arm64 hooking lib
 * trampoline. c - trampoline gen
 *
 * SPDX-License-Identifier: MIT
 */

#include "trampoline.h"
#include "relocator.h"
#include "assembler.h"
#include "../include/types.h"
#include "../include/status.h"
#include "../platform/memory.h"

#include <string.h>


int trampoline_create(uintptr_t target, size_t hook_size, uintptr_t *out)
{
    int status;
    void *mem = NULL;
    size_t instr_count = hook_size / INSTR_SIZE;

    status = mem_alloc_exec(TRAMPOLINE_MAX, &mem);
    if (status != OK)
    {
        return status;
    }

    uint32_t code[TRAMPOLINE_MAX / INSTR_SIZE];
    struct codebuf cb;
    codebuf_init(&cb, code, sizeof(code) / sizeof(code[0]), (uintptr_t)mem);

    const uint32_t *src = (const uint32_t *)target;
    for (size_t i = 0; i < instr_count; i++)
    {
        uintptr_t instr_pc = target + (i * INSTR_SIZE);
        status = relocate_instr(src[i], instr_pc, &cb);
        if (status != OK)
        {
            mem_free(mem, TRAMPOLINE_MAX);
            return status;
        }
    }

    emit_absolute_jump(&cb, target + hook_size);
    memcpy(mem, code, codebuf_size(&cb));
    flush_icache(mem, codebuf_size(&cb));
    *out = (uintptr_t)mem;

    return OK;
}


int trampoline_destroy(uintptr_t trampoline)
{
    if (trampoline == 0)
    {
        return ERR_INVALID_ARG;
    }
    return mem_free((void *)trampoline, TRAMPOLINE_MAX);
}
