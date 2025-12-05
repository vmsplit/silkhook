/*
 * silkhook     - miniature arm hooking lib
 * trampoline.c - trampoline generation
 *
 * SPDX-License-Identifier: MIT
 */

#include "trampoline.h"
#include "assembler.h"
#include "../include/types.h"
#include "../include/status.h"
#include "../platform/memory.h"

#ifdef SILKHOOK_ARCH_ARM64
    #include "relocator.h"
    #include "arch.h"
#else
    #include "relocator_arm32.h"
    #include "relocator_thumb.h"
    #include "arch_arm32.h"
#endif

#ifdef __KERNEL__
    #include <linux/string.h>
#else
    #include <string.h>
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * trampoline creation
 * ───────────────────────────────────────────────────────────────────────────── */

int __trampoline_create(uintptr_t targ, size_t n_bytes, uintptr_t *out, int is_thumb)
{
    void *mem = NULL;
    uint32_t code[SILKHOOK_TRAMPOLINE_MAX / 4];
    struct __codebuf cb;
    int status;

    status = __mem_alloc_exec(SILKHOOK_TRAMPOLINE_MAX, &mem);
    if (status != SILKHOOK_OK)
        return status;

    #ifdef SILKHOOK_ARCH_ARM64
    {
        __CODEBUF_INIT(&cb, code, sizeof(code) / sizeof(code[0]), (uintptr_t)mem);

        __CODEBUF_EMIT(&cb, __BTI_C());

        size_t n_instr = n_bytes / SILKHOOK_INSTR_SIZE;
        const uint32_t *src = (const uint32_t *)targ;

        for (size_t i = 0; i < n_instr; i++)
        {
            status = __reloc(src[i], targ + (i * SILKHOOK_INSTR_SIZE), &cb);
            if (status != SILKHOOK_OK)
            {
                __mem_free(mem, SILKHOOK_TRAMPOLINE_MAX);
                return status;
            }
        }


        __EMIT_ABS_JMP(&cb, targ + n_bytes);

        memcpy(mem, code, __CODEBUF_SIZE(&cb));
        __flush_icache(mem, __CODEBUF_SIZE(&cb));
    }
    #else /*  SILKHOOK_ARCH_ARM32  */
        (void) is_thumb;

        __CODEBUF_INIT(&cb, code, sizeof(code) / sizeof(code[0]), (uintptr_t) mem);

        if (is_thumb)
        {
            uint16_t thumb_code[SILKHOOK_TRAMPOLINE_MAX / 2];
            struct __thumb_codebuf tcb;

            __THUMB_CODEBUF_INIT(&tcb, thumb_code, sizeof(thumb_code) / sizeof(thumb_code[0]), (uintptr_t) mem);

            /*  reloc orig thumb instrs  */
            status = __thumb_reloc((const uint16_t *)targ, n_bytes, targ, &tcb);
            if (status != SILKHOOK_OK)
            {
                __mem_free(mem, SILKHOOK_TRAMPOLINE_MAX);
                return status;
            }

            /* Jump back with thumb bit */
            __thumb_emit_abs_jmp(&tcb, (targ + n_bytes) | 1);

            memcpy(mem, thumb_code, __THUMB_CODEBUF_SIZE(&tcb));
            __flush_icache(mem, __THUMB_CODEBUF_SIZE(&tcb));
        }
        else {
            size_t n_instr = n_bytes / SILKHOOK_INSTR_SIZE;
            const uint32_t *src = (const uint32_t *) targ;

            for (size_t i = 0; i < n_instr; i++)
            {
                status = __arm32_reloc(src[i], targ + (i * SILKHOOK_INSTR_SIZE), &cb);
                if (status != SILKHOOK_OK)
                {
                    __mem_free(mem, SILKHOOK_TRAMPOLINE_MAX);
                    return status;
                }
            }

            /*  jump back */
            __CODEBUF_EMIT(&cb, 0xEA000000u);                  /* b +4               */
            __CODEBUF_EMIT(&cb, (uint32_t) (targ + n_bytes));  /* .long addr         */
            __CODEBUF_EMIT(&cb, 0xE51FF00Cu);                  /* ldr pc, [pc, #-12] */

            memcpy(mem, code, __CODEBUF_SIZE(&cb));
            __flush_icache(mem, __CODEBUF_SIZE(&cb));
        }
    #endif

    *out = (uintptr_t) mem;
    return SILKHOOK_OK;
}

int __trampoline_destroy(uintptr_t tramp)
{
    if (!tramp)
        return SILKHOOK_ERR_INVAL;

    return __mem_free((void *)tramp, SILKHOOK_TRAMPOLINE_MAX);
}
