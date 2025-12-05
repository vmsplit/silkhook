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

    (void) is_thumb;

    status = __mem_alloc_exec(SILKHOOK_TRAMPOLINE_MAX, &mem);
    if (status != SILKHOOK_OK)
        return status;

    __CODEBUF_INIT(&cb, code, sizeof(code)  /  sizeof(code[0]), (uintptr_t) mem);

    #ifdef SILKHOOK_ARCH_ARM64
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

    #else /*  SILKHOOK_ARCH_ARM32  */

        if (is_thumb)
        {
            /*  just copy the orig bytes and jmp back  */
            const uint16_t *src = (const uint16_t *) targ;
            size_t n_hw = n_bytes / 2;

            /*  copied orig instrs ( halfword pairs packed into uint32_t ) */
            for (size_t i = 0; i < n_hw; i += 2)
            {
                uint32_t packed;
                if (i + 1 < n_hw)
                    packed = __THUMB_PACK(src[i], src[i + 1]);
                else
                    packed = __THUMB_PACK(src[i], __THUMB_NOP);
                __CODEBUF_EMIT(&cb, packed);
            }

            /*  targ will need thumb bit so jump back  */
            uint32_t jmp[3];
            __THUMB_ABS_JMP(jmp, __ADD_THUMB(targ + n_bytes));
            __CODEBUF_EMIT(&cb, jmp[0]);
            __CODEBUF_EMIT(&cb, jmp[1]);
            __CODEBUF_EMIT(&cb, jmp[2]);
        }
        else {
            size_t n_instr = n_bytes / SILKHOOK_INSTR_SIZE;
            const uint32_t *src = (const uint32_t *)targ;

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
            __CODEBUF_EMIT(&cb, 0xEA000000u);                 /* b +4               */
            __CODEBUF_EMIT(&cb, (uint32_t)(targ + n_bytes));  /* .long addr         */
            __CODEBUF_EMIT(&cb, 0xE51FF00Cu);                 /* ldr pc, [pc, #-12] */
        }
    #endif

    memcpy(mem, code, __CODEBUF_SIZE(&cb));
    __flush_icache(mem, __CODEBUF_SIZE(&cb));

    *out = (uintptr_t)mem;
    return SILKHOOK_OK;
}

int __trampoline_destroy(uintptr_t tramp)
{
    if (!tramp)
        return SILKHOOK_ERR_INVAL;

    return __mem_free((void *)tramp, SILKHOOK_TRAMPOLINE_MAX);
}
