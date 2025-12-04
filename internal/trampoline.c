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

#ifdef __KERNEL__
    #include <linux/string.h>
#else
    #include <string.h>
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * trampoline creation
 *
 * assumed layout:
 *   [0]       bti c    <- landing pad  (migth be a nop on older processors)
 *   [1.. n]   relocated instrs
 *   [n+1]     ldr x16, [pc, #8]
 *   [n+2]     br  x16
 *   [n+3]     <ret_addr_low>
 *   [n+4]     <ret_addr_high>
 * ───────────────────────────────────────────────────────────────────────────── */

int __trampoline_create(uintptr_t targ, size_t n_bytes, uintptr_t *out)
{
    void *mem = NULL;
    uint32_t code[SILKHOOK_TRAMPOLINE_MAX / 4];
    struct __codebuf cb;
    size_t n_instr = n_bytes / SILKHOOK_INSTR_SIZE;
    const uint32_t *src = (const uint32_t *) targ;
    int status;

    status = __mem_alloc_exec(SILKHOOK_TRAMPOLINE_MAX, &mem);
    if (status != SILKHOOK_OK)
        return status;

    __CODEBUF_INIT(&cb, code, sizeof(code) / sizeof(code[0]), (uintptr_t) mem);

    /*
     *  required for indirect calls on BTI-enabld devices
     *  HINT #34 / nop on older devices (as said earlier)
     */
    __CODEBUF_EMIT(&cb, __BTI_C());

    for (size_t i = 0; i < n_instr; i++)
    {
        status = __relocate(src[i], targ + (i * SILKHOOK_INSTR_SIZE), &cb);
        if (status != SILKHOOK_OK)
        {
            __mem_free(mem, SILKHOOK_TRAMPOLINE_MAX);
            return status;
        }
    }

    __EMIT_ABS_JMP(&cb, targ + n_bytes);

    memcpy(mem, code,   __CODEBUF_SIZE(&cb));
    __flush_icache(mem, __CODEBUF_SIZE(&cb));

    *out = (uintptr_t) mem;
    return SILKHOOK_OK;
}

int __trampoline_destroy(uintptr_t tramp)
{
    if (!tramp)
        return SILKHOOK_ERR_INVAL;

    return __mem_free((void *) tramp, SILKHOOK_TRAMPOLINE_MAX);
}
