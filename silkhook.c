/*
 * silkhook   - miniature arm64 hooking lib
 * silkhook.c - core API
 *
 * SPDX-License-Identifier: MIT
 */

#include "include/silkhook.h"
#include "include/status.h"
#include "include/types.h"
#include "internal/trampoline.h"
#include "internal/assembler.h"
#include "internal/arch.h"
#include "platform/memory.h"

#include <string.h>


int init(void)
{
    return OK;
}

void shutdown(void)
{
}

int hook_create(void *targ, void *detour, struct hook *h, void **orig)
{
    int status;

    if (! targ || !detour || !h)
    {
        return ERR_INVALID_ARG;
    }

    memset(h, 0, sizeof(struct hook));

    h->targ    = (uintptr_t)targ;
    h->detour    = (uintptr_t)detour;
    h->orig_size = HOOK_SIZE;
    h->active    = false;

    memcpy(h->orig_instrs, targ, HOOK_SIZE);

    status = trampoline_create(h->targ, h->orig_size, &h->trampoline);
    if (status != OK)
    {
        return status;
    }

    if (orig)
    {
        *orig = (void *)h->trampoline;
    }

    return OK;
}

int hook_install(struct hook *h)
{
    int status;

    if (!h)
    {
        return ERR_INVALID_ARG;
    }
    if (h->active)
    {
        return ERR_EXISTS;
    }

    status = mem_make_writable((void *)h->targ, HOOK_SIZE);
    if (status != OK)
    {
        return status;
    }

    uint32_t hook_code[HOOK_INSTR_COUNT];
    struct codebuf cb;
    codebuf_init(&cb, hook_code, HOOK_INSTR_COUNT, h->targ);
    emit_absolute_jump(&cb, h->detour);

    memcpy((void *)h->targ, hook_code, HOOK_SIZE);
    flush_icache((void *)h->targ, HOOK_SIZE);

    h->active = true;
    return OK;
}

int hook_remove(struct hook *h)
{
    int status;

    if (!h)
    {
        return ERR_INVALID_ARG;
    }
    if (!h->active)
    {
        return ERR_NOT_HOOKED;
    }

    status = mem_make_writable((void *)h->targ, HOOK_SIZE);
    if (status != OK)
    {
        return status;
    }

    memcpy((void *)h->targ, h->orig_instrs, HOOK_SIZE);
    flush_icache((void *)h->targ, HOOK_SIZE);

    h->active = false;
    return OK;
}

int hook_destroy(struct hook *h)
{
    if (!h)
    {
        return ERR_INVALID_ARG;
    }
    if (h->active)
    {
        hook_remove(h);
    }
    if (h->trampoline)
    {
        trampoline_destroy(h->trampoline);
        h->trampoline = 0;
    }

    return OK;
}

int hook(void *targ, void *detour, struct hook *h, void **orig)
{
    int status;

    status = hook_create(targ, detour, h, orig);
    if (status != OK)
    {
        return status;
    }

    status = hook_install(h);
    if (status != OK)
    {
        hook_destroy(h);
        return status;
    }

    return OK;
}

int unhook(struct hook *h)
{
    int status;

    status = hook_remove(h);
    if (status != OK && status != ERR_NOT_HOOKED)
    {
        return status;
    }

    return hook_destroy(h);
}

int hook_batch(struct hook_desc *descs, size_t count, struct hook *hooks)
{
    int status;
    size_t i;

    if (!descs || !hooks || count == 0)
        return ERR_INVALID_ARG;

    for (i = 0; i < count; i++)
    {
        status = hook(descs[i].targ, descs[i].detour, &hooks[i], descs[i].orig);
        if (status != OK)
            goto rollback;
    }

    return OK;

rollback:
    while (i-- >0)
        unhook(&hooks[i]);
    return status;
}

int unhook_batch(struct hook *hooks, size_t count)
{
    int status, last_err = OK;

    if (!hooks || count == 0)
        return ERR_INVALID_ARG;

    for (size_t i = 0; i < count; i++)
    {
        status = unhook(&hooks[i]);
        if (status != OK)
            last_err = status;
    }

    return last_err;
}
