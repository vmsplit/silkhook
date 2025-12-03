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
#include <pthread.h>


/*  linked list registry for hooks  */
static struct hook *g_hooks = NULL;

static void _registry_add(struct hook *h)
{
    h->next = g_hooks;
    g_hooks = h;
}

static void _registry_remove(struct hook *h)
{
    struct hook **pp = &g_hooks;
    while (*pp)
    {
        if (*pp == h)
        {
            *pp = h->next;
            h->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}


/*  mutex locks  */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOCK()    pthread_mutex_lock(&g_lock)
#define UNLOCK()  pthread_mutex_unlock(&g_lock)


size_t hook_count(void)
{
    size_t count = 0;
    LOCK();
    for (struct hook *h = g_hooks;  h; h = h->next)
        count++;
    UNLOCK();
    return count;
}


int unhook_all(void)
{
    int last_err = OK;

    LOCK();
    while (g_hooks)
    {
        struct hook *h = g_hooks;

        if (h->active)
        {
            int status = mem_make_writable((void *) h->targ, HOOK_SIZE);
            if (status == OK)
            {
                memcpy((void *) h->targ, h->orig_instrs, HOOK_SIZE);
                flush_icache((void *) h->targ, HOOK_SIZE);
                h->active = false;
            }
            else {
                last_err = status;
            }
        }

        g_hooks = h->next;
        h->next = NULL;

        if (h->trampoline)
        {
            trampoline_destroy(h->trampoline);
            h->trampoline = 0;
        }
    }
    UNLOCK();

    return last_err;
}


int init(void)
{
    return OK;
}

void shutdown(void)
{
    /*  literally just remove all hooks!  */
    unhook_all();
}

int hook_create(void *targ, void *detour, struct hook *h, void **orig)
{
    int status;

    if (!targ || !detour || !h)
        return ERR_INVALID_ARG;

    LOCK();

    memset(h, 0, sizeof(*h));

    h->targ      = (uintptr_t)targ;
    h->detour    = (uintptr_t)detour;
    h->orig_size = HOOK_SIZE;
    h->active    = false;

    memcpy(h->orig_instrs, targ, HOOK_SIZE);

    status = trampoline_create(h->targ, h->orig_size, &h->trampoline);
    if (status != OK)
    {
        UNLOCK();
        return status;
    }

    if (orig)
        *orig = (void *) h->trampoline;

    UNLOCK();
    return OK;
}

int hook_install(struct hook *h)
{
    int status;
    uint32_t hook_code[HOOK_INSTR_COUNT];
    struct codebuf cb;

    if (!h)
        return ERR_INVALID_ARG;

    LOCK();

    if (h->active)
    {
        UNLOCK();
        return ERR_EXISTS;
    }

    status = mem_make_writable((void *) h->targ, HOOK_SIZE);
    if (status != OK)
    {
        UNLOCK();
        return status;
    }

    codebuf_init(&cb, hook_code, HOOK_INSTR_COUNT, h->targ);
    emit_absolute_jump(&cb, h->detour);

    memcpy((void *) h->targ, hook_code, HOOK_SIZE);
    flush_icache((void *) h->targ, HOOK_SIZE);

    h->active = true;
    _registry_add(h);

    UNLOCK();
    return OK;
}

int hook_remove(struct hook *h)
{
    int status;

    if (!h)
        return ERR_INVALID_ARG;

    LOCK();

    if (!h->active)
    {
        UNLOCK();
        return ERR_NOT_HOOKED;
    }

    status = mem_make_writable((void *) h->targ, HOOK_SIZE);
    if (status != OK)
    {
        UNLOCK();
        return status;
    }

    memcpy((void *) h->targ, h->orig_instrs, HOOK_SIZE);
    flush_icache((void *) h->targ, HOOK_SIZE);

    h->active = false;

    UNLOCK();
    return OK;
}

int hook_destroy(struct hook *h)
{
    if (!h)
        return ERR_INVALID_ARG;

    LOCK();

    if (h->active)
    {
        int status = mem_make_writable((void *) h->targ, HOOK_SIZE);
        if (status == OK)
        {
            memcpy((void *) h->targ, h->orig_instrs, HOOK_SIZE);
            flush_icache((void *) h->targ, HOOK_SIZE);
            h->active =  false;
        }
        _registry_remove(h);
    }

    if (h->trampoline)
    {
        trampoline_destroy(h->trampoline);
        h->trampoline = 0;
    }

    UNLOCK();
    return OK;
}

int hook(void *targ, void *detour, struct hook *h, void **orig)
{
    int status;

    status = hook_create(targ, detour, h, orig);
    if (status != OK)
        return status;

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
        return status;

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
