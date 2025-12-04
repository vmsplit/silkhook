/*
 * silkhook   - miniature arm64 hooking lib
 * silkhook.c - core implementation
 *
 * SPDX-License-Identifier: MIT
 */

#include "include/silkhook.h"
#include "include/status.h"
#include "include/types.h"
#include "internal/arch.h"
#include "internal/assembler.h"
#include "internal/trampoline.h"
#include "platform/memory.h"

#ifdef __KERNEL__
    #include <linux/mutex.h>
    #include <linux/string.h>
    static DEFINE_MUTEX(__g_lock);
    #define __LOCK()    mutex_lock(&__g_lock)
    #define __UNLOCK()  mutex_unlock(&__g_lock)
#else
    #include <pthread.h>
    #include <string.h>
    static pthread_mutex_t __g_lock = PTHREAD_MUTEX_INITIALIZER;
    #define __LOCK()    pthread_mutex_lock(&__g_lock)
    #define __UNLOCK()  pthread_mutex_unlock(&__g_lock)
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * registry
 * ───────────────────────────────────────────────────────────────────────────── */

static struct silkhook_hook *__g_hooks = NULL;

#define __REG_ADD(h) do { \
    (h)->next = __g_hooks; \
    __g_hooks = (h); \
} while (0)

static void __reg_del(struct silkhook_hook *h)
{
    struct silkhook_hook **pp = &__g_hooks;
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

static struct silkhook_hook *__reg_find(uintptr_t targ)
{
    for (struct silkhook_hook *h = __g_hooks; h; h = h->next)
        if (h->targ == targ)
            return h;
    return NULL;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * internal write helper
 * ───────────────────────────────────────────────────────────────────────────── */

static int __write_hook(uintptr_t targ, const void *code, size_t len)
{
#ifdef __KERNEL__
    return __mem_write_text((void *) targ, code, len);
#else
    int r = __mem_make_rw((void *) targ, len);
    if (r != SILKHOOK_OK)
        return r;
    memcpy((void *) targ, code, len);
    __flush_icache((void *) targ, len);
    return SILKHOOK_OK;
#endif
}


/* ─────────────────────────────────────────────────────────────────────────────
 * lifecycle
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_init(void)
{
    return SILKHOOK_OK;
}

void silkhook_shutdown(void)
{
    silkhook_unhook_all();
}


/* ─────────────────────────────────────────────────────────────────────────────
 * staged API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_create(void *targ, void *detour, struct silkhook_hook *h, void **orig)
{
    int r;

    if (!targ || !detour || !h)
        return SILKHOOK_ERR_INVAL;

    __LOCK();
    memset(h, 0, sizeof(*h));

    h->targ      = (uintptr_t) targ;
    h->detour    = (uintptr_t) detour;
    h->orig_size = SILKHOOK_HOOK_N_BYTE;
    h->active    = false;
    h->next      = NULL;

    memcpy(h->orig, targ, SILKHOOK_HOOK_N_BYTE);

    r = __trampoline_create(h->targ, h->orig_size, &h->trampoline);
    if (r != SILKHOOK_OK)
    {
        __UNLOCK();
        return r;
    }

    if (orig)
        *orig = (void *) h->trampoline;

    __UNLOCK();
    return SILKHOOK_OK;
}

int silkhook_enable(struct silkhook_hook *h)
{
    uint32_t code[SILKHOOK_HOOK_N_INSTR];
    int r;

    if (!h)
        return SILKHOOK_ERR_INVAL;

    __LOCK();

    if (h->active || __reg_find(h->targ))
    {
        __UNLOCK();
        return SILKHOOK_ERR_EXISTS;
    }

    __ABS_JMP(code, h->detour);

    r = __write_hook(h->targ, code, SILKHOOK_HOOK_N_BYTE);
    if (r != SILKHOOK_OK)
    {
        __UNLOCK();
        return r;
    }

    h->active = true;
    __REG_ADD(h);

    __UNLOCK();
    return SILKHOOK_OK;
}

int silkhook_disable(struct silkhook_hook *h)
{
    int r;

    if (!h)
        return SILKHOOK_ERR_INVAL;

    __LOCK();

    if (!h->active)
    {
        __UNLOCK();
        return SILKHOOK_ERR_NOENT;
    }

    r = __write_hook(h->targ, h->orig, SILKHOOK_HOOK_N_BYTE);
    if (r != SILKHOOK_OK)
    {
        __UNLOCK();
        return r;
    }

    h->active = false;
    __reg_del(h);

    __UNLOCK();
    return SILKHOOK_OK;
}

int silkhook_destroy(struct silkhook_hook *h)
{
    if (!h)
        return SILKHOOK_ERR_INVAL;

    __LOCK();

    if (h->active)
    {
        __write_hook(h->targ, h->orig, SILKHOOK_HOOK_N_BYTE);
        h->active = false;
        __reg_del(h);
    }

    if (h->trampoline)
    {
        __trampoline_destroy(h->trampoline);
        h->trampoline = 0;
    }

    __UNLOCK();
    return SILKHOOK_OK;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * simple API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_hook(void *targ, void *detour, struct silkhook_hook *h, void **orig)
{
    int r = silkhook_create(targ, detour, h, orig);
    if (r != SILKHOOK_OK)
        return r;

    r = silkhook_enable(h);
    if (r != SILKHOOK_OK)
    {
        silkhook_destroy(h);
        return r;
    }

    return SILKHOOK_OK;
}

int silkhook_unhook(struct silkhook_hook *h)
{
    int r = silkhook_disable(h);
    if (r != SILKHOOK_OK && r != SILKHOOK_ERR_NOENT)
        return r;
    return silkhook_destroy(h);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * batch API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_hook_batch(struct silkhook_desc *descs, size_t n, struct silkhook_hook *hooks)
{
    int r;
    size_t i;

    if (!descs || !hooks || n == 0)
        return SILKHOOK_ERR_INVAL;

    for (i = 0; i < n; i++)
    {
        r = silkhook_hook(descs[i].targ, descs[i].detour, &hooks[i], descs[i].orig);
        if (r != SILKHOOK_OK)
            goto fail;
    }
    return SILKHOOK_OK;

fail:
    while (i--)
        silkhook_unhook(&hooks[i]);
    return r;
}

int silkhook_unhook_batch(struct silkhook_hook *hooks, size_t n)
{
    int r, last = SILKHOOK_OK;

    if (!hooks || n == 0)
        return SILKHOOK_ERR_INVAL;

    for (size_t i = 0; i < n; i++)
    {
        r = silkhook_unhook(&hooks[i]);
        if (r != SILKHOOK_OK)
            last = r;
    }
    return last;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * query API
 * ───────────────────────────────────────────────────────────────────────────── */

size_t silkhook_count(void)
{
    size_t n = 0;
    __LOCK();
    for (struct silkhook_hook *h = __g_hooks; h; h = h->next)
        n++;
    __UNLOCK();
    return n;
}

struct silkhook_hook *silkhook_find(void *targ)
{
    struct silkhook_hook *h;
    __LOCK();
    h = __reg_find((uintptr_t)targ);
    __UNLOCK();
    return h;
}

int silkhook_unhook_all(void)
{
    int last = SILKHOOK_OK;

    __LOCK();
    while (__g_hooks)
    {
        struct silkhook_hook *h = __g_hooks;

        if (h->active)
        {
            int r = __write_hook(h->targ, h->orig, SILKHOOK_HOOK_N_BYTE);
            if (r != SILKHOOK_OK)
                last = r;
            h->active = false;
        }

        __g_hooks = h->next;
        h->next = NULL;

        if (h->trampoline)
        {
            __trampoline_destroy(h->trampoline);
            h->trampoline = 0;
        }
    }
    __UNLOCK();

    return last;
}
