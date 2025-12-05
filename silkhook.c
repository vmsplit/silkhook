/*
 * silkhook   - miniature arm hooking lib
 * silkhook.c - core implementation
 *
 * SPDX-License-Identifier: MIT
 */

#ifdef __KERNEL__
    #include <linux/string.h>
    #include <linux/spinlock.h>
#else
    #include <string.h>
    #include <pthread.h>
#endif

#include "include/silkhook.h"
#include "include/types.h"
#include "include/status.h"
#include "internal/trampoline.h"
#include "platform/memory.h"

#ifdef SILKHOOK_ARCH_ARM64
    #include "internal/arch.h"
#else
    #include "internal/arch_arm32.h"
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * locking
 * ───────────────────────────────────────────────────────────────────────────── */

#ifdef __KERNEL__
    static DEFINE_SPINLOCK(__silkhook_lock);
    static unsigned long   __silkhook_flags;
    #define __LOCK()     spin_lock_irqsave(&__silkhook_lock, __silkhook_flags)
    #define __UNLOCK()   spin_unlock_irqrestore(&__silkhook_lock, __silkhook_flags)
#else
    static pthread_mutex_t __silkhook_lock = PTHREAD_MUTEX_INITIALIZER;
    #define __LOCK()     pthread_mutex_lock(&__silkhook_lock)
    #define __UNLOCK()   pthread_mutex_unlock(&__silkhook_lock)
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * hook registry
 * ───────────────────────────────────────────────────────────────────────────── */

static struct silkhook_hook *__reg = NULL;

static struct silkhook_hook *__reg_find(uintptr_t targ)
{
    struct silkhook_hook *cur = __reg;

    #ifdef SILKHOOK_ARCH_ARM32
        targ = __STRIP_THUMB(targ);
    #endif

    while (cur)
    {
    #ifdef SILKHOOK_ARCH_ARM32
        if (__STRIP_THUMB(cur->targ) == targ)
    #else
        if (cur->targ == targ)
    #endif
            return cur;

        cur = cur->next;
    }
    return NULL;
}

#define __REG_ADD(h)       do { (h)->next = __reg; __reg = (h); } while (0)
#define __REG_REMOVE(h)    do {            \
    if (__reg == (h)) __reg = (h)->next;   \
    else {                                 \
        struct silkhook_hook *__p = __reg; \
        while (__p && __p->next != (h)) __p = __p->next; \
        if (__p) __p->next = (h)->next;    \
    }                                      \
} while (0)


/* ─────────────────────────────────────────────────────────────────────────────
 * mem writing helpers (plat-spec)
 * ───────────────────────────────────────────────────────────────────────────── */

extern int __mem_write_code(void *dst, const void *src, size_t len);
extern void __flush_icache(void *addr, size_t len);

static int __write_hook(uintptr_t targ, const void *code, size_t len)
{
    int r = __mem_write_code((void *) targ, code, len);
    if (r == SILKHOOK_OK)
        __flush_icache((void *) targ, len);
    return r;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public api
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_init(void)
{
    return SILKHOOK_OK;
}

void silkhook_shutdown(void)
{
    /*  nothing to do  */
}

int silkhook_create(void *targ, void *detour, struct silkhook_hook *h, void **orig)
{
    int r;
    uintptr_t real_targ;

    if (!targ || !detour || !h)
        return SILKHOOK_ERR_INVAL;

    __LOCK();
    memset(h, 0, sizeof(*h));

    #ifdef SILKHOOK_ARCH_ARM32
        h->is_thumb = __IS_THUMB(targ);
        real_targ = __STRIP_THUMB((uintptr_t) targ);
        h->targ = real_targ;
        h->detour = (uintptr_t) detour;
    #else
        real_targ = (uintptr_t) targ;
        h->targ = real_targ;
        h->detour = (uintptr_t) detour;
    #endif

    h->orig_size = SILKHOOK_HOOK_N_BYTE;
    h->active = false;
    h->next = NULL;

    memcpy(h->orig, (void *) real_targ, SILKHOOK_HOOK_N_BYTE);

    r = __trampoline_create(real_targ, h->orig_size, &h->trampoline,
                            #ifdef SILKHOOK_ARCH_ARM32
                              h->is_thumb
                            #else
                              0
                            #endif
    );

    if (r != SILKHOOK_OK)
    {
        __UNLOCK();
        return r;
    }

    if (orig)
    {
    #ifdef SILKHOOK_ARCH_ARM32
        *orig = (void *) (h->is_thumb ? __ADD_THUMB(h->trampoline) : h->trampoline);
    #else
        *orig = (void *) h->trampoline;
    #endif
    }

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
        __UNLOCK();
        return SILKHOOK_ERR_STATE;
    }

    __trampoline_destroy(h->trampoline);
    memset(h, 0, sizeof(*h));

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

    #ifdef SILKHOOK_ARCH_ARM64
    __ABS_JMP(code, h->detour);
    #else
    if (h->is_thumb)
        __THUMB_ABS_JMP(code, h->detour);
    else
        __ARM32_ABS_JMP(code, __STRIP_THUMB(h->detour));
    #endif

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
        return SILKHOOK_ERR_STATE;
    }

    r = __write_hook(h->targ, h->orig, h->orig_size);
    if (r != SILKHOOK_OK)
    {
        __UNLOCK();
        return r;
    }

    h->active = false;
    __REG_REMOVE(h);

    __UNLOCK();
    return SILKHOOK_OK;
}

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
    if (r != SILKHOOK_OK)
        return r;

    return silkhook_destroy(h);
}

bool silkhook_is_active(struct silkhook_hook *h)
{
    if (!h)
        return false;
    return h->active;
}

const char *silkhook_strerror(int err)
{
    switch (err)
    {
    case SILKHOOK_OK:           return "success";
    case SILKHOOK_ERR_NOMEM:    return "out of memory";
    case SILKHOOK_ERR_PROT:     return "permission denied fuck you";
    case SILKHOOK_ERR_INVAL:    return "invalid argument";
    case SILKHOOK_ERR_EXISTS:   return "hook already exists";
    case SILKHOOK_ERR_NOENT:    return "hook not found";
    case SILKHOOK_ERR_STATE:    return "invalid state";
    case SILKHOOK_ERR_INSTR:    return "unsupported instruction";
    default:                    return "unknown error";
    }
}
