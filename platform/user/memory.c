/*
 * silkhook - miniature arm64 hooking lib
 * memory.c - userspace memory ops
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include "../memory.h"
#include "../../include/status.h"

#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * asm impl
 * ───────────────────────────────────────────────────────────────────────────── */

extern void __silkhook_flush_icache(void *addr, size_t len);


/* ─────────────────────────────────────────────────────────────────────────────
 * internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static inline uintptr_t __page_size(void)
{
    return (uintptr_t) sysconf(_SC_PAGESIZE);
}

static inline void *__page_start(void *p)
{
    return (void *) ((uintptr_t) p & ~(__page_size() - 1));
}

static inline size_t __page_span(void *p, size_t len)
{
    uintptr_t ps = __page_size();
    uintptr_t s = (uintptr_t)p & ~(ps - 1);
    uintptr_t e = ((uintptr_t)p + len + ps - 1) & ~(ps - 1);
    return e - s;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */

int __mem_make_rw(void *addr, size_t len)
{
    if (mprotect(__page_start(addr), __page_span(addr, len), PROT_READ | PROT_WRITE | PROT_EXEC))
        return SILKHOOK_ERR_PROT;
    return SILKHOOK_OK;
}

int __mem_make_rx(void *addr, size_t len)
{
    if (mprotect(__page_start(addr), __page_span(addr, len), PROT_READ | PROT_EXEC))
        return SILKHOOK_ERR_PROT;
    return SILKHOOK_OK;
}

int __mem_alloc_exec(size_t size, void **out)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return SILKHOOK_ERR_NOMEM;

    *out = p;
    return SILKHOOK_OK;
}

int __mem_free(void *ptr, size_t size)
{
    if (munmap(ptr, size))
        return SILKHOOK_ERR_NOMEM;
    return SILKHOOK_OK;
}

void __flush_icache(void *addr, size_t len)
{
    __silkhook_flush_icache(addr, len);
}
