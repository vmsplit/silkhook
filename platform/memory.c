/*
 * silkhook - miniature arm64 hooking lib
 * memory.c - linux mem operations
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include "memory.h"
#include "linux.h"
#include "../include/status.h"

#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * internal helpers
 * ───────────────────────────────────────────────────────────────────────────── */

static inline void *_page_align(void *addr)
{
    uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    return (void *)((uintptr_t)addr & ~(page_size - 1));
}

static inline size_t _page_aligned_size(void *addr, size_t len)
{
    uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    uintptr_t start     = (uintptr_t)_page_align(addr);
    uintptr_t end       = ((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1);
    return end - start;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */

int mem_protect(void *addr, size_t len, int prot)
{
    void *aligned = _page_align(addr);
    size_t aligned_len = _page_aligned_size(addr, len);

    if (mprotect(aligned, aligned_len, prot) != 0)
    {
        return ERR_PROT;
    }
    return OK;
}


int mem_make_writable(void *addr, size_t len)
{
    return mem_protect(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}


int mem_make_exec(void *addr, size_t len)
{
    return mem_protect(addr, len, PROT_READ | PROT_EXEC);
}


int mem_alloc_exec(size_t size, void **out)
{
    void *mem = mmap(
        NULL,
        size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (mem == MAP_FAILED)
    {
        return ERR_ALLOC;
    }

    *out = mem;
    return OK;
}


int mem_free(void *ptr, size_t size)
{
    if (munmap(ptr, size) != 0)
    {
        return ERR_ALLOC;
    }
    return OK;
}


void flush_icache(void *addr, size_t len)
{
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end   = start + len;

    __asm__ __volatile__("dsb ish" ::: "memory");

    for (uintptr_t p = start; p < end; p += 4)
    {
        __asm__ __volatile__("dc cvau, %0" :: "r"(p));
    }

    __asm__ __volatile__("dsb ish" ::: "memory");

    for (uintptr_t p = start; p < end; p += 4)
    {
        __asm__ __volatile__("ic ivau, %0" :: "r"(p));
    }

    __asm__ __volatile__("dsb ish" ::: "memory");
    __asm__ __volatile__("isb" ::: "memory");
}
