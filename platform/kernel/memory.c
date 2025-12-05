/*
 * silkhook - miniature arm64 hooking lib
 * memory.c - kernel memory operations
 *
 * SPDX-License-Identifier: MIT
 */

#include "../memory.h"
#include "../../include/status.h"
#include "ksyms.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * resolved symbols (cached)
 * ───────────────────────────────────────────────────────────────────────────── */

static void *(*__module_alloc_fn)(unsigned long) = NULL;
static int (*__set_memory_x_fn)(unsigned long, int) = NULL;
static int (*__patch_text_fn)(void *addr, u32 insn) = NULL;

static int __resolve_syms(void)
{
    if (!__module_alloc_fn)
    {
        __module_alloc_fn = silkhook_ksym("module_alloc");
        if (! __module_alloc_fn)
            return -ENOENT;
    }
    if (!__set_memory_x_fn)
    {
        __set_memory_x_fn = silkhook_ksym("set_memory_x");
        if (! __set_memory_x_fn)
            return -ENOENT;
    }
    if (! __patch_text_fn)
    {
        __patch_text_fn = silkhook_ksym("aarch64_insn_patch_text_nosync");
        if (! __patch_text_fn)
            return -ENOENT;
    }
    return 0;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */

int __mem_make_rw(void *addr, size_t len)
{
    (void)addr; (void)len;
    return SILKHOOK_OK;
}

int __mem_make_rx(void *addr, size_t len)
{
    (void)addr; (void)len;
    return SILKHOOK_OK;
}

int __mem_alloc_exec(size_t size, void **out)
{
    void *mem;
    int ret;

    ret = __resolve_syms();
    if (ret)
        return SILKHOOK_ERR_PROT;

    mem = __module_alloc_fn(size);
    if (! mem)
        return SILKHOOK_ERR_NOMEM;

    memset(mem, 0, size);

    flush_icache_range((unsigned long)mem, (unsigned long)mem + size);
    ret = __set_memory_x_fn((unsigned long)mem, (size + PAGE_SIZE - 1) >> PAGE_SHIFT);
    if (ret)
    {
        vfree(mem);
        return SILKHOOK_ERR_PROT;
    }

    *out = mem;
    return SILKHOOK_OK;
}

int __mem_free(void *ptr, size_t size)
{
    (void)size;
    if (ptr)
        vfree(ptr);
    return SILKHOOK_OK;
}

int __mem_write_code(void *dst, const void *src, size_t len)
{
    /*  __mem_write_text  uses aarch64_insn_patch_text_nosync  */
    return __mem_write_text(dst, src, len);
}

void __flush_icache(void *addr, size_t len)
{
    flush_icache_range((unsigned long)addr, (unsigned long)addr + len);
}

int __mem_write_text(void *dst, const void *src, size_t len)
{
    const u32 *instrs = src;
    size_t n = len / sizeof(u32);
    size_t i;
    int ret;

    ret = __resolve_syms();
    if (ret)
        return SILKHOOK_ERR_PROT;

    for (i = 0; i < n; i++)
    {
        ret = __patch_text_fn((u32 *)dst + i, instrs[i]);
        if (ret)
        {
            pr_err("silkhook: patch_text failure @  offset[%zu]: %d\n", i * 4, ret);
            return SILKHOOK_ERR_PROT;
        }
    }

    return SILKHOOK_OK;
}
