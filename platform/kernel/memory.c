/*
 * silkhook - miniature arm64 hooking lib
 * memory.c - kernel memory ops
 *
 * SPDX-License-Identifier: MIT
 */

#include "memory.h"
#include "../../include/status.h"
#include "ksyms.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>


/* ─────────────────────────────────────────────────────────────────────────────
 * resolved symbols
 * ───────────────────────────────────────────────────────────────────────────── */

static void *(*__module_alloc_fn)(unsigned long)       = NULL;
static int   (*__set_memory_x_fn)(unsigned long, int)  = NULL;
static int   (*__patch_text_fn)(void *addr, u32 instr) = NULL;

static int __syms_resolved = 0;


/* ─────────────────────────────────────────────────────────────────────────────
 * init
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook_mem_init(void)
{
	if (__syms_resolved)
		return 0;

	__module_alloc_fn = silkhook_ksym("module_alloc");
	__set_memory_x_fn = silkhook_ksym("set_memory_x");
	__patch_text_fn = silkhook_ksym("aarch64_insn_patch_text_nosync");

	if (!__module_alloc_fn || !__set_memory_x_fn || !__patch_text_fn)
	{
		pr_err("silkhook: mem symbols missing...\n");
		return SILKHOOK_ERR_RESOLVE;
	}

	__syms_resolved = 1;
	return 0;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */

int __mem_make_rw(void *addr, size_t len)
{
	(void) addr; (void) len;
	return SILKHOOK_OK;
}

int __mem_make_rx(void *addr, size_t len)
{
	(void) addr; (void) len;
	return SILKHOOK_OK;
}

int __mem_alloc_exec(size_t size, void **out)
{
	void *mem;
	int ret;

	if (!__syms_resolved)
		return SILKHOOK_ERR_PROT;

	mem = __module_alloc_fn(size);
	if (!mem)
		return SILKHOOK_ERR_NOMEM;

	memset(mem, 0, size);

	ret = __set_memory_x_fn((unsigned long) mem & PAGE_MASK,
				(size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (ret)
	{
		vfree(mem);
		return SILKHOOK_ERR_PROT;
	}

	flush_icache_range((unsigned long) mem, (unsigned long) mem + size);

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

void __flush_icache(void *addr, size_t len)
{
	flush_icache_range((unsigned long) addr, (unsigned long) addr + len);
}

int __mem_write_text(void *dst, const void *src, size_t len)
{
	const u32 *instrs = src;
	size_t n = len / sizeof(u32);
	size_t i;
	int ret;

	if (!__syms_resolved || !__patch_text_fn)
		return SILKHOOK_ERR_PROT;

	for (i = 0; i < n; i++)
	{
		ret = __patch_text_fn((u32 *) dst + i, instrs[i]);
		if (ret)
		{
			pr_err("silkhook: patch_text failure @ offset %zu: %d\n",
			       i * 4, ret);
			return SILKHOOK_ERR_PROT;
		}
	}

	return SILKHOOK_OK;
}

int __mem_write_code(void *dst, const void *src, size_t len)
{
	return __mem_write_text(dst, src, len);
}
