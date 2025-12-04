/*
 * silkhook        - miniature arm64 hooking lib
 * silkhook_kmod.c - kernel mod using silkhook lib
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <asm/cacheflush.h>

#include "include/types.h"
#include "include/status.h"
#include "internal/arch.h"
#include "platform/memory.h"
#include "platform/kernel/ksyms.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * hook state
 * ───────────────────────────────────────────────────────────────────────────── */

static struct {
    void        *target;
    void        *trampoline;
    u32         orig[4];
    bool        active;
} hook;

static unsigned int hook_count = 0;
static long (*orig_getuid)(const struct pt_regs *regs);


/* ─────────────────────────────────────────────────────────────────────────────
 * detour
 * ───────────────────────────────────────────────────────────────────────────── */

static long hook_getuid(const struct pt_regs *regs)
{
    hook_count++;
    return orig_getuid(regs);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * hook helpers using library functions
 * ───────────────────────────────────────────────────────────────────────────── */

static int install_hook(void *target, void *detour, void **trampoline_out)
{
    void *tramp;
    u32 *p;
    u32 jmp[4];
    uintptr_t ret_addr;
    int r;

    memcpy(hook.orig, target, sizeof(hook.orig));

    r = __mem_alloc_exec(4096, &tramp);
    if (r != SILKHOOK_OK)
        return r;

    p = tramp;
    ret_addr = (uintptr_t)target + 16;

    p[0] = hook. orig[0];
    p[1] = hook.orig[1];
    p[2] = hook.orig[2];
    p[3] = hook.orig[3];
    p[4] = 0x58000050;
    p[5] = 0xD61F0200;
    p[6] = (u32)(ret_addr & 0xFFFFFFFF);
    p[7] = (u32)(ret_addr >> 32);

    __flush_icache(tramp, 32);

    *trampoline_out = tramp;

    __ABS_JMP(jmp, (uintptr_t)detour);

    r = __mem_write_text(target, jmp, sizeof(jmp));
    if (r != SILKHOOK_OK)
    {
        __mem_free(tramp, 4096);
        return r;
    }

    return SILKHOOK_OK;
}

static int remove_hook(void *target, u32 *orig, void *trampoline)
{
    int r;

    r = __mem_write_text(target, orig, 16);
    if (r != SILKHOOK_OK)
        return r;

    __mem_free(trampoline, 4096);
    return SILKHOOK_OK;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * module init/exit
 * ───────────────────────────────────────────────────────────────────────────── */

static int __init silkhook_test_init(void)
{
    int r;

    pr_info("silkhook: loading...\n");

    hook. target = silkhook_ksym("__arm64_sys_getuid");
    if (!hook.target)
    {
        pr_err("silkhook: targ not found\n");
        return -ENOENT;
    }
    pr_info("silkhook:   target @ %px\n", hook. target);

    r = install_hook(hook.target, hook_getuid, &hook.trampoline);
    if (r != SILKHOOK_OK)
    {
        pr_err("silkhook: install failed !!!\n");
        pr_err("silkhook:   %s\n", silkhook_strerror(r));
        return -EFAULT;
    }

    orig_getuid = hook.trampoline;
    hook.active = true;

    pr_info("silkhook: hook installed !!!\n");
    pr_info("silkhook:   trampoline @ %px\n", hook. trampoline);
    pr_info("silkhook: run 'id'\n");

    return 0;
}

static void __exit silkhook_test_exit(void)
{
    if (hook.active)
    {
        remove_hook(hook.target, hook.orig, hook.trampoline);
        hook. active = false;
    }
    pr_info("silkhook: unloaded, hook triggered %u times\n", hook_count);
}

module_init(silkhook_test_init);
module_exit(silkhook_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("silkhook");
MODULE_DESCRIPTION("silkhook library test");
