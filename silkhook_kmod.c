/*
 * silkhook        - miniature arm64 hooking lib
 * silkhook_kmod. c - kernel mod using silkhook lib
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "include/silkhook.h"
#include "platform/kernel/ksyms.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * hook state
 * ───────────────────────────────────────────────────────────────────────────── */

static struct silkhook_hook hook;
static unsigned int hook_count = 0;
static long (*orig_getuid)(const struct pt_regs *regs);


/* ─────────────────────────────────────────────────────────────────────────────
 * detour
 * ───────────────────────────────────────────────────────────────────────────── */

static long hook_getuid(const struct pt_regs *regs)
{
    long uid;
    hook_count++;
    uid = orig_getuid(regs);
    if (hook_count == 1 || hook_count % 10 == 0)
        pr_info("silkhook: getuid #%u -> %ld\n", hook_count, uid);
    return uid;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * module init/exit
 * ───────────────────────────────────────────────────────────────────────────── */

static int __init silkhook_test_init(void)
{
    void *target;
    int r;

    pr_info("silkhook: loading...\n");

    target = silkhook_ksym("__arm64_sys_getuid");
    if (! target)
    {
        pr_err("silkhook: targ not found\n");
        return -ENOENT;
    }
    pr_info("silkhook:   target @ %px\n", target);

    r = silkhook_hook(target, hook_getuid, &hook, (void **) &orig_getuid);
    if (r != SILKHOOK_OK)
    {
        pr_err("silkhook: hook failure: %s\n", silkhook_strerror(r));
        return -EFAULT;
    }

    pr_info("silkhook: installed !!!,  trampoline @ %px\n", (void *) hook.trampoline);
    return 0;
}

static void __exit silkhook_test_exit(void)
{
    silkhook_unhook(&hook);
    pr_info("silkhook: unloaded !!!,  triggered %u times\n", hook_count);
}

module_init(silkhook_test_init);
module_exit(silkhook_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("silkhook");
MODULE_DESCRIPTION("silkhook full lib test");
