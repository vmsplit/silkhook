/*
 * silkhook        - miniature arm64 hooking lib
 * silkhook_kmod.c - kernel mod using silkhook lib
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "include/macros.h"
#include "include/silkhook.h"
#include "platform/kernel/ksyms.h"


static unsigned int hook_count = 0;


/* ─────────────────────────────────────────────────────────────────────────────
 * detour
 * ───────────────────────────────────────────────────────────────────────────── */

SILKHOOK_DEFINE(getuid_hook, long, (const struct pt_regs *regs))
{
    long uid;

    hook_count++;
    uid = SILKHOOK_CALL_ORIG(getuid_hook, regs);

    if (hook_count == 1 || hook_count % 10 == 0)
        pr_info("silkhook: getuid #%u -> %ld\n", hook_count, uid);

    return uid;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * module init/exit
 * ───────────────────────────────────────────────────────────────────────────── */

static int __init silkhook_test_init(void)
{
    int r;

    pr_info("silkhook: loading...\n");

    r = SILKHOOK_INSTALL_SYM(getuid_hook, "__arm64_sys_getuid");
    if (r != SILKHOOK_OK)
    {
        pr_err("silkhook: install failure: %s\n", silkhook_strerror(r));
        return -EFAULT;
    }

    pr_info("silkhook: installed !!!\n");
    return 0;
}

static void __exit silkhook_test_exit(void)
{
    SILKHOOK_UNINSTALL(getuid_hook);
    pr_info("silkhook: unloaded !!!, triggered %u times\n", hook_count);
}

module_init(silkhook_test_init);
module_exit(silkhook_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("silkhook");
MODULE_DESCRIPTION("silkhook macro API test");
