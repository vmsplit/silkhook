/*
 * silkhook      - miniature arm hooking lib
 * silkhook_kmod - kernel module test
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <asm/unistd.h>

#include "include/silkhook.h"
#include "platform/kernel/ksyms.h"
#include "platform/kernel/hide.h"
#include "platform/kernel/memory.h"
#include "platform/kernel/svc.h"
#include "platform/kernel/shadow.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vmsplit");
MODULE_DESCRIPTION("silkhook testtttttt382982332");


static struct delayed_work setup_work;
static struct silkhook_svc_hook  __svc_hook;
static struct silkhook_hidden_mod __hidden;
static unsigned int              __trigger_count;

asmlinkage long hooked_getuid(void);

asmlinkage long hooked_getuid(void)
{
	__trigger_count++;
	if (__trigger_count % 10 == 1)
		pr_info("silkhook: [silent] getuid called!! count=%u\n", __trigger_count);

	return current_uid().val;
}

static void do_silkhook_setup(struct work_struct *work)
{
	int r;

	pr_info("silkhook: setup started !!!\n");

	if (silkhook_ksyms_init() != 0) return;
	if (silkhook_mem_init() != 0) return;

	r = silkhook__svc_init(&__svc_hook);
	if (r != SILKHOOK_OK)
	{
		pr_err("silkhook: svc init failure: %d\n", r);
		return;
	}

	r = silkhook__svc_install(&__svc_hook, __NR_getuid, hooked_getuid);
	if (r != SILKHOOK_OK)
	{
		pr_err("silkhook: svc install failure: %d\n", r);
		return;
	}

	silkhook__hide_mod(THIS_MODULE, &__hidden);

	pr_info("silkhook: setup complete !!!\n");
}

static int __init silkhook_mod_init(void)
{
	pr_info("silkhook: module loaded !!!\n");
	INIT_DELAYED_WORK(&setup_work, do_silkhook_setup);
	schedule_delayed_work(&setup_work, msecs_to_jiffies(100));
	return 0;
}

static void __exit silkhook_mod_exit(void)
{
	cancel_delayed_work_sync(&setup_work);
	silkhook__unhide_mod(&__hidden);
	silkhook__svc_remove(&__svc_hook);
	pr_info("silkhook: unloaded !!!\n");
}

module_init(silkhook_mod_init);
module_exit(silkhook_mod_exit);
