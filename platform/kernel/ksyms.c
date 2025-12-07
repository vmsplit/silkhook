/*
 * silkhook - miniature arm hooking lib
 * ksyms.c  - kallsyms resolution
 *
 * SPDX-License-Identifier: MIT
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#include "ksyms.h"

static unsigned long (*__kallsyms_lookup_name)(const char *) = NULL;

static unsigned long kprobe_get_func_addr(const char *func_name)
{
	static struct kprobe kp;
	unsigned long addr;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = func_name;

	if (register_kprobe(&kp) < 0)
	{
		pr_err("silkhook: kprobe failure for %s\n", func_name);
		return 0;
	}

	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);

	pr_info("silkhook: kprobe found %s @ %lx\n", func_name, addr);
	return addr;
}

int silkhook_ksyms_init(void)
{
	if (__kallsyms_lookup_name)
		return 0;

	__kallsyms_lookup_name = (void *)kprobe_get_func_addr("kallsyms_lookup_name");
	if (!__kallsyms_lookup_name)
	{
		pr_err("silkhook: failure to resolve kallsyms_lookup_name\n");
		return -ENOENT;
	}

	return 0;
}

void *silkhook_ksym(const char *name)
{
	if (!__kallsyms_lookup_name)
		return NULL;

	return (void *)__kallsyms_lookup_name(name);
}
