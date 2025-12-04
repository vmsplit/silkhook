/*
 * silkhook - miniature arm64 hooking lib
 * ksyms.c  - kernel symbol resolution
 *
 * SPDX-License-Identifier: MIT
 */

#include "ksyms.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>


static unsigned long (*__kallsyms_lookup_name)(const char *name) = NULL;

static int __resolve_kallsyms(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int r;

    if (__kallsyms_lookup_name)
        return 0;

    r = register_kprobe(&kp);
    if (r < 0)
        return r;

    __kallsyms_lookup_name = (void *) kp.addr;
    unregister_kprobe(&kp);

    return 0;
}

void *silkhook_ksym(const char *name)
{
    if (__resolve_kallsyms() != 0)
        return NULL;

    return (void *) __kallsyms_lookup_name(name);
}
EXPORT_SYMBOL(silkhook_ksym);

void *silkhook_ksym_mod(const char *mod, const char *name)
{
    char buf[256];

    if (!mod)
        return silkhook_ksym(name);

    snprintf(buf, sizeof(buf), "%s:%s", mod, name);
    return silkhook_ksym(buf);
}
EXPORT_SYMBOL(silkhook_ksym_mod);
