/*
 * silkhook - miniature arm64 hooking lib
 * macros.h - declarative macro API
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _MACROS_H_
#define _MACROS_H_

#include "silkhook.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * declarative hook definition
 *
 * usage:
 *
 *   SILKHOOK_DEFINE(my_hook, long, (const struct pt_regs *regs))
 *   {
 *       long ret = SILKHOOK_CALL_ORIG(my_hook, regs);
 *       pr_info("hooked -> %ld\n", ret);
 *       return ret;
 *   }
 *
 *   // in init:
 *   void *targ = silkhook_ksym("__arm64_sys_getuid");
 *   SILKHOOK_INSTALL(my_hook, targ);
 *
 *   // in cleanup:
 *   SILKHOOK_UNINSTALL(my_hook);
 * ───────────────────────────────────────────────────────────────────────────── */

#define SILKHOOK_DEFINE(name, ret_type, args)        \
    static struct silkhook_hook __sh_hook_##name;    \
    static ret_type (*__sh_orig_##name) args = NULL; \
    static ret_type __sh_detour_##name args

#define SILKHOOK_CALL_ORIG(name, ...)  \
    (__sh_orig_##name(__VA_ARGS__))

#define SILKHOOK_INSTALL(name, target) \
    silkhook_hook((void *)(target), (void *)__sh_detour_##name, \
                  &__sh_hook_##name, (void **)&__sh_orig_##name)

#define SILKHOOK_UNINSTALL(name)    \
    silkhook_unhook(&__sh_hook_##name)

#define SILKHOOK_IS_INSTALLED(name) \
    silkhook_is_active(&__sh_hook_##name)


#ifdef __KERNEL__
/* ─────────────────────────────────────────────────────────────────────────────
 * install by symbol name
 * ───────────────────────────────────────────────────────────────────────────── */

#define SILKHOOK_INSTALL_SYM(name, sym_name) ({ \
    void *__targ = silkhook_ksym(sym_name); \
    __targ ? SILKHOOK_INSTALL(name, __targ) : SILKHOOK_ERR_NOENT; \
})

#endif /* __KERNEL__ */


#endif /* _MACROS_H_ */
