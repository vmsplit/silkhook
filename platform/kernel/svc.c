/*
 * silkhook - miniature arm hooking lib
 * svc.c    - EL0 SVC handler hooking
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include <asm/unistd.h>

#include "svc.h"
#include "shadow.h"
#include "ksyms.h"
#include "memory.h"
#include "../../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * globals
 * ───────────────────────────────────────────────────────────────────────────── */

int hooked_syscall_number = -1;
void *new_sys_call_table_ptr = NULL;
void *el0_svc_common_ptr = NULL;

/* Defined in svc_hook.S */
extern void el0_svc_common_hook(void);

#define SHELLCODE_INSTR_COUNT 5
#define INSTR_SIZE 4

/* ─────────────────────────────────────────────────────────────────────────────
 * shellcode gen
 * ───────────────────────────────────────────────────────────────────────────── */

static void assemble_mov64(unsigned int reg, uint64_t addr, uint32_t *buf)
{
    buf[0] = 0xD2800000 | (reg & 0x1F) | ((addr         & 0xFFFF) << 5);
    buf[1] = 0xF2A00000 | (reg & 0x1F) | (((addr >> 16) & 0xFFFF) << 5);
    buf[2] = 0xF2C00000 | (reg & 0x1F) | (((addr >> 32) & 0xFFFF) << 5);
    buf[3] = 0xF2E00000 | (reg & 0x1F) | (((addr >> 48) & 0xFFFF) << 5);
}

/* ─────────────────────────────────────────────────────────────────────────────
 * stop_machine callback
 * ───────────────────────────────────────────────────────────────────────────── */

struct copy_args {
    void     *hook_fn;
    void     *svc_fn;
    uint32_t *orig_instrs;
    uint32_t *shellcode;
};

static int copy_shellcode_sync(void *arg)
{
    struct copy_args *a = arg;
    int i;

    for (i = 0; i < SHELLCODE_INSTR_COUNT; i++)
    {
        __mem_write_text((uint32_t *) a->hook_fn + i,
                         &a->orig_instrs[i],
                         INSTR_SIZE);
    }

    for (i = 0; i < SHELLCODE_INSTR_COUNT; i++)
    {
        __mem_write_text((uint32_t *) a->svc_fn + i,
                         &a->shellcode[i],
                         INSTR_SIZE);
    }

    return 0;
}

static int restore_sync(void *arg)
{
    struct copy_args *a = arg;
    int i;

    for (i = 0; i < SHELLCODE_INSTR_COUNT; i++)
    {
        __mem_write_text((uint32_t *) a->svc_fn + i,
                         &a->orig_instrs[i],
                         INSTR_SIZE);
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * public API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__svc_init(struct silkhook_svc_hook *h)
{
    if (!h) return SILKHOOK_ERR_INVAL;
    memset(h, 0, sizeof(*h));

    h->invoke_syscall = silkhook_ksym("invoke_syscall");

    if (!h->invoke_syscall)
    {
        pr_err("silkhook: failure to resolve invoke_syscall\n");
        return SILKHOOK_ERR_RESOLVE;
    }

    h->sys_call_table = silkhook_ksym("sys_call_table");

    if (!h->sys_call_table)
    {
        pr_err("silkhook: failure to resolve sys_call_table\n");
        return SILKHOOK_ERR_RESOLVE;
    }

    pr_info("silkhook:   invoke_syscall @ %px\n", h->invoke_syscall);
    pr_info("silkhook:   sys_call_table @ %px\n", h->sys_call_table);
    pr_info("silkhook:   hook func      @ %px\n", el0_svc_common_hook);

    return SILKHOOK_OK;
}

int silkhook__svc_install(struct silkhook_svc_hook *h, int sysno, void *detour)
{
    struct copy_args args;
    uint32_t shellcode[SHELLCODE_INSTR_COUNT];
    int r;

    if (!h || !h->invoke_syscall || !detour)
        return SILKHOOK_ERR_INVAL;

    if (h->installed)
        return SILKHOOK_ERR_EXISTS;

    r = silkhook__shadow_create(&h->shadow);
    if (r != SILKHOOK_OK) return r;

    r = silkhook__shadow_hook(&h->shadow, sysno, detour, NULL);
    if (r != SILKHOOK_OK)
    {
        silkhook__shadow_destroy(&h->shadow);
        return r;
    }

    hooked_syscall_number = sysno;
    new_sys_call_table_ptr = h->shadow.shadow;
    el0_svc_common_ptr = h->invoke_syscall;

    memcpy(h->orig_instrs, h->invoke_syscall, SHELLCODE_INSTR_COUNT * INSTR_SIZE);
    h->orig_size = SHELLCODE_INSTR_COUNT * INSTR_SIZE;

    pr_info("silkhook: orig instrs: %08x %08x %08x %08x %08x\n",
            h->orig_instrs[0], h->orig_instrs[1], h->orig_instrs[2],
            h->orig_instrs[3], h->orig_instrs[4]);

    assemble_mov64(12, (uint64_t)el0_svc_common_hook, shellcode);
    shellcode[4] = 0xD61F0180;

    pr_info("silkhook: shellcode: %08x %08x %08x %08x %08x\n",
            shellcode[0], shellcode[1], shellcode[2],
            shellcode[3], shellcode[4]);

    args.hook_fn     = el0_svc_common_hook;
    args.svc_fn      = h->invoke_syscall;
    args.orig_instrs = h->orig_instrs;
    args.shellcode   = shellcode;

    stop_machine(copy_shellcode_sync, &args, NULL);

    h->installed = 1;
    pr_info("silkhook: svc hook installed on syscall %d !!!\n", sysno);

    return SILKHOOK_OK;
}

int silkhook__svc_remove(struct silkhook_svc_hook *h)
{
    struct copy_args args;

    if (!h || !h->installed)
        return SILKHOOK_ERR_INVAL;

    args.svc_fn = h->invoke_syscall;
    args.orig_instrs = h->orig_instrs;

    stop_machine(restore_sync, &args, NULL);

    silkhook__shadow_destroy(&h->shadow);

    hooked_syscall_number = -1;
    new_sys_call_table_ptr = NULL;
    el0_svc_common_ptr = NULL;

    h->installed = 0;
    pr_info("silkhook: svc hook removed !!!\n");

    return SILKHOOK_OK;
}
