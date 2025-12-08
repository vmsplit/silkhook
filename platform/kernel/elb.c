/*
 * silkhook - miniature arm hooking lib
 * elb.c    - EL (Exception Level) Bounce PoC
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/debug-monitors.h>
#include <asm/ptrace.h>

#include "elb.h"
#include "memory.h"
#include "ksyms.h"
#include "../../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * hook registry
 *
 * linked list protectd by spinlock
 * lookup by pc elr_el1 on exception
 * ───────────────────────────────────────────────────────────────────────────── */

static DEFINE_SPINLOCK(__elb_lock);
static struct silkhook_elb_hook *__elb_hooks = NULL;

static struct silkhook_elb_hook *__elb_find_by_pc(unsigned long pc)
{
    struct silkhook_elb_hook *h = __elb_hooks;

    while (h)
    {
        if ((unsigned long) h->targ == pc)
            return h;
        h = h->next;
    }
    return NULL;
}

static void __elb_add(struct silkhook_elb_hook *h)
{
    h->next = __elb_hooks;
    __elb_hooks = h;
}

static void __elb_remove(struct silkhook_elb_hook *h)
{
    struct silkhook_elb_hook **pp = &__elb_hooks;

    while (*pp)
    {
        if (*pp == h)
        {
            *pp = h->next;
            return;
        }
        pp = &(*pp)->next;
    }
}


/* ─────────────────────────────────────────────────────────────────────────────
 * brk exception handler
 *
 * called by kernel's debug exception dispatch when brk #imm matches
 * we registerd via register_kernel_break_hook()
 *
 * return:
 *   DBG_HOOK_HANDLED - do not pass it to other handlers
 *   DBG_HOOK_ERROR   - not ours,  let the kernel handle it
 * ───────────────────────────────────────────────────────────────────────────── */

static int __elb_brk_handler(struct pt_regs *regs, unsigned long esr)
{
    struct silkhook_elb_hook *h;
    unsigned long pc = instruction_pointer(regs);
    unsigned long flags;

    spin_lock_irqsave(&__elb_lock, flags);
    h = __elb_find_by_pc(pc);
    spin_unlock_irqrestore(&__elb_lock, flags);

    if (!h)
        return DBG_HOOK_ERROR;

    if (h->handler)
        h->handler(regs, h);

    regs->pc += 4;

    return DBG_HOOK_HANDLED;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * resolved symbols
 *
 * break_hook api may not be exported, resolve via kallsyms
 * ───────────────────────────────────────────────────────────────────────────── */

static void (*__register_kernel_break_hook)(struct break_hook *) = NULL;
static void (*__unregister_kernel_break_hook)(struct break_hook *) = NULL;

static struct break_hook __elb_break_hook = {
    .fn  = __elb_brk_handler,
    .imm = SILKHOOK_BRK_IMM,
};


/* ─────────────────────────────────────────────────────────────────────────────
 * simple init & exit
 * ───────────────────────────────────────────────────────────────────────────── */

static int __elb_initialised = 0;

int silkhook__elb_init(void)
{
    if (__elb_initialised)
        return SILKHOOK_OK;

    /*  resolve break hook API  */
    __register_kernel_break_hook   = silkhook_ksym("register_kernel_break_hook");
    __unregister_kernel_break_hook = silkhook_ksym("unregister_kernel_break_hook");

    if (!__register_kernel_break_hook || !__unregister_kernel_break_hook)
    {
        pr_err("silkhook: failure to resolve break_hook API\n");
        return SILKHOOK_ERR_RESOLVE;
    }

    __register_kernel_break_hook(&__elb_break_hook);
    __elb_initialised = 1;

    pr_info("silkhook: elb initialised (brk #0x%x) !!!\n", SILKHOOK_BRK_IMM);
    return SILKHOOK_OK;
}

void silkhook__elb_exit(void)
{
    if (!__elb_initialised)
        return;

    if (__unregister_kernel_break_hook)
        __unregister_kernel_break_hook(&__elb_break_hook);

    __elb_initialised = 0;

    pr_info("silkhook: elb exited !!!\n");
}


/* ─────────────────────────────────────────────────────────────────────────────
 * install & remove functs
 *
 * install:
 *   1.  save orig instr @ targ
 *   2.  write brk #SILKHOOK_BRK_IMM -> targ
 *   3.  add to registry
 *
 * remove:
 *   1.  restore orig instr
 *   2.  remove from registry
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__elb_install(struct silkhook_elb_hook *h, void *targ,
                          silkhook_elb_handler_t handler, void *priv)
{
    unsigned long flags;
    uint32_t brk_instr = SILKHOOK_BRK_INSTR;
    int r;

    if (!h || !targ || !handler)
            return SILKHOOK_ERR_INVAL;

    if (!__elb_initialised)
    {
        r = silkhook__elb_init();
        if (r != SILKHOOK_OK)
            return r;
    }

    memset(h, 0, sizeof(*h));
    h->targ    = targ;
    h->handler = handler;
    h->priv    = priv;

    /*  save orig instr  */
    memcpy(&h->orig_instr, targ, sizeof(uint32_t));

    /*  write brk instr  */
    r = __mem_write_text(targ, &brk_instr, sizeof(uint32_t));
    if (r != SILKHOOK_OK)
        return r;

    /*  simply add back 2 the registry  */
    spin_lock_irqsave(&__elb_lock, flags);
    __elb_add(h);
    spin_unlock_irqrestore(&__elb_lock, flags);

    h->installed = 1;

    pr_info("silkhook: elb hook installed @ %px (orig=%08x) !!!\n",
            targ, h->orig_instr);

    return SILKHOOK_OK;
}


int silkhook__elb_remove(struct silkhook_elb_hook *h)
{
    unsigned long flags;
    int r;

    if (!h || !h->installed)
        return SILKHOOK_ERR_INVAL;

    /*  restore orig instr  */
    r = __mem_write_text(h->targ, &h->orig_instr, sizeof(uint32_t));
    if (r != SILKHOOK_OK)
        return r;

    /*  remove from registry  */
    spin_lock_irqsave(&__elb_lock, flags);
    __elb_remove(h);
    spin_unlock_irqrestore(&__elb_lock, flags);

    h->installed = 0;

    pr_info("silkhook: elb hook removed @ %px !!!\n", h->targ);

    return SILKHOOK_OK;
}
