/*
 * silkhook - miniature arm hooking lib
 * ich.c    - interrupt coalescing hijack
 *
 * SPDX-License-Identifier: MIT
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <asm/debug-monitors.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

#include "ich.h"
#include "ksyms.h"
#include "memory.h"
#include "../../include/status.h"


/* ─────────────────────────────────────────────────────────────────────────────
 * globals
 * ───────────────────────────────────────────────────────────────────────────── */

static DEFINE_SPINLOCK(__ich_lock);
static struct silkhook_ich_hook *__ich_active = NULL;
static struct break_hook __ich_brk_hook;
static int __ich_initialised = 0;

static void (*__register_kernel_break_hook)(struct break_hook *)   = NULL;
static void (*__unregister_kernel_break_hook)(struct break_hook *) = NULL;


/* ─────────────────────────────────────────────────────────────────────────────
 * cycle counter helpers
 *
 * pmccntr_el0: cycle counter      (available if enabled)
 * cntvct_el0:  virt timer counter (available always)
 * ───────────────────────────────────────────────────────────────────────────── */

static inline uint64_t __ich_cycles(void)
{
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

static inline void __ich_delay_cycles(unsigned int cycles)
{
    uint64_t start = __ich_cycles();
    while (__ich_cycles() - start < cycles)
        cpu_relax();
}


/* ─────────────────────────────────────────────────────────────────────────────
 * jitter gen
 *
 * add random delay within cfg'd window
 * makes timing analysis harder
 * ───────────────────────────────────────────────────────────────────────────── */

static inline unsigned int __ich_jitter(struct silkhook_ich_hook *h)
{
    unsigned int range = h->jitter_max - h->jitter_min;
    unsigned int r;

    // if (range == 0)
    //     return h->jitter_min;

    r = (unsigned int)(__ich_cycles() ^ (unsigned long) current);
    return h->jitter_min + (r % range);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * instr emulation (same as elb)
 * ───────────────────────────────────────────────────────────────────────────── */

static void __ich_emulate_instr(struct pt_regs *regs, uint32_t instr)
{
    unsigned int rd, rn;

    /*  nop - d503201f  */
    if (instr == 0xD503201F)
        return;

    /*  hint instrs (pac, bti, etc) - d503xxxx  */
    if ((instr & 0xFFFFF01F) == 0xD503201F)
        return;

    /*  mov xd, xn (orr xd, xzr, xn) - aa0003e0 | (rn << 16) | rd  */
    if ((instr & 0xFFE0FFE0) == 0xAA0003E0)
    {
        rd = instr & 0x1F;
        rn = (instr >> 16) & 0x1F;
        if (rd < 31 && rn < 31)
            regs->regs[rd] = regs->regs[rn];
        return;
    }

    /*  stp x29, x30, [sp, #imm]! - common prologue
     *  encoding: 1010100110 imm7 Rt2 Rn Rt
     *  we need to emu stack push  */
    if ((instr & 0xFFC00000) == 0xA9800000)
    {
        int32_t imm7 = (instr >> 15) & 0x7F;
        unsigned int rt2 = (instr >> 10) & 0x1F;
        unsigned int rn_reg = (instr >> 5) & 0x1F;
        unsigned int rt = instr & 0x1F;
        int64_t offset;
        uint64_t *sp;

        /*  sign extend imm7  */
        if (imm7 & 0x40)
            imm7 |= ~0x7F;
        offset = imm7 * 8;

        /*  pre-index: sp = sp + offset,  then store  */
        if (rn_reg == 31)
        {
            regs->sp += offset;
            sp = (uint64_t *)regs->sp;
            if (rt < 31)
                sp[0] = regs->regs[rt];
            if (rt2 < 31)
                sp[1] = regs->regs[rt2];
        }
        return;
    }

    /*  mrs x0, ...  - common in syscall handlers  */
    if ((instr & 0xFFF00000) == 0xD5300000)
        return;

    /*  HOPE FOR THE BEST!!!!  */
    pr_warn_once("silkhook: [ich] unhandled instr %08x\n", instr);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * brk handler (for ich)
 *
 * called from hardirq ctx on timer interrupt
 * HAS TO BE FAST!!
 * ───────────────────────────────────────────────────────────────────────────── */

static int __ich_brk_handler(struct pt_regs *regs, unsigned long esr)
{
    struct silkhook_ich_hook *h;
    uint64_t start_cycles;
    unsigned int jitter;

    h = READ_ONCE(__ich_active);
    if (!h)
        return DBG_HOOK_ERROR;

    if (instruction_pointer(regs) != (unsigned long)h->targ)
        return DBG_HOOK_ERROR;

    h->coalesce_ctr++;
    if (h->coalesce_ctr < h->coalesce_n)
    {
        h->skip_count++;
        goto emu_n_skip;
    }
    h->coalesce_ctr = 0;

    jitter = __ich_jitter(h);
    __ich_delay_cycles(jitter);

    start_cycles = __ich_cycles();

    if (h->payload)
        h->payload(regs, h);

    h->total_cycles += __ich_cycles() - start_cycles;
    h->exec_count++;

emu_n_skip:
    __ich_emulate_instr(regs, h->orig_instr);
    regs->pc += 4;

    return DBG_HOOK_HANDLED;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * init / exit
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__ich_init(void)
{
    if (__ich_initialised)
        return SILKHOOK_OK;

    __register_kernel_break_hook = silkhook_ksym("register_kernel_break_hook");
    __unregister_kernel_break_hook = silkhook_ksym("unregister_kernel_break_hook");

    if (!__register_kernel_break_hook || !__unregister_kernel_break_hook)
    {
        pr_err("silkhook: [ich] cannot resolve break_hook api\n");
        return SILKHOOK_ERR_RESOLVE;
    }

    __ich_brk_hook.fn = __ich_brk_handler;
    __ich_brk_hook.imm = SILKHOOK_ICH_BRK_IMM;

    __register_kernel_break_hook(&__ich_brk_hook);
    __ich_initialised = 1;

    pr_info("silkhook: ich initialised (brk #0x%x) !!!\n", SILKHOOK_ICH_BRK_IMM);
    return SILKHOOK_OK;
}

void silkhook__ich_exit(void)
{
    if (!__ich_initialised)
        return;

    if (__unregister_kernel_break_hook)
        __unregister_kernel_break_hook(&__ich_brk_hook);

    __ich_initialised = 0;
    pr_info("silkhook: ich exited !!!\n");
}


/* ─────────────────────────────────────────────────────────────────────────────
 * install / remove
 * ───────────────────────────────────────────────────────────────────────────── */

 int silkhook__ich_install(struct silkhook_ich_hook *h, struct silkhook_ich_cfg *cfg)
 {
     void *targ = NULL;
     uint32_t brk_instr = SILKHOOK_ICH_BRK_INSTR;
     unsigned long flags;
     int r;
     int i;
     const char *found_sym = NULL;

     static const char *timer_syms[] = {
         "hrtimer_interrupt",
         "update_process_times",
         "tick_sched_handle",
         "tick_handle_periodic",
         "arch_timer_handler_phys",
         NULL
     };

     if (! h || !cfg || !cfg->payload)
         return SILKHOOK_ERR_INVAL;

     if (! __ich_initialised)
         return SILKHOOK_ERR_STATE;

     for (i = 0; timer_syms[i]; i++)
     {
         targ = silkhook_ksym(timer_syms[i]);
         if (targ)
         {
             found_sym = timer_syms[i];
             pr_info("silkhook: [ich] trying %s @ %px\n", found_sym, targ);
             break;
         }
     }

     if (!targ)
     {
         pr_err("silkhook: [ich] cannot find any timer handler\n");
         return SILKHOOK_ERR_RESOLVE;
     }

     spin_lock_irqsave(&__ich_lock, flags);

     if (__ich_active)
     {
         spin_unlock_irqrestore(&__ich_lock, flags);
         return SILKHOOK_ERR_EXISTS;
     }

     memset(h, 0, sizeof(*h));
     h->targ = targ;
     h->coalesce_n = cfg->coalesce_n ?  cfg->coalesce_n : SILKHOOK_ICH_DEFAULT_COALESCE;
     h->jitter_min = cfg->jitter_min ?  cfg->jitter_min : SILKHOOK_ICH_DEFAULT_JITTER_MIN;
     h->jitter_max = cfg->jitter_max ? cfg->jitter_max : SILKHOOK_ICH_DEFAULT_JITTER_MAX;
     h->payload = cfg->payload;
     h->payload_ctx = cfg->payload_ctx;

     h->orig_instr = *(uint32_t *) targ;

     WRITE_ONCE(__ich_active, h);

     spin_unlock_irqrestore(&__ich_lock, flags);

     r = __mem_write_text(targ, &brk_instr, 4);
     if (r != SILKHOOK_OK)
     {
         spin_lock_irqsave(&__ich_lock, flags);
         WRITE_ONCE(__ich_active, NULL);
         spin_unlock_irqrestore(&__ich_lock, flags);
         return r;
     }

     h->installed = 1;

     pr_info("silkhook: ich hooked %s @ %px (coalesce=%u orig=%08x) !! !\n",
             found_sym, targ, h->coalesce_n, h->orig_instr);

     return SILKHOOK_OK;
 }

int silkhook__ich_remove(struct silkhook_ich_hook *h)
{
    unsigned long flags;

    if (!h || !h->installed)
        return SILKHOOK_ERR_INVAL;

    /*  restore orig instr  */
    __mem_write_text(h->targ, &h->orig_instr, 4);

    spin_lock_irqsave(&__ich_lock, flags);
    if (__ich_active == h)
        WRITE_ONCE(__ich_active, NULL);
    spin_unlock_irqrestore(&__ich_lock, flags);

    h->installed = 0;

    pr_info("silkhook: ich removed (exec=%llu skip=%llu avg_cyc=%llu) !!!\n",
            h->exec_count, h->skip_count,
            h->exec_count ? h->total_cycles / h->exec_count : 0);

    return SILKHOOK_OK;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * runtime helpers
 * ───────────────────────────────────────────────────────────────────────────── */

void silkhook__ich_set_coalesce(struct silkhook_ich_hook *h, unsigned int n)
{
    if (h)
        WRITE_ONCE(h->coalesce_n, n);
}

void silkhook__ich_get_stats(struct silkhook_ich_hook *h, uint64_t *exec,
                             uint64_t *skip, uint64_t *cyc)
{
    if (!h)
        return;
    if (exec)
        *exec = READ_ONCE(h->exec_count);
    if (skip)
        *skip = READ_ONCE(h->skip_count);
    if (cyc)
        *cyc = READ_ONCE(h->total_cycles);
}
