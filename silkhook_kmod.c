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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/unistd.h>

#include "include/silkhook.h"
#include "platform/kernel/ksyms.h"
#include "platform/kernel/hide.h"
#include "platform/kernel/memory.h"
#include "platform/kernel/svc.h"
#include "platform/kernel/shadow.h"
#include "platform/kernel/elb.h"
#include "platform/kernel/ich.h"
#include "platform/kernel/apr.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vmsplit");
MODULE_DESCRIPTION("silkhook test");


static struct delayed_work        setup_work;
static struct silkhook_svc_hook   __svc_hook;
static struct silkhook_hidden_mod __hidden;
static struct silkhook_elb_hook   __elb_hook;
static struct silkhook_ich_hook   __ich_hook;
static struct silkhook_apr_hook   __apr_hook;
static unsigned int               __trigger_count;

static uint32_t apr_shellcode[] = {
    0xd280a720,   /*  mov x0, #0x539 (1337)  */
    0xd65f03c0,   /*  ret                    */
};


/* ─────────────────────────────────────────────────────────────────────────────
 * svc hook test (shadow tbl)
 * ───────────────────────────────────────────────────────────────────────────── */

asmlinkage long hooked_getuid(void);

asmlinkage long hooked_getuid(void)
{
    __trigger_count++;
    if (__trigger_count % 10 == 1)
        pr_info("silkhook: [svc] getuid called !!  count=%u\n", __trigger_count);

    return current_uid().val;
}


/* ─────────────────────────────────────────────────────────────────────────────
 * elb hook test (exception bounce)
 * ───────────────────────────────────────────────────────────────────────────── */

static unsigned int __elb_count;
static int __elb_stack_dumped;

static void elb_test_handler(struct pt_regs *regs, struct silkhook_elb_hook *ctx)
{
    __elb_count++;

    if (!__elb_stack_dumped)
    {
        __elb_stack_dumped = 1;
        pr_info("silkhook: --------------------------------------------\n");
        pr_info("silkhook:   [elb] callstack proof\n");
        pr_info("silkhook:   [elb] proving hook runs in exception path:\n");
        pr_info("silkhook: --------------------------------------------\n");
        dump_stack();
        pr_info("silkhook: --------------------------------------------\n");
    }

    if (__elb_count % 100 == 1)
        pr_info("silkhook: [elb] exception bounce !! pc=%lx count=%u\n",
                instruction_pointer(regs), __elb_count);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * ich hook test (interrupt coalescing hijack)
 *
 * runs from hardirq ctx on timer interrupt
 * ───────────────────────────────────────────────────────────────────────────── */

static unsigned int __ich_exec_count;

static void ich_test_payload(struct pt_regs *regs, struct silkhook_ich_hook *ctx)
{
    struct task_struct *task = current;

    __ich_exec_count++;

    if (__ich_exec_count % 10 == 1)
    {
        pr_info("silkhook: [ich] tick !! cpu=%u pid=%d comm=%s\n",
                smp_processor_id(),
                task->pid,
                task->comm);
    }

    if (strncmp(task->comm, "ssh", 3) == 0)
    {
        if (__ich_exec_count % 50 == 1)
            pr_info("silkhook: [ich] spotted ssh !! pid=%d\n", task->pid);
    }
}


/* ─────────────────────────────────────────────────────────────────────────────
 * apr hook test (asynchronous page remap)
 *
 * replaces getppid with shadow page version
 * ───────────────────────────────────────────────────────────────────────────── */

// static unsigned int __apr_count = 0;

/*
 * replacement getppid
 * lives in shadow page, executes instead of real getppid
 */
// static asmlinkage long apr_hooked_getppid(const struct pt_regs *regs)
// {
//     return 1337;
// }


/* ─────────────────────────────────────────────────────────────────────────────
 * /proc/silkhook_debug - elb proof
 * ───────────────────────────────────────────────────────────────────────────── */

static int silkhook__debug_show(struct seq_file *m, void *v)
{
    uint32_t *hook_site;
    uint32_t instr;
    int i;
    int has_movz = 0, has_br = 0;

    seq_puts(m, "+---------------------+\n");
    seq_puts(m, "|  silkhook elb test  |\n");
    seq_puts(m, "+---------------------+\n\n");

    if (!__elb_hook.installed)
    {
        seq_puts(m, "elb hook NOT installed\n");
        return 0;
    }

    hook_site = (uint32_t *)__elb_hook.targ;
    instr = hook_site[0];

    seq_puts(m, "[1] single instr patch\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    seq_printf(m, "    hook addr:     %px\n", hook_site);
    seq_printf(m, "    curr instr:    %08x\n", instr);
    seq_printf(m, "    expected brk:  %08x\n", SILKHOOK_BRK_INSTR);
    seq_printf(m, "    orig instr:    %08x\n", __elb_hook.orig_instr);
    seq_printf(m, "    bytes changed: %d\n", 4);

    if (instr == SILKHOOK_BRK_INSTR)
        seq_puts(m, "    result:        GOOD - only 4 bytes modified!!\n\n");
    else
        seq_puts(m, "    result:        BAD\n\n");

    seq_puts(m, "[2] no jump sequences\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    seq_puts(m, "    scanning for inline hook sigs...\n");

    for (i = 0; i < 5; i++)
    {
        uint32_t ins = hook_site[i];

        if ((ins & 0xFF800000) == 0xD2800000)
            has_movz++;
        if ((ins >> 23) == (0xF28 >> 1) ||
            (ins >> 23) == (0xF2A >> 1) ||
            (ins >> 23) == (0xF2C >> 1) ||
            (ins >> 23) == (0xF2E >> 1))
            has_movz++;
        if ((ins & 0xFFFFFC1F) == 0xD61F0000)
            has_br++;
    }

    seq_printf(m, "    movz/movk spotted: %d\n", has_movz);
    seq_printf(m, "    br found:          %d\n", has_br);

    if (has_movz < 2 && has_br == 0)
        seq_puts(m, "    result:            GOOD - no shellcode pattern!!\n\n");
    else
        seq_puts(m, "    result:            BAD - jump seq detected\n\n");

    seq_puts(m, "[3] brk instr analysis\n");
    seq_puts(m, "    -------------------------------------------------------\n");

    if ((instr & 0xFFE0001F) == 0xD4200000)
    {
        uint16_t imm = (instr >> 5) & 0xFFFF;

        seq_printf(m, "    encoding:      brk #0x%04x\n", imm);
        seq_printf(m, "    opcode mask:   %08x & FFE0001F = D4200000 [GOOD]\n", instr);
        seq_puts(m, "    result:        GOOD - valid brk instr\n\n");
    }
    else {
        seq_puts(m, "    result:        BAD\n\n");
    }

    seq_puts(m, "[4] mem dump @ hook-site\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    for (i = 0; i < 8; i++)
    {
        seq_printf(m, "    %px: %08x", &hook_site[i], hook_site[i]);
        if (i == 0)
            seq_printf(m, "  <-- brk #0x%04x (hook)\n", SILKHOOK_BRK_IMM);
        else
            seq_puts(m, "\n");
    }

    return 0;
}

static int silkhook__debug_open(struct inode *inode, struct file *file)
{
    return single_open(file, silkhook__debug_show, NULL);
}

static const struct proc_ops silkhook_debug_ops = {
    .proc_open    = silkhook__debug_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


/* ─────────────────────────────────────────────────────────────────────────────
 * /proc/silkhook_ich - ich stats
 * ───────────────────────────────────────────────────────────────────────────── */

static int silkhook__ich_debug_show(struct seq_file *m, void *v)
{
    uint64_t exec, skip, cycles;

    seq_puts(m, "┌─────────────────────────────────────────┐\n");
    seq_puts(m, "│           silkhook ich stats            │\n");
    seq_puts(m, "└─────────────────────────────────────────┘\n\n");

    if (!__ich_hook.installed)
    {
        seq_puts(m, "[!]  ich hook NOT installed\n");
        return 0;
    }

    silkhook__ich_get_stats(&__ich_hook, &exec, &skip, &cycles);

    seq_puts(m, "┌─────────────────────────────────────────┐\n");
    seq_puts(m, "│ config                                  │\n");
    seq_puts(m, "├─────────────────────────────────────────┤\n");
    seq_printf(m, "│ targ:     %px              │\n",           __ich_hook.targ);
    seq_printf(m, "│ orig instr: %08x                    │\n",    __ich_hook.orig_instr);
    seq_printf(m, "│ coalesce:   every %4u irqs             │\n", __ich_hook.coalesce_n);
    seq_printf(m, "│ jitter:     %u-%u cycles                │\n",
               __ich_hook.jitter_min, __ich_hook.jitter_max);
    seq_puts(m, "└─────────────────────────────────────────┘\n\n");

    seq_puts(m, "┌─────────────────────────────────────────┐\n");
    seq_puts(m, "│ runtime stats                           │\n");
    seq_puts(m, "├─────────────────────────────────────────┤\n");
    seq_printf(m, "│ execs:      %8llu                    │\n", exec);
    seq_printf(m, "│ skipped:    %8llu                    │\n", skip);
    seq_printf(m, "│ total cyc:  %8llu                    │\n", cycles);
    if (exec > 0)
        seq_printf(m, "│ avg cycles: %8llu                    │\n", cycles / exec);
    seq_puts(m, "└─────────────────────────────────────────┘\n");

    return 0;
}

static int silkhook__ich_debug_open(struct inode *inode, struct file *file)
{
    return single_open(file, silkhook__ich_debug_show, NULL);
}

static const struct proc_ops silkhook_ich_debug_ops = {
    .proc_open    = silkhook__ich_debug_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


/* ─────────────────────────────────────────────────────────────────────────────
 * /proc/silkhook_apr - apr stats
 * ───────────────────────────────────────────────────────────────────────────── */

static int silkhook__apr_debug_show(struct seq_file *m, void *v)
{
    seq_puts(m, "┌─────────────────────────────────────────┐\n");
    seq_puts(m, "│           silkhook apr stats            │\n");
    seq_puts(m, "└─────────────────────────────────────────┘\n\n");

    if (!__apr_hook.installed)
    {
        seq_puts(m, "[!] apr hook NOT installed\n");
        return 0;
    }

    seq_puts(m, "┌─────────────────────────────────────────┐\n");
    seq_puts(m, "│ config                                  │\n");
    seq_puts(m, "├─────────────────────────────────────────┤\n");
    seq_printf(m, "│ targ:     %px              │\n", __apr_hook.targ);
    seq_printf(m, "│ shadow:     %px            │\n", __apr_hook.shadow);
    seq_printf(m, "│ orig_pfn:   %lx                       │\n", __apr_hook.pfn_orig);
    seq_printf(m, "│ hook_pfn:   %lx                       │\n", __apr_hook.pfn_hook);
    seq_printf(m, "│ active:     %s                         │\n",
               __apr_hook.active ? "yes" : "no");
    seq_puts(m, "└─────────────────────────────────────────┘\n\n");

    // seq_puts(m, "┌─────────────────────────────────────────┐\n");
    // seq_puts(m, "│ runtime stats                           │\n");
    // seq_puts(m, "├─────────────────────────────────────────┤\n");
    // seq_printf(m, "│ executions: %8u                    │\n", __apr_count);
    // seq_puts(m, "└─────────────────────────────────────────┘\n\n");

    seq_puts(m, "┌─────────────────────────────────────────┐\n");
    seq_puts(m, "│ technique                               │\n");
    seq_puts(m, "├─────────────────────────────────────────┤\n");
    seq_puts(m, "│ • two physical pages, one VA            │\n");
    seq_puts(m, "│ • swap via PTE pfn manipulation         │\n");
    seq_puts(m, "│ • atomic enable/disable                 │\n");
    seq_puts(m, "│ • no code patching                      │\n");
    seq_puts(m, "│ • forensics: can show clean page        │\n");
    seq_puts(m, "└─────────────────────────────────────────┘\n");

    return 0;
}

static int silkhook__apr_debug_open(struct inode *inode, struct file *file)
{
    return single_open(file, silkhook__apr_debug_show, NULL);
}

static const struct proc_ops silkhook_apr_debug_ops = {
    .proc_open    = silkhook__apr_debug_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


/* ─────────────────────────────────────────────────────────────────────────────
 * setup
 * ───────────────────────────────────────────────────────────────────────────── */

static void do_silkhook_setup(struct work_struct *work)
{
    int r;
    void *targ;

    pr_info("silkhook: setup started !!!\n");

    if (silkhook_ksyms_init() != 0)
        return;
    if (silkhook_mem_init() != 0)
        return;

    /*  svc hook  */
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

    /*  elb hook  */
    r = silkhook__elb_init();
    if (r != SILKHOOK_OK)
    {
        pr_err("silkhook: elb init failure: %d\n", r);
        goto skip_elb;
    }

    targ = silkhook_ksym("__arm64_sys_getpid");
    if (targ)
    {
        r = silkhook__elb_install(&__elb_hook, targ, elb_test_handler, NULL);
        if (r == SILKHOOK_OK)
            proc_create("silkhook_debug", 0444, NULL, &silkhook_debug_ops);
        else
            pr_err("silkhook: elb install failure: %d\n", r);
    }

skip_elb:
    /*  ich hook  */
    r = silkhook__ich_init();
    if (r != SILKHOOK_OK)
    {
        pr_err("silkhook: ich init failure: %d\n", r);
        goto skip_ich;
    }

    {
        struct silkhook_ich_cfg ich_cfg = {
            .coalesce_n  = 16,
            .jitter_min  = 10,
            .jitter_max  = 50,
            .payload     = ich_test_payload,
            .payload_ctx = NULL,
        };

        r = silkhook__ich_install(&__ich_hook, &ich_cfg);
        if (r == SILKHOOK_OK)
        {
            proc_create("silkhook_ich", 0444, NULL, &silkhook_ich_debug_ops);
            pr_info("silkhook: ich ready !!!\n");
        }
        else {
            pr_err("silkhook: ich install failure: %d\n", r);
        }
    }

skip_ich:
    /*  apr hook  */
    r = silkhook__apr_init();
    if (r != SILKHOOK_OK)
    {
        pr_err("silkhook: apr init failure: %d\n", r);
        goto skip_apr;
    }

    targ = silkhook_ksym("__arm64_sys_getppid");
    if (targ) {
        r = silkhook__apr_install(&__apr_hook, targ,
                                    apr_shellcode, sizeof(apr_shellcode));
        if (r == SILKHOOK_OK) {
            silkhook__apr_enable(&__apr_hook);
            proc_create("silkhook_apr", 0444, NULL, &silkhook_apr_debug_ops);
            pr_info("silkhook: apr ready !!!\n");
        } else {
            pr_err("silkhook: apr install failure: %d\n", r);
        }
    }

skip_apr:
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
    remove_proc_entry("silkhook_apr", NULL);
    remove_proc_entry("silkhook_ich", NULL);
    remove_proc_entry("silkhook_debug", NULL);

    cancel_delayed_work_sync(&setup_work);

    silkhook__unhide_mod(&__hidden);

    silkhook__apr_disable(&__apr_hook);
    silkhook__apr_remove(&__apr_hook);
    silkhook__apr_exit();

    silkhook__ich_remove(&__ich_hook);
    silkhook__ich_exit();

    silkhook__elb_remove(&__elb_hook);
    silkhook__elb_exit();

    silkhook__svc_remove(&__svc_hook);

    pr_info("silkhook: unloaded !!!\n");
}

module_init(silkhook_mod_init);
module_exit(silkhook_mod_exit);
