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
#include <asm/unistd.h>

#include "include/silkhook.h"
#include "platform/kernel/ksyms.h"
#include "platform/kernel/hide.h"
#include "platform/kernel/memory.h"
#include "platform/kernel/svc.h"
#include "platform/kernel/shadow.h"
#include "platform/kernel/elb.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vmsplit");
MODULE_DESCRIPTION("silkhook test0000002992929292");


static struct delayed_work setup_work;
static struct silkhook_svc_hook   __svc_hook;
static struct silkhook_hidden_mod __hidden;
static struct silkhook_elb_hook   __elb_hook;
static unsigned int               __trigger_count;


/* ─────────────────────────────────────────────────────────────────────────────
 * svc hook test (shadow tbl)
 * ───────────────────────────────────────────────────────────────────────────── */

asmlinkage long hooked_getuid(void);

asmlinkage long hooked_getuid(void)
{
    __trigger_count++;
    if (__trigger_count % 10 == 1)
        pr_info("silkhook: [svc] getuid called !! count=%u\n", __trigger_count);

    return current_uid().val;
}


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
        seq_puts(m, "silkhook: elb hook NOT installed\n");
        return 0;
    }

    hook_site = (uint32_t *) __elb_hook.targ;
    instr = hook_site[0];

    /* ─────────────────────────────────────────────────────────────────────
     * debug 1:  4 byte single instr patch
     * ───────────────────────────────────────────────────────────────────── */
    seq_puts(m, "[1] single instr patch\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    seq_printf(m, "    hook addr:     %px\n",  hook_site);
    seq_printf(m, "    curr instr:    %08x\n", instr);
    seq_printf(m, "    expected brk:  %08x\n", SILKHOOK_BRK_INSTR);
    seq_printf(m, "    orig instr:    %08x\n", __elb_hook.orig_instr);
    seq_printf(m, "    bytes changed: %d\n", 4);

    if (instr == SILKHOOK_BRK_INSTR)
        seq_puts(m, "    result:        GOOD - only 4 bytes modified!!\n\n");
    else
        seq_puts(m, "    result:        BAD  - unexpected instr!!\n\n");


    /* ─────────────────────────────────────────────────────────────────────
     * debug 2:  no jump seqs visible
     * ───────────────────────────────────────────────────────────────────── */
    seq_puts(m, "[2] no jump sequences\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    seq_puts(m, "    scanning for inline hook sigs...\n");

    for (i = 0; i < 5; i++)
    {
        uint32_t ins = hook_site[i];
        /*  movz xN, #imm = 0xD28.....  */
        if ((ins & 0xFF800000) == 0xD2800000)
        {
            has_movz++;
            seq_printf(m, "      [!]  movz @ +%02x: %08x\n", i * 4, ins);
        }
        /*  movk xN, #imm = 0xF2......  */
        if ((ins & 0xFF800000) == 0xF2800000 ||
            (ins & 0xFF800000) == 0xF2A00000 ||
            (ins & 0xFF800000) == 0xF2C00000 ||
            (ins & 0xFF800000) == 0xF2E00000)
        {
            has_movz++;
            seq_printf(m, "      [!] movk @ +%02x:  %08x\n", i * 4, ins);
        }
        /*  br xN = 0xD61F0...  */
        if ((ins & 0xFFFFFC1F) == 0xD61F0000)
        {
            has_br++;
            seq_printf(m, "      [!] br   @ +%02x:  %08x\n", i * 4, ins);
        }
    }

    seq_printf(m, "    movz/movk spotted: %d\n", has_movz);
    seq_printf(m, "    br found:          %d\n", has_br);

    if (has_movz < 2 && has_br == 0)
        seq_puts(m, "    result:          GOOD - no shellcode pattern!!\n\n");
    else
        seq_puts(m, "    result:          BAD  - jump sequence spotted!!\n\n");

    /* ─────────────────────────────────────────────────────────────────────
     * debug 3:  brk instr analysis
     * ───────────────────────────────────────────────────────────────────── */
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
        seq_puts(m, "    result:        BAD  - not a brk instr\n\n");
    }

    /* ─────────────────────────────────────────────────────────────────────
     * debug 4:  brk integrity  (kernel ctx)
     * ───────────────────────────────────────────────────────────────────── */
    seq_puts(m, "[4] brk integrity\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    seq_puts(m, "    kernel brk imm vals:\n");
    seq_puts(m, "      0x0004       kprobes single-step\n");
    seq_puts(m, "      0x0005       kprobes breakpoint\n");
    seq_puts(m, "      0x0006       uprobes breakpoint\n");
    seq_puts(m, "      0x0400       kgdb breakpoint\n");
    seq_puts(m, "      0x0800       BUG()  macro\n");
    seq_puts(m, "      0x09xx       WARN() macro\n");
    seq_puts(m, "      0x5xxx       kasan\n");
    seq_printf(m, "      0x%04x       silkhook  <--  (our hook)\n", SILKHOOK_BRK_IMM);
    seq_puts(m, "    result:        GOOD - should look like debug / kasan use\n\n");

    /* ─────────────────────────────────────────────────────────────────────
     * debug 5:  mem dump
     * ───────────────────────────────────────────────────────────────────── */
    seq_puts(m, "[5] mem dump @ hook-site\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    for (i = 0; i < 8; i++)
    {
        seq_printf(m, "    %px: %08x", &hook_site[i], hook_site[i]);
        if (i == 0)
            seq_printf(m, "  <-- brk #0x%04x (hook)\n", SILKHOOK_BRK_IMM);
        else
            seq_puts(m, "\n");
    }

    /* ─────────────────────────────────────────────────────────────────────
     * debug 6:  cmp with inline hook
     * ───────────────────────────────────────────────────────────────────── */
    seq_puts(m, "\n[6] compare:  elb vs inline hook\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    seq_puts(m, "    technique        bytes   pattern             detectable\n");
    seq_puts(m, "    -------------------------------------------------------\n");
    seq_puts(m, "    inline  (ldr+br) 16      ldr x16,[pc,#8];br  high\n");
    seq_puts(m, "    inline  (mov+br) 20      movz;movk;movk;br   high\n");
    seq_puts(m, "    elb  (brk)       4       brk #imm            low\n");
    seq_puts(m, "    -------------------------------------------------------\n");

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
 * elb hook test  (exception bounce)
 * ───────────────────────────────────────────────────────────────────────────── */

static unsigned int __elb_count;

static void elb_test_handler(struct pt_regs *regs, struct silkhook_elb_hook *ctx)
{
    __elb_count++;

    /*  dump callstack on  1st invoke as proof  */
    if (__elb_count == 1)
    {
        pr_info("silkhook: --------------------------------------------\n");
        pr_info("silkhook:   [elb]  callstack proof\n");
        pr_info("silkhook:   [elb]  proving hook runs in exception path:\n");
        pr_info("silkhook: --------------------------------------------\n");
        dump_stack();
        pr_info("silkhook: --------------------------------------------\n");
    }

    if (__elb_count % 100 == 1)
        pr_info("silkhook: [elb] exception bounce !! pc=%lx count=%u\n",
                instruction_pointer(regs), __elb_count);
}


/* ─────────────────────────────────────────────────────────────────────────────
 * setup
 * ───────────────────────────────────────────────────────────────────────────── */

static void do_silkhook_setup(struct work_struct *work)
{
    int r;
    void *targ;

    pr_info("silkhook: setup started !!
        !\n");

    if (silkhook_ksyms_init() != 0) return;
    if (silkhook_mem_init() != 0) return;

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

    /*  elb hook hook..something that gets called frequently  */
    r = silkhook__elb_init();
    if (r != SILKHOOK_OK)
    {
        pr_err("silkhook: elb init failure: %d\n", r);
        goto skip_elb;
    }

    /*  e.g.: hook the entry of some kernel funct
     *  NOTE: something that doesn't cause recursion!!!  */
    targ = silkhook_ksym("__arm64_sys_getpid");
    if (targ)
    {
        r = silkhook__elb_install(&__elb_hook, targ, elb_test_handler, NULL);
        proc_create("silkhook_debug", 0444, NULL, &silkhook_debug_ops);
        if (r != SILKHOOK_OK)
            pr_err("silkhook: elb install failure: %d\n", r);
    }

skip_elb:
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
    remove_proc_entry("silkhook_debug", NULL);
    cancel_delayed_work_sync(&setup_work);
    silkhook__unhide_mod(&__hidden);
    silkhook__elb_remove(&__elb_hook);
    silkhook__elb_exit();
    silkhook__svc_remove(&__svc_hook);
    pr_info("silkhook: unloaded !!!\n");
}

module_init(silkhook_mod_init);
module_exit(silkhook_mod_exit);
