/*
 * silkhook - miniature arm hooking lib
 * elb.h    - EL (Exception Level) Bounce PoC
 *
 * SPDX-License-Identifier: MIT
 *
 * technique:
 *   use brk #imm to triggr a debug exception, run hook code
 *   in the exception handler context.  no inline patching @
 *   the hook-site beyond a single brk instruction
 *
 *   from any observer's perspective, it's just a debug trap
 *   ..hypervisors expect brk instrs for kprobes, kgdb, etc etc
 *
 *   ┌─────────────────────────────────────────────────────────┐
 *   │  targ funct:                                            │
 *   │  ┌───────────────────────────────────────────────────┐  │
 *   │  │  ...                                              │  │
 *   │  │  brk  #SILKHOOK_BRK_IMM    ◀── trigger exception  │  │
 *   │  │  ...  (continue  after)                           │  │
 *   │  └───────────────────────────────────────────────────┘  │
 *   │                       │                                 │
 *   │                       ▼                                 │
 *   │  ┌───────────────────────────────────────────────────┐  │
 *   │  │  brk_handler:                                     │  │
 *   │  │    if (imm == SILKHOOK_BRK_IMM)                   │  │
 *   │  │    {                                              │  │
 *   │  │        ctx = lookup_by_pc(elr_el1);               │  │
 *   │  │        ctx->handler(regs);                        │  │
 *   │  │        return DBG_HOOK_HANDLED;                   │  │
 *   │  │    }                                              │  │
 *   │  └───────────────────────────────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────┘
 *
 * why?:
 *   - no funct prologue modif
 *   - hook code runs in exception ctx  (like it'll be expected to)
 *   - brk instrs r expected by kernel  (kprobes, kgdb)
 *   - hypervisor's should see normal debug exception flow
 *   - mem scanners see a single brk, not a seq of jumps
 */

#ifndef _SILKHOOK_ELB_H_
#define _SILKHOOK_ELB_H_

#include <linux/types.h>


#define SILKHOOK_BRK_IMM    0x5148
#define SILKHOOK_BRK_INSTR  (0xD4200000 | (SILKHOOK_BRK_IMM << 5))


/* ─────────────────────────────────────────────────────────────────────────────
 * core elb hook context
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_elb_hook;

typedef void (*silkhook_elb_handler_t)(struct pt_regs *regs,
                                       struct silkhook_elb_hook *ctx);

struct silkhook_elb_hook
{
    void                     *targ;
    silkhook_elb_handler_t   handler;
    void                     *priv;
    uint32_t                 orig_instr;
    int                      installed;
    struct silkhook_elb_hook *next;
};


/* ─────────────────────────────────────────────────────────────────────────────
 * elb API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__elb_init(void);
void silkhook__elb_exit(void);

int silkhook__elb_install(struct silkhook_elb_hook *h, void *targ,
                          silkhook_elb_handler_t handler, void *priv);
int silkhook__elb_remove(struct silkhook_elb_hook *h);


#endif /* _SILKHOOK_ELB_H_ */
