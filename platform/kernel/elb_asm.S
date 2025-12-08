/*
 * silkhook  - miniature arm hooking lib
 * elb_asm.S - elb asm helpers
 *
 * SPDX-License-Identifier: MIT
 */

.text

/* ─────────────────────────────────────────────────────────────────────────────
 * silkhook_elb_trigger
 *
 * explicit triggr for elb hook  (if opted to call manually)
 * normally you'd patch the brk into the targ,  but this is useful
 * for testing or explicit invoke
 *
 *   x0 =  ctx ptr (passed 2 handler via regs->x0)
 * ───────────────────────────────────────────────────────────────────────────── */

.global silkhook_elb_trigger
.align 4
silkhook_elb_trigger:
    brk     #0x5148
    ret
