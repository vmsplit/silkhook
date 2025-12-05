/*
 * silkhook - arm32 asm primitives
 * SPDX-License-Identifier: MIT
 */


.text
.arm

/* ─────────────────────────────────────────────────────────────────────────────
 * __silkhook_flush_icache(addr, len)
 *     r0 = start addr
 *     r1 = len
 * ───────────────────────────────────────────────────────────────────────────── */

.globl __silkhook_flush_icache
.type  __silkhook_flush_icache, %function
__silkhook_flush_icache:
    push    {r4, r7, lr}

    mov     r4, r0              /* save start addr */
    add     r1, r0, r1          /* r1 = end addr */
    mov     r0, r4              /* r0 = start addr */
    mov     r2, #0              /* flags = 0 */
    mov     r7, #0xf0000        /* __ARM_NR_cacheflush upper */
    add     r7, r7, #0x02       /* __ARM_NR_cacheflush = 0xf0002 */
    svc     #0

    pop     {r4, r7, pc}

.size __silkhook_flush_icache, .-__silkhook_flush_icache

.section .note.GNU-stack,"",%progbits
