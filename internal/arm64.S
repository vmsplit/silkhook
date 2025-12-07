/**
 * silkhook - miniature arm64 hooking lib
 * arm64.S  - asm primitives
 *
 * SPDX-License-Identifier: MIT
 */

.text


/* ─────────────────────────────────────────────────────────────────────────────
 * cache maintenance
 *
 * __silkhook_flush_icache(addr, len)
 *     x0 = start addr
 *     x1 = len
 *
 * flushes dcache to PoU, inval icache
 * ───────────────────────────────────────────────────────────────────────────── */

.globl __silkhook_flush_icache
.align 4
__silkhook_flush_icache:
    // save orig start/len
    mov     x2, x0
    add     x3, x0, x1

    // align down to cache line (64 bytes)
    and     x0, x2, #~0x3f

    // ensure prior stores complete
    dsb     ish

.Ldc_loop:
    // clean dcache to PoU
    dc      cvau, x0
    add     x0, x0, #64
    cmp     x0, x3
    b.lt    .Ldc_loop

    // ensure dcache clean complete
    dsb     ish

    // reset for icache
    and     x0, x2, #~0x3f

.Lic_loop:
    // inval icache
    ic      ivau, x0
    add     x0, x0, #64
    cmp     x0, x3
    b.lt    .Lic_loop

    // ensure icache inval complete
    dsb     ish

    // sync instr stream
    isb

    ret


/* ─────────────────────────────────────────────────────────────────────────────
 * pt_regs size  (16-byte aligned)
 *
 * x0-x30 (31 regs * 8) + sp + pc + pstate = 272 bytes
 * ───────────────────────────────────────────────────────────────────────────── */

#define SILKHOOK_PT_REGS_SIZE 272


/* ─────────────────────────────────────────────────────────────────────────────
 * hook entry macro
 *
 * output:
 *     <func>_hook_entry    - entry point,  saves regs, calls handler
 *     <func>_orig          - trampoline to call orig
 *     <func>_reloc_ret     - return trampoline
 *
 * handler signature:
 *     void <func>_hook_handler(struct silkhook_pt_regs *regs)
 * ───────────────────────────────────────────────────────────────────────────── */

.macro silkhook_entry func

.extern \func\()_hook_handler

.globl \func\()_hook_entry
.align 12
\func\()_hook_entry:
    // restore x0 if came via safe jump
    ldr     x0, [sp], #16

    // allocate pt_regs
    sub     sp, sp, #SILKHOOK_PT_REGS_SIZE

    // save x0-x29
    stp     x0, x1,   [sp, #0]
    stp     x2, x3,   [sp, #16]
    stp     x4, x5,   [sp, #32]
    stp     x6, x7,   [sp, #48]
    stp     x8, x9,   [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]

    // save pstate
    mrs     x1, spsr_el1
    str     x1, [sp, #248]

    // call handler with pt_regs ptr
    mov     x0, sp
    bl      \func\()_hook_handler

    // restore pstate
    ldr     x1, [sp, #248]
    msr     spsr_el1, x1

    // restore x0-x29
    ldp     x0, x1,   [sp, #0]
    ldp     x2, x3,   [sp, #16]
    ldp     x4, x5,   [sp, #32]
    ldp     x6, x7,   [sp, #48]
    ldp     x8, x9,   [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]

    add     sp, sp, #SILKHOOK_PT_REGS_SIZE
    ret


// trampoline - call orig function
.globl \func\()_orig
\func\()_orig:
    // slots for reloc'd orig instrs (filled at install)
    nop                         // b . +8
    nop                         // ret
    nop                         // str x0, [sp, #-16]!
    nop                         // movz x0,  #...
    nop                         // movk x0,  #...
    nop                         // movk x0,  #...
    nop                         // movk x0,  #...
    nop                         // br x0
    nop                         // ldr x0, [sp], #16


// return trampoline
.globl \func\()_reloc_ret
\func\()_reloc_ret:
    nop                         // junk (b .+8)
    nop                         // junk (ret)
    str     x0, [sp, #-16]!     // push x0
    nop                         // movz x0,  #(func + hook_size - pop_size)
    nop                         // movk x0,  #...
    nop                         // movk x0,  #...
    nop                         // movk x0,  #...
    br      x0                  // jump back
    nop                         // junk (ldr x0, [sp], #16)

.endm
