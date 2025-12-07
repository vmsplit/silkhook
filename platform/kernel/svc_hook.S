/*
 * silkhook   - miniature arm hooking lib
 * svc_hook.S - naked asm impl
 *
 * SPDX-License-Identifier: MIT
 *
 * invoke_syscall sig  (kernel 6.x):
 *   x0 = regs
 *   x1 = syscall num (scno)
 *   x2 = sc_nr (num of syscalls)
 *   x3 = syscall_table ptr
 *
 * credits: https://github.com/3intermute/arm64_silent_syscall_hook
 */

.text
.global el0_svc_common_hook
.global hooked_syscall_number
.global new_sys_call_table_ptr
.global el0_svc_common_ptr

el0_svc_common_hook:
    /*  nops to be replaced with orig instrs  */
    nop
    nop
    nop
    nop
    nop

    /*  load targ syscall num -> w12  */
    adrp    x12, hooked_syscall_number
    add     x12, x12, :lo12:hooked_syscall_number
    ldr     w12, [x12]

    /*  compare w/ curr syscall num (in w1)  */
    cmp     w1, w12
    b.eq    .Lredirect

.Lno_redirect:
    /*  load invoke_syscall addr  */
    adrp    x12, el0_svc_common_ptr
    add     x12, x12, :lo12:el0_svc_common_ptr
    ldr     x12, [x12]

    /*  jump to invoke_syscall + 20 : NOTE: skip 5 instrs
        cuz they were overwritten  */
    add     x12, x12, #20
    br      x12

.Lredirect:
    /*  load shadow tbl ptr -> x3  */
    adrp    x12, new_sys_call_table_ptr
    add     x12, x12, :lo12:new_sys_call_table_ptr
    ldr     x3, [x12]
    b       .Lno_redirect
