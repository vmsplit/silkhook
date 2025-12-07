/*
 * silkhook     - miniature arm64 hooking lib
 * arch_arm32.h - arm32 arch definitions
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_ARCH_ARM32_H_
#define _SILKHOOK_ARCH_ARM32_H_

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
#endif


/* ─────────────────────────────────────────────────────────────────────────────
 * arm32 constants
 *
 * NOTE: PC reads as current instr  + 8  in ARM mode
 *       PC reads as current instr  + 4  in thumb mode
 * ───────────────────────────────────────────────────────────────────────────── */

#define __ARM32_INSTR_SIZE        4u
#define __ARM32_HOOK_N_INSTR      3u
#define __ARM32_HOOK_N_BYTE       (__ARM32_INSTR_SIZE * __ARM32_HOOK_N_INSTR)
#define __ARM32_TRAMPOLINE_MAX    64

#define __THUMB_INSTR_SIZE        2u
#define __THUMB_HOOK_N_INSTR      6u  /* 6 x 16-bit = 12 bytes */
#define __THUMB_HOOK_N_BYTE       (__THUMB_INSTR_SIZE * __THUMB_HOOK_N_INSTR)


/* ─────────────────────────────────────────────────────────────────────────────
 * thumb mode detection
 *
 * LSB of func ptr indicates mode:
 *   1 = thumb mode
 *   0 = arm mode
 * ───────────────────────────────────────────────────────────────────────────── */

#define __IS_THUMB(addr)        (((uintptr_t)(addr)) & 1u)
#define __STRIP_THUMB(addr)     ((uintptr_t)(addr) & ~1u)
#define __ADD_THUMB(addr)       ((uintptr_t)(addr) | 1u)


/* ─────────────────────────────────────────────────────────────────────────────
 * arm mode instructions
 * ───────────────────────────────────────────────────────────────────────────── */

#define __ARM32_COND_AL         0xE0000000u

/*  nop (mov r0, r0)  */
#define __ARM32_NOP() \
    (0xE1A00000u)

/*  b <off> (pc-relative,  signed, word aligned)
 *  NOTE!!!: pc is +8 ahead during exec  */
#define __ARM32_B(off) \
    (__ARM32_COND_AL | 0x0A000000u | ((((off) - 8) >> 2) & 0x00FFFFFFu))

/*  bl <off>  */
#define __ARM32_BL(off) \
    (__ARM32_COND_AL | 0x0B000000u | ((((off) - 8) >> 2) & 0x00FFFFFFu))

/*  bx <reg>  */
#define __ARM32_BX(reg) \
    (0xE12FFF10u | (reg))

/*  ldr pc, [pc, #-12]  - load pc from embedded addr  */
#define __ARM32_LDR_PC_M12() \
    (0xE51FF00Cu)

#define __ARM32_LDR_LIT_MASK    0x0F7F0000u
#define __ARM32_LDR_LIT_OP      0x051F0000u

/*  decode LDR lit off  */
#define __ARM32_DEC_LDR_LIT(instr) \
    ((((instr) & (1u << 23)) ? 1 : -1) * ((int32_t)((instr) & 0xFFFu)) + 8)

/*  movw <reg>, #<imm16> (ARMv6T2+)  */
#define __ARM32_MOVW(reg, imm) \
    (0xE3000000u | (((imm) & 0xF000u) << 4) | ((reg) << 12) | ((imm) & 0xFFFu))

/*  movt <reg>, #<imm16> (ARMv6T2+)  */
#define __ARM32_MOVT(reg, imm) \
    (0xE3400000u | (((imm) & 0xF000u) << 4) | ((reg) << 12) | ((imm) & 0xFFFu))

/*  push {<reg>}  */
#define __ARM32_PUSH(reg) \
    (0xE52D0004u | ((reg) << 12))

/*  pop {<reg>}  */
#define __ARM32_POP(reg) \
    (0xE49D0004u | ((reg) << 12))


/* ─────────────────────────────────────────────────────────────────────────────
 * arm abs jump seq  (12 bytes)
 *
 *   b   +4               ; skip over embedded addr
 *   .long addr          ; embedded 32-bit targ addr
 *   ldr pc, [pc, #-12]   ; load pc from the embedded addr
 *
 * why -12?   at the ldr, PC = ldr_addr    + 8
 *            embedded addr is at ldr_addr - 4
 *            off = (ldr_addr - 4) - (ldr_addr + 8) = -12
 * ───────────────────────────────────────────────────────────────────────────── */

#define __ARM32_ABS_JMP(buf, targ) do { \
    (buf)[0] = 0xEA000000u;              /* b +4 (skip addr) */   \
    (buf)[1] = (uint32_t)(targ);         /* embedded addr */      \
    (buf)[2] = 0xE51FF00Cu;              /* ldr pc, [pc, #-12] */ \
} while (0)


/* ─────────────────────────────────────────────────────────────────────────────
 * thumb mode instructions
 *
 * thumb uses 16-bit instrs,  but can have 32-bit thumb2 instructions.
 * So, for hooking,  we can use thumb2 for the abs jump
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * thunb abs jump seq  (12 bytes = 6 half-words)
 *
 *   ldr. w pc, [pc, #0]  ; load PC from next word (thumb2: 4 bytes)
 *   .align 4
 *   .long addr           ; targ addr  (must have thumb bit set!)
 *
 * encoding: ldr. w pc, [pc, #0] = 0xF000 0xF8DF
 *   1st halfword:  0xF8DF
 *   2nd halfword:  0xF000
 *
 * ...but we need to handle alignment,  so we use somethig simpler:
 *
 *   push {r0}            ; save r0        (2 bytes)
 *   ldr  r0, [pc, #4]    ; load addr      (2 bytes)
 *   mov  pc, r0          ; jump           (2 bytes)  --  actually use bx r0
 *   pop  {r0}            ; never reached! (2 bytes)  --  use as padding
 *   .long addr           ; targ         (4 bytes)
 *
 * total:  12 bytes , but we trash r0...
 *
 * better seq using LDR PC (thumb2):
 *   ldr. w pc, [pc, #0]  ; 4 bytes - loads from PC+4  (aligned)
 *   nop                  ; 2 bytes - padding for alignment
 *   .long addr           ; 4 bytes - targ (with thumb bit if thumb targ)
 *   nop                  ; 2 bytes - padding
 *
 * total:  12 bytes
 */

#define __THUMB2_LDR_PC_0_LO    0xF8DFu
#define __THUMB2_LDR_PC_0_HI    0xF000u

#define __THUMB_NOP             0xBF00u

/*  we can pack 2 16-bit vals into 32-bit for our codebuf  */
#define __THUMB_PACK(lo, hi)    (((uint32_t)(hi) << 16) | (uint32_t)(lo))

/*
 * thumb abs jump  (12 bytes = 3 x uint32_t in our codebuf)
 *
 * mem layout (in bytes):
 *   [0-1]  ldr. w pc, [pc, #0] low  (0xF8DF)
 *   [2-3]  ldr.w pc,  [pc, #0] high (0xF000)
 *   [4-5]  nop (0xBF00) - pad!!!
 *   [6-7]  nop (0xBF00) - even more padding to align addr
 *   [8-11] targ addr  (with thumb bit if needed)
 *
 * actually..., ldr.w pc, [pc, #imm] loads from (PC + 4 + imm) & ~3
 * pc during exec = addr of ldr. w + 4
 * ...soooo PC+4 = addr of ldr. w + 8, then &~3 2 align
 * we need imm such that  (PC + 4 + imm) & ~3  points to our addr!!
 *
 * better to just use a reg-based approach cuz it'll be more predictable ig..
 */

/*
 * trivial thumb abs jump  (12 bytes)
 *
 *   push {r4}           ; 2 bytes - B401
 *   ldr  r4, [pc, #4]   ; 2 bytes - 4C01  (loads from PC+4, word aligned = +8 from here )
 *   bx   r4             ; 2 bytes - 4720
 *   pop  {r4}           ; 2 bytes - BC01  (never reached!!, padded)
 *   .long addr          ; 4 bytes - targ
 *
 * total:  12 bytes
 */
#define __THUMB_PUSH_R4         0xB401u
#define __THUMB_LDR_R4_PC_4     0x4C01u
#define __THUMB_BX_R4           0x4720u
#define __THUMB_POP_R4          0xBC01u

#define __THUMB_ABS_JMP(buf, targ) do { \
    (buf)[0] = __THUMB_PACK(__THUMB_PUSH_R4, __THUMB_LDR_R4_PC_4); \
    (buf)[1] = __THUMB_PACK(__THUMB_BX_R4, __THUMB_POP_R4); \
    (buf)[2] = (uint32_t)(targ); \
} while (0)


/* ─────────────────────────────────────────────────────────────────────────────
 * decode helpers
 * ───────────────────────────────────────────────────────────────────────────── */

#define __ARM32_SEXT(val, bits) \
    ((int32_t)(((uint32_t)(val) ^ (1u << ((bits) - 1))) - (1u << ((bits) - 1))))

/*  decode B/BL offset (result in bytes)  */
#define __ARM32_DEC_B(instr) \
    ((__ARM32_SEXT((instr) & 0x00FFFFFFu, 24) << 2) + 8)

/*  extract reg fields  */
#define __ARM32_RD(instr)       (((instr) >> 12) & 0xFu)
#define __ARM32_RN(instr)       (((instr) >> 16) & 0xFu)
#define __ARM32_COND(instr)     (((instr) >> 28) & 0xFu)


#endif /* _SILKHOOK_ARCH_ARM32_H_ */
