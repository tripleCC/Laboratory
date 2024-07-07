# Copyright (c) (2022,2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CC_ARM_ARCH_7 && CCN_MULMOD_384_ASM

CC_ASM_SUBSECTIONS_VIA_SYMBOLS

.text
.syntax unified
.code 16

/**
 * ARM32 implementation of Montgomery modular multiplication
 * and reduction for P-384.
 */

#define Z0 r0
#define Z1 r1
#define Z2 r2
#define Z3 r3
#define Z4 r4
#define Z5 r5
#define Z6 r6
#define Z7 r7
#define Z8 r8
#define Z9 r9
#define Z10 r10
#define Z11 r11
#define Z12 r12

#define u Z12
#define t r14
#define q Z0

/**
 * Montgomery REDC.
 *
 *     r += p384 * v
 *       += (2^384 - 2^128 - 2^96 + 2^32 - 1) * v
 *       += (v << 384) - (v << 128) - (v << 96) + (v << 32) - v
 *
 *     v = -p[0]^(-1) * r[0] (mod 2^32)
 *       = 1 * r[0] (mod 2^32)
 *       = r[0] (mod 2^32)
 *
 * The (384+32+1)-bit number in { Z0-Z12, carry } will have its least-significant
 * 32 bits (Z0) cleared. We right-shift by 32 bits and obtain a (384+1)-bit
 * number in { Z0-Z11, carry }.
 */
.align 2
.thumb_func
_partial_redc:
    push { lr }

    // Carry from previous round.
    adcs Z12, Z12, q

    mov t, #0
    adc t, t, #0

    // Reduce.
    adds Z1, Z1, q
    adcs Z2, Z2, #0
    adcs Z3, Z3, #0
    adcs Z4, Z4, #0
    adcs Z5, Z5, #0
    adcs Z6, Z6, #0
    adcs Z7, Z7, #0
    adcs Z8, Z8, #0
    adcs Z9, Z9, #0

    // Save Z1, so we can use q=Z0 a tad longer.
    push { Z1 }

    adcs Z10, Z10, #0
    adcs Z11, Z11, #0
    adcs Z12, Z12, #0
    adc    t,   t, #0

    mov  Z1, Z2
    subs Z2, Z3, q
    sbcs Z3, Z4, q
    sbcs Z4, Z5, #0
    sbcs Z5, Z6, #0
    sbcs Z6, Z7, #0
    sbcs Z7, Z8, #0
    sbcs Z8, Z9, #0

    // We don't need q any longer, set Z0 := Z1.
    pop { Z0 }

    sbcs  Z9, Z10, #0
    sbcs Z10, Z11, #0
    sbcs Z11, Z12, #0

    // Set carry := t.
    adcs t, t, 0xfffffffe

    pop { lr }
    bx lr


/**
 * Last step of Montgomery's REDC algorithm.
 *
 *   if Z >= M then Z = Z - M
 */
.macro final_sub
    // Set u := carry.
    mov u, #0
    adc u, u, #0

    // Subtract M.
    subs  Z0,  Z0, 0xffffffff
    sbcs  Z1,  Z1, #0
    sbcs  Z2,  Z2, #0
    sbcs  Z3,  Z3, 0xffffffff
    sbcs  Z4,  Z4, 0xfffffffe
    sbcs  Z5,  Z5, 0xffffffff
    sbcs  Z6,  Z6, 0xffffffff
    sbcs  Z7,  Z7, 0xffffffff
    sbcs  Z8,  Z8, 0xffffffff
    sbcs  Z9,  Z9, 0xffffffff
    sbcs Z10, Z10, 0xffffffff
    sbcs Z11, Z11, 0xffffffff

    // u = (Z < M) ? 0xffffffff : 0
    sbc u, u, #0

    // Add M back, if needed.
    adds  Z0,  Z0, u
    adcs  Z1,  Z1, #0
    adcs  Z2,  Z2, #0
    adcs  Z3,  Z3, u
    adcs  Z4,  Z4, u, lsl #1
    adcs  Z5,  Z5, u
    adcs  Z6,  Z6, u
    adcs  Z7,  Z7, u
    adcs  Z8,  Z8, u
    adcs  Z9,  Z9, u
    adcs Z10, Z10, u
    adc  Z11, Z11, u
.endm


/**
 * Montgomery modular multiplication.
 *
 * This implementation follows a Full Operand-Caching approach. The 768-bit
 * product P is stored on the stack and iteratively reduced modulo M.
 *
 * For 10 available registers {r3-r12} (w=10), we determine the size
 * of the caching operand `e` such that w <= e+1 + 2*e.
 *
 * For e=3, w = 3+1 + 2*3 = 10. The number of rows then is r = ⌊n/e⌋ = 4,
 * where n=12 is the number of limbs.
 */
.align 2
.globl _ccn_mulmod_p384
.thumb_func
_ccn_mulmod_p384: /* void ccn_mulmod_p384(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    push { r0, r4-r12, lr }

    #include "ccn_mulmod_p384-armv7-generated.inc"

    // Load Z.
    ldm sp, { Z0-Z12 }

    // Clear carry flag.
    adds t, t, #0

    // Partially reduce twelve times.
    bl _partial_redc

    ldr Z12, [sp, #(4*13)]
    bl _partial_redc

    ldr Z12, [sp, #(4*14)]
    bl _partial_redc

    ldr Z12, [sp, #(4*15)]
    bl _partial_redc

    ldr Z12, [sp, #(4*16)]
    bl _partial_redc

    ldr Z12, [sp, #(4*17)]
    bl _partial_redc

    ldr Z12, [sp, #(4*18)]
    bl _partial_redc

    ldr Z12, [sp, #(4*19)]
    bl _partial_redc

    ldr Z12, [sp, #(4*20)]
    bl _partial_redc

    ldr Z12, [sp, #(4*21)]
    bl _partial_redc

    ldr Z12, [sp, #(4*22)]
    bl _partial_redc

    ldr Z12, [sp, #(4*23)]
    bl _partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    add sp, #(24*4)
    pop { r14 }

    // Write Z.
    stm r14, { Z0-Z11 }

    pop { r4-r12, lr }
    bx lr

#endif
