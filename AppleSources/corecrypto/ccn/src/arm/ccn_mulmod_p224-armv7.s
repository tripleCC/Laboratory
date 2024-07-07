# Copyright (c) (2019,2021-2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CC_ARM_ARCH_7 && CCN_MULMOD_224_ASM

CC_ASM_SUBSECTIONS_VIA_SYMBOLS

.text
.syntax unified
.code 16

/**
 * ARM32 implementation of Montgomery modular multiplication and reduction
 * for P-224.
 */

#define Z0 r2
#define Z1 r3
#define Z2 r4
#define Z3 r5
#define Z4 r6
#define Z5 r7
#define Z6 r8
#define Z7 r9

#define u r10
#define q r11
#define t r12

/**
 * Montgomery REDC.
 *
 *     r += p224 * v
 *       += (2^224 - 2^96 + 1) * v
 *       += (v << 224) - (v << 96) + v
 *
 *     v = -p[0]^(-1) * r[0] (mod 2^32)
 *       = -1 * r[0]         (mod 2^32)
 *       = -r[0]             (mod 2^32)
 *
 * The (224+32+1)-bit number in { Z0-Z7, t } will have its least-significant
 * 64 bits (Z0) cleared. We right-shift by 32 bits and obtain a (224+1)-bit
 * number in { Z0-Z6, t }.
 */
.align 2
.thumb_func
_partial_redc:
    neg q, Z0

    // Carry.
    adds u, q, t
    mov  t, #0
    adc  t, t, #0

    // Reduce.
    adds Z0, Z0, q
    adcs Z0, Z1, #0
    adcs Z1, Z2, #0
    adcs Z2, Z3, #0
    adcs Z3, Z4, #0
    adcs Z4, Z5, #0
    adcs Z5, Z6, #0
    adcs Z6, Z7, u
    adc   t,  t, #0

    subs Z2, Z2, q
    sbcs Z3, Z3, #0
    sbcs Z4, Z4, #0
    sbcs Z5, Z5, #0
    sbcs Z6, Z6, #0
    sbc   t,  t, #0

    bx lr


/**
 * Last step of Montgomery's REDC algorithm.
 *
 *   if Z >= M then Z = Z - M
 */
.macro final_sub
    // Subtract M.
    subs Z0, Z0, #1
    sbcs Z1, Z1, #0
    sbcs Z2, Z2, #0
    sbcs Z3, Z3, 0xffffffff
    sbcs Z4, Z4, 0xffffffff
    sbcs Z5, Z5, 0xffffffff
    sbcs Z6, Z6, 0xffffffff

    // u := (Z < M) ? 0xffffffff : 0
    sbc u, t, #0

    // Add p back, if needed.
    adds Z0, Z0, u, lsr #31
    adcs Z1, Z1, #0
    adcs Z2, Z2, #0
    adcs Z3, Z3, u
    adcs Z4, Z4, u
    adcs Z5, Z5, u
    adc  Z6, Z6, u
.endm


/**
 * Montgomery modular multiplication.
 *
 * This implementation follows a Full Operand-Caching approach. The 448-bit
 * product P is stored on the stack and iteratively reduced modulo M.
 *
 * For 10 available registers {r3-r12} (w=10), we determine the size
 * of the caching operand `e` such that w <= e+1 + 2*e.
 *
 * For e=3, w = 3+1 + 2*3 = 10. The number of rows then is r = ⌊n/e⌋ = 2,
 * where n=7 is the number of limbs, leaving a partial initial block.
 */
.align 2
.globl _ccn_mulmod_p224
.thumb_func
_ccn_mulmod_p224: /* void ccn_mulmod_p224(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    push { r4-r12, lr }

    #include "ccn_mulmod_p224-armv7-generated.inc"

    // Load Z.
    ldm sp, { Z0-Z7 }

    mov t, #0

    // Partially reduce seven times.
    bl _partial_redc

    ldr Z7, [sp, #(4*8)]
    bl _partial_redc

    ldr Z7, [sp, #(4*9)]
    bl _partial_redc

    ldr Z7, [sp, #(4*10)]
    bl _partial_redc

    ldr Z7, [sp, #(4*11)]
    bl _partial_redc

    ldr Z7, [sp, #(4*12)]
    bl _partial_redc

    ldr Z7, [sp, #(4*13)]
    bl _partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stm r0, { Z0-Z6 }

    add sp, #(14*4)
    pop { r4-r12, lr }
    bx lr

#endif
