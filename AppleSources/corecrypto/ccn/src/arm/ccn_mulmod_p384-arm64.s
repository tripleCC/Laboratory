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

#if defined(__arm64__) && CCN_MULMOD_384_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

/**
 * ARM64 implementations of Montgomery modular multiplication and reduction
 * for P-384.
 */

#define v x1
#define u x2
#define q x3

#define Z0 x4
#define Z1 x5
#define Z2 x6
#define Z3 x7
#define Z4 x8
#define Z5 x9
#define Z6 x10
#define Z7 x11

#define A0 x12
#define A1 x13
#define A2 x14
#define A3 x15
#define A4 x16
#define A5 x17

#define B0 x19
#define B1 x20
#define B2 x21
#define B3 x22
#define B4 x23
#define B5 x24


/**
 * Montgomery REDC.
 *
 *     r += p384 * v
 *       += (2^384 - 2^128 - 2^96 + 2^32 - 1) * v
 *       += (v << 384) - (v << 128) - (v << 96) + (v << 32) - v
 *
 *     v =   -p[0]^(-1) * r[0] (mod 2^64)
 *       =  0x100000001 * r[0] (mod 2^64)
 *       = (r[0] << 32) + r[0] (mod 2^64)
 *
 * The 512-bit number in registers {Z7-Z0} will have its least-significant
 * 64 bits (Z0) cleared. We right-shift by 64 bits and obtain a 448-bit
 * number in registers {Z6-Z0}.
 */
.macro partial_redc
    adds v, Z0, Z0, lsl #32
    lsr  u, v, #32

    adcs Z0, Z1, u
    adcs Z1, Z2, xzr
    adcs Z2, Z3, xzr
    adcs Z3, Z4, xzr
    adcs Z4, Z5, xzr
    adcs Z5, Z6, v
    adc  Z6, Z7, xzr

    subs Z0, Z0, v, lsl #32
    sbcs Z1, Z1, v
    cinc q, xzr, cc

    subs Z1, Z1, u
    sbcs Z2, Z2, q
    sbcs Z3, Z3, xzr
    sbcs Z4, Z4, xzr
    sbcs Z5, Z5, xzr
    sbc  Z6, Z6, xzr
.endm


/**
 * Last step of Montgomery's REDC algorithm.
 *
 *   if Z >= M then Z = Z - M
 */
.macro final_sub
    mov u, 0xffffffff00000000 // m[0:1]
    mov v, 0xfffffffffffffffe // m[2]
    mov q, 0xffffffffffffffff // m[3:]

    // Subtract M.
    subs Z0, Z0, u, lsr #32
    sbcs Z1, Z1, u
    sbcs Z2, Z2, v
    sbcs Z3, Z3, q
    sbcs Z4, Z4, q
    sbcs Z5, Z5, q

    // q = (Z < M) ? 0xffffffffffffffff : 0
    sbc q, Z6, xzr

    // Clear u,v if (Z >= M).
    and u, u, q
    and v, v, q

    // Add M back, if needed.
    adds Z0, Z0, u, lsr #32
    adcs Z1, Z1, u
    adcs Z2, Z2, v
    adcs Z3, Z3, q
    adcs Z4, Z4, q
    adc  Z5, Z5, q
.endm


/**
 * Montgomery modular multiplication.
 *
 * This implementation follows a Coarsely Integrated Product Scanning
 * approach. A and B are multiplied using product scanning and six partial
 * Montgomery reductions are performed on intermediate results - alternating
 * between multiplication and reduction.
 */
.align 4
.globl _ccn_mulmod_p384
_ccn_mulmod_p384: /* void ccn_mulmod_p384(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    // Store x19-x24.
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!

    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1], #16
    ldp A4, A5, [x1]

    // Load B.
    ldp B0, B1, [x2], #16
    ldp B2, B3, [x2], #16
    ldp B4, B5, [x2]

    // Z0 = A0 * B0
    mul   Z0, A0, B0
    umulh Z1, A0, B0

    // Z1 += A1 * B0
    mul    v, A1, B0
    umulh Z2, A1, B0

    adds Z1, Z1, v
    adc  Z2, Z2, xzr

    // Z1 += A0 * B1
    mul   v, A0, B1
    umulh u, A0, B1

    adds Z1, Z1, v
    adcs Z2, Z2, u
    adc  Z3, xzr, xzr

    // Z2 += A2 * B0
    mul   v, A2, B0
    umulh u, A2, B0

    adds Z2, Z2, v
    adcs Z3, Z3, u
    adc  Z4, xzr, xzr

    // Z2 += A1 * B1
    mul   v, A1, B1
    umulh u, A1, B1

    adds Z2, Z2, v
    adcs Z3, Z3, u
    adc  Z4, Z4, xzr

    // Z2 += A0 * B2
    mul   v, A0, B2
    umulh u, A0, B2

    adds Z2, Z2, v
    adcs Z3, Z3, u
    adc  Z4, Z4, xzr

    // Z3 += A3 * B0
    mul   v, A3, B0
    umulh u, A3, B0

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, xzr, xzr

    // Z3 += A2 * B1
    mul   v, A2, B1
    umulh u, A2, B1

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Z3 += A1 * B2
    mul   v, A1, B2
    umulh u, A1, B2

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Z3 += A0 * B3
    mul   v, A0, B3
    umulh u, A0, B3

    adds Z3, Z3, v
    adcs Z4, Z4, u
    adc  Z5, Z5, xzr

    // Z4 += A4 * B0
    mul   v, A4, B0
    umulh u, A4, B0

    adds Z4, Z4, v
    adcs Z5, Z5, u
    adc  Z6, xzr, xzr

    // Z4 += A3 * B1
    mul   v, A3, B1
    umulh u, A3, B1

    adds Z4, Z4, v
    adcs Z5, Z5, u
    adc  Z6, Z6, xzr

    // Z4 += A2 * B2
    mul   v, A2, B2
    umulh u, A2, B2

    adds Z4, Z4, v
    adcs Z5, Z5, u
    adc  Z6, Z6, xzr

    // Z4 += A1 * B3
    mul   v, A1, B3
    umulh u, A1, B3

    adds Z4, Z4, v
    adcs Z5, Z5, u
    adc  Z6, Z6, xzr

    // Z4 += A0 * B4
    mul   v, A0, B4
    umulh u, A0, B4

    adds Z4, Z4, v
    adcs Z5, Z5, u
    adc  Z6, Z6, xzr

    // Z5 += A5 * B0
    mul   v, A5, B0
    umulh u, A5, B0

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, xzr, xzr

    // Z5 += A4 * B1
    mul   v, A4, B1
    umulh u, A4, B1

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A3 * B2
    mul   v, A3, B2
    umulh u, A3, B2

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A2 * B3
    mul   v, A2, B3
    umulh u, A2, B3

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A1 * B4
    mul   v, A1, B4
    umulh u, A1, B4

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A0 * B5
    mul   v, A0, B5
    umulh u, A0, B5

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Partial reduction.
    partial_redc

    // Z5 += A5 * B1
    mul   v, A5, B1
    umulh u, A5, B1

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, xzr, xzr

    // Z5 += A4 * B2
    mul   v, A4, B2
    umulh u, A4, B2

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A3 * B3
    mul   v, A3, B3
    umulh u, A3, B3

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A2 * B4
    mul   v, A2, B4
    umulh u, A2, B4

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A1 * B5
    mul   v, A1, B5
    umulh u, A1, B5

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Partial reduction.
    partial_redc

    // Z5 += A5 * B2
    mul   v, A5, B2
    umulh u, A5, B2

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, xzr, xzr

    // Z5 += A4 * B3
    mul   v, A4, B3
    umulh u, A4, B3

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A3 * B4
    mul   v, A3, B4
    umulh u, A3, B4

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A2 * B5
    mul   v, A2, B5
    umulh u, A2, B5

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Partial reduction.
    partial_redc

    // Z5 += A5 * B3
    mul   v, A5, B3
    umulh u, A5, B3

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, xzr, xzr

    // Z5 += A4 * B4
    mul   v, A4, B4
    umulh u, A4, B4

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Z5 += A3 * B5
    mul   v, A3, B5
    umulh u, A3, B5

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Partial reduction.
    partial_redc

    // Z5 += A5 * B4
    mul   v, A5, B4
    umulh u, A5, B4

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, xzr, xzr

    // Z5 += A4 * B5
    mul   v, A4, B5
    umulh u, A4, B5

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, Z7, xzr

    // Partial reduction.
    partial_redc

    // Z5 += A5 * B5
    mul   v, A5, B5
    umulh u, A5, B5

    adds Z5, Z5, v
    adcs Z6, Z6, u
    adc  Z7, xzr, xzr

    // Partial reduction.
    partial_redc

    // if Z >= M then Z := Z − M
    final_sub

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0], #16
    stp Z4, Z5, [x0]

    // Restore x19-x24.
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16

    ret

#endif
