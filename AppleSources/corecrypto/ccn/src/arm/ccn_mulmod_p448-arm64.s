# Copyright (c) (2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__arm64__) && CCN_MULMOD_448_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

/**
 * ARM64 implementation of Curve448 field operations.
 */

#define u x0
#define v x1

#define  Z0  x3
#define  Z1  x4
#define  Z2  x5
#define  Z3  x6
#define  Z4  x7
#define  Z5  x8
#define  Z6  x9
#define  Z7 x10
#define  Z8 x11
#define  Z9 x12
#define Z10 x13
#define Z11 x14

// Overlap with B0 and A6.
#define Z12 x15
#define Z13 x16

#define A0 x23
#define A1 x22
#define A2 x21
#define A3 x20
#define A4 x19
#define A5 x17
#define A6 x16

#define B0 x15
#define B1 x24
#define B2 x25
#define B3 x26
#define B4 x27
#define B5 x28
#define B6  x2


.macro redc_one
    adds Z0, Z0, Z7
    adcs Z1, Z1, xzr
    adcs Z2, Z2, xzr
    lsl  Z7, Z7, #32
    adcs Z3, Z3, Z7
    adcs Z4, Z4, xzr
    adcs Z5, Z5, xzr
    adcs Z6, Z6, xzr
    adc  Z7, xzr, xzr

    adds Z0, Z0, Z7
    adcs Z1, Z1, xzr
    adcs Z2, Z2, xzr
    lsl  Z7, Z7, #32
    adc  Z3, Z3, Z7
.endm


.align 4
.globl _ccn_addmod_p448
_ccn_addmod_p448: /* void ccn_addmod_p448(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    // Load A.
    ldp Z0, Z1, [x1], #16
    ldp Z2, Z3, [x1], #16
    ldp Z4, Z5, [x1], #16
    ldr Z6, [x1]

    // Load B.
    ldp  Z7,  Z8, [x2], #16
    ldp  Z9, Z10, [x2], #16
    ldp Z11, Z12, [x2], #16
    ldr Z13, [x2]

    adds Z0, Z0,  Z7
    adcs Z1, Z1,  Z8
    adcs Z2, Z2,  Z9
    adcs Z3, Z3, Z10
    adcs Z4, Z4, Z11
    adcs Z5, Z5, Z12
    adcs Z6, Z6, Z13
    adc  Z7, xzr, xzr

    redc_one

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0], #16
    stp Z4, Z5, [x0], #16
    str Z6, [x0], #8

    ret


.align 4
.globl _ccn_submod_p448
_ccn_submod_p448: /* void ccn_submod_p448(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    // Load A.
    ldp Z0, Z1, [x1], #16
    ldp Z2, Z3, [x1], #16
    ldp Z4, Z5, [x1], #16
    ldr Z6, [x1]

    // Load B.
    ldp  Z7,  Z8, [x2], #16
    ldp  Z9, Z10, [x2], #16
    ldp Z11, Z12, [x2], #16
    ldr Z13, [x2]

    subs Z0, Z0,  Z7
    sbcs Z1, Z1,  Z8
    sbcs Z2, Z2,  Z9
    sbcs Z3, Z3, Z10
    sbcs Z4, Z4, Z11
    sbcs Z5, Z5, Z12
    sbcs Z6, Z6, Z13
    cset Z7, cc

    // Reduce once.
    subs Z0, Z0, Z7
    sbcs Z1, Z1, xzr
    sbcs Z2, Z2, xzr
    lsl  Z7, Z7, #32
    sbcs Z3, Z3, Z7
    sbcs Z4, Z4, xzr
    sbcs Z5, Z5, xzr
    sbcs Z6, Z6, xzr
    cset Z7, cc

    // Reduce twice.
    subs Z0, Z0, Z7
    sbcs Z1, Z1, xzr
    sbcs Z2, Z2, xzr
    lsl  Z7, Z7, #32
    sbc  Z3, Z3, Z7

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0], #16
    stp Z4, Z5, [x0], #16
    str Z6, [x0], #8

    ret


.align 4
.globl _ccn_mulmod_p448
_ccn_mulmod_p448: /* void ccn_mulmod_p448(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    // Store x19-x28.
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!

    // Store x0 for later.
    str x0, [sp, #-16]!

    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1], #16
    ldp A4, A5, [x1], #16
    ldr A6, [x1]

    // Load B.
    ldp B0, B1, [x2], #16
    ldp B2, B3, [x2], #16
    ldp B4, B5, [x2], #16
    ldr B6, [x2]

    // Z0 = A0 * B0
    mul   Z0, A0, B0
    umulh Z1, A0, B0

    // Z1 += A1 * B0
    mul    u, A1, B0
    umulh Z2, A1, B0

    // Z2 += A2 * B0
    mul    v, A2, B0
    umulh Z3, A2, B0

    adds Z1, Z1, u
    adcs Z2, Z2, v

    // Z3 += A3 * B0
    mul    u, A3, B0
    umulh Z4, A3, B0

    // Z4 += A4 * B0
    mul    v, A4, B0
    umulh Z5, A4, B0

    adcs Z3, Z3, u
    adcs Z4, Z4, v

    // Z5 += A5 * B0
    mul    u, A5, B0
    umulh Z6, A5, B0

    // Z6 += A6 * B0
    mul    v, A6, B0
    umulh Z7, A6, B0

    adcs Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A6 * B1
    mul    u, A6, B1
    umulh Z8, A6, B1

    // Z8 += A6 * B2
    mul    v, A6, B2
    umulh Z9, A6, B2

    adcs Z7, Z7, u
    adcs Z8, Z8, v

    // Z9 += A6 * B3
    mul     u, A6, B3
    umulh Z10, A6, B3

    // Z10 += A6 * B4
    mul     v, A6, B4
    umulh Z11, A6, B4

    adcs  Z9,  Z9, u
    adcs Z10, Z10, v

    // Z11 += A6 * B5
    mul     u, A6, B5
    umulh Z12, A6, B5

    // Z12 += A6 * B6
    mul     v, A6, B6
    umulh Z13, A6, B6

    adcs Z11, Z11, u
    adcs Z12, Z12, v
    adc  Z13, Z13, xzr

    // Z1 += A0 * B1
    mul   u, A0, B1
    umulh v, A0, B1

    adds Z1, Z1, u
    adcs Z2, Z2, v

    // Z3 += A2 * B1
    mul   u, A2, B1
    umulh v, A2, B1

    adcs Z3, Z3, u
    adcs Z4, Z4, v

    // Z5 += A4 * B1
    mul   u, A4, B1
    umulh v, A4, B1

    adcs Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A5 * B2
    mul   u, A5, B2
    umulh v, A5, B2

    adcs Z7, Z7, u
    adcs Z8, Z8, v

    // Z9 += A5 * B4
    mul   u, A5, B4
    umulh v, A5, B4

    adcs  Z9,  Z9, u
    adcs Z10, Z10, v

    // Z11 += A5 * B6
    mul   u, A5, B6
    umulh v, A5, B6

    adcs Z11, Z11, u
    adcs Z12, Z12, v
    adc  Z13, Z13, xzr

    // Z2 += A1 * B1
    mul   u, A1, B1
    umulh v, A1, B1

    adds Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 += A3 * B1
    mul   u, A3, B1
    umulh v, A3, B1

    adcs Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 += A5 * B1
    mul   u, A5, B1
    umulh v, A5, B1

    adcs Z6, Z6, u
    adcs Z7, Z7, v

    // Z8 += A5 * B3
    mul   u, A5, B3
    umulh v, A5, B3

    adcs Z8, Z8, u
    adcs Z9, Z9, v

    // Z10 += A5 * B5
    mul   u, A5, B5
    umulh v, A5, B5

    adcs Z10, Z10, u
    adcs Z11, Z11, v
    adc   A5, xzr, xzr

    // Z2 += A0 * B2
    mul   u, A0, B2
    umulh v, A0, B2

    adds Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 += A2 * B2
    mul   u, A2, B2
    umulh v, A2, B2

    adcs Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 += A4 * B2
    mul   u, A4, B2
    umulh v, A4, B2

    adcs Z6, Z6, u
    adcs Z7, Z7, v

    // Z8 += A4 * B4
    mul   u, A4, B4
    umulh v, A4, B4

    adcs Z8, Z8, u
    adcs Z9, Z9, v

    // Z10 += A4 * B6
    mul   u, A4, B6
    umulh v, A4, B6

    adcs Z10, Z10, u
    adcs Z11, Z11, v
    adc   A5,  A5, xzr

    // Z3 += A1 * B2
    mul   u, A1, B2
    umulh v, A1, B2

    adds Z3, Z3, u
    adcs Z4, Z4, v

    // Z5 += A3 * B2
    mul   u, A3, B2
    umulh v, A3, B2

    adcs Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A4 * B3
    mul   u, A4, B3
    umulh v, A4, B3

    adcs Z7, Z7, u
    adcs Z8, Z8, v

    // Z9 += A4 * B5
    mul   u, A4, B5
    umulh v, A4, B5

    adcs  Z9,  Z9, u
    adcs Z10, Z10, v
    adc   A4, xzr, xzr

    // Z3 += A0 * B3
    mul   u, A0, B3
    umulh v, A0, B3

    adds Z3, Z3, u
    adcs Z4, Z4, v

    // Z5 += A2 * B3
    mul   u, A2, B3
    umulh v, A2, B3

    adcs Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A3 * B4
    mul   u, A3, B4
    umulh v, A3, B4

    adcs Z7, Z7, u
    adcs Z8, Z8, v

    // Z9 += A3 * B6
    mul   u, A3, B6
    umulh v, A3, B6

    adcs  Z9,  Z9, u
    adcs Z10, Z10, v
    adc   A4,  A4, xzr

    // Z4 += A1 * B3
    mul   u, A1, B3
    umulh v, A1, B3

    adds Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 += A3 * B3
    mul   u, A3, B3
    umulh v, A3, B3

    adcs Z6, Z6, u
    adcs Z7, Z7, v

    // Z8 += A3 * B5
    mul   u, A3, B5
    umulh v, A3, B5

    adcs Z8,  Z8, u
    adcs Z9,  Z9, v
    adc  A3, xzr, xzr

    // Z4 += A0 * B4
    mul   u, A0, B4
    umulh v, A0, B4

    adds Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 += A2 * B4
    mul   u, A2, B4
    umulh v, A2, B4

    adcs Z6, Z6, u
    adcs Z7, Z7, v

    // Z8 += A2 * B6
    mul   u, A2, B6
    umulh v, A2, B6

    adcs Z8, Z8, u
    adcs Z9, Z9, v
    adc  A3, A3, xzr

    // Z5 += A1 * B4
    mul   u, A1, B4
    umulh v, A1, B4

    adds Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A2 * B5
    mul   u, A2, B5
    umulh v, A2, B5

    adcs Z7,  Z7, u
    adcs Z8,  Z8, v
    adc  A2, xzr, xzr

    // Z5 += A0 * B5
    mul   u, A0, B5
    umulh v, A0, B5

    adds Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A1 * B6
    mul   u, A1, B6
    umulh v, A1, B6

    adcs Z7, Z7, u
    adcs Z8, Z8, v
    adc  A2, A2, xzr

    // Z6 += A1 * B5
    mul   u, A1, B5
    umulh v, A1, B5

    adds Z6,  Z6, u
    adcs Z7,  Z7, v
    adc  A1, xzr, xzr

    // Z6 += A0 * B6
    mul   u, A0, B6
    umulh v, A0, B6

    adds  Z6,  Z6, u
    adcs  Z7,  Z7, v
    adcs  Z8,  Z8, A1
    adcs  Z9,  Z9, A2
    adcs Z10, Z10, A3
    adcs Z11, Z11, A4
    adcs Z12, Z12, A5
    adc  Z13, Z13, xzr

L_redc_full:
    adds Z0, Z0, Z7
    adcs Z1, Z1, Z8
    adcs Z2, Z2, Z9
    adcs Z3, Z3, Z10
    adcs Z4, Z4, Z11
    adcs Z5, Z5, Z12
    adcs Z6, Z6, Z13
    adc   u, xzr, xzr

    and  v, Z10, 0xffffffff00000000
    adds Z3, Z3, v
    adcs Z4, Z4, Z11
    adcs Z5, Z5, Z12
    adcs Z6, Z6, Z13
    adc   u,  u, xzr

    mov v, Z10
    extr Z10, Z11, Z10, #32
    extr Z11, Z12, Z11, #32
    extr Z12, Z13, Z12, #32
    extr Z13, Z7, Z13, #32
    extr Z7, Z8, Z7, #32
    extr Z8, Z9, Z8, #32
    extr Z9, v, Z9, #32

    adds Z0, Z0, Z10
    adcs Z1, Z1, Z11
    adcs Z2, Z2, Z12
    adcs Z3, Z3, Z13
    adcs Z4, Z4, Z7
    adcs Z5, Z5, Z8
    adcs Z6, Z6, Z9
    adc  Z7,  u, xzr

    // Reduce by a single limb.
    redc_one

    // Load x0.
    ldr x0, [sp], #16

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0], #16
    stp Z4, Z5, [x0], #16
    str Z6, [x0], #8

    // Restore x19-x28.
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16

    ret


.align 4
.globl _ccn_sqrmod_p448
_ccn_sqrmod_p448: /* void ccn_sqrmod_p448(cc_unit *r, const cc_unit *a); */
    BRANCH_TARGET_CALL

    // Store x19-x28.
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!

    // Store x0 for later.
    str x0, [sp, #-16]!

    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1], #16
    ldp A4, A5, [x1], #16
    ldr A6, [x1]

    // Z1 += A1 * A0
    mul   Z1, A1, A0
    umulh Z2, A1, A0

    // Z2 += A2 * A0
    mul    u, A2, A0
    umulh Z3, A2, A0

    // Z3 += A3 * A0
    mul    v, A3, A0
    umulh Z4, A3, A0

    adds Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 += A4 * A0
    mul    u, A4, A0
    umulh Z5, A4, A0

    // Z5 += A5 * A0
    mul    v, A5, A0
    umulh Z6, A5, A0

    adcs Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 += A6 * A0
    mul    u, A6, A0
    umulh Z7, A6, A0

    // Z7 += A6 * A1
    mul    v, A6, A1
    umulh Z8, A6, A1

    adcs Z6, Z6, u
    adcs Z7, Z7, v

    // Z8 += A6 * A2
    mul    u, A6, A2
    umulh Z9, A6, A2

    // Z9 += A6 * A3
    mul     v, A6, A3
    umulh Z10, A6, A3

    adcs Z8, Z8, u
    adcs Z9, Z9, v

    // Z10 += A6 * A4
    mul     u, A6, A4
    umulh Z11, A6, A4

    // Z11 += A6 * A5
    mul     v, A6, A5
    umulh Z12, A6, A5

    adcs Z10, Z10, u
    adcs Z11, Z11, v
    adc   B5, xzr, xzr

    // Z3 += A2 * A1
    mul   u, A2, A1
    umulh v, A2, A1

    adds Z3, Z3, u
    adcs Z4, Z4, v

    // Z5 += A4 * A1
    mul   u, A4, A1
    umulh v, A4, A1

    adcs Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A5 * A2
    mul   u, A5, A2
    umulh v, A5, A2

    adcs Z7, Z7, u
    adcs Z8, Z8, v

    // Z9 += A5 * A4
    mul   u, A5, A4
    umulh v, A5, A4

    adcs  Z9,  Z9, u
    adcs Z10, Z10, v
    adc   B4, xzr, xzr

    // Z4 += A3 * A1
    mul   u, A3, A1
    umulh v, A3, A1

    adds Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 += A5 * A1
    mul   u, A5, A1
    umulh v, A5, A1

    adcs Z6, Z6, u
    adcs Z7, Z7, v

    // Z8 += A5 * A3
    mul   u, A5, A3
    umulh v, A5, A3

    adcs  Z8,  Z8, u
    adcs  Z9,  Z9, v
    adc   B3, xzr, xzr

    // Z5 += A3 * A2
    mul   u, A3, A2
    umulh v, A3, A2

    adds Z5, Z5, u
    adcs Z6, Z6, v

    // Z7 += A4 * A3
    mul   u, A4, A3
    umulh v, A4, A3

    adcs Z7,  Z7, u
    adcs Z8,  Z8, v
    adc  B2, xzr, xzr

    // Z6 += A4 * A2
    mul   u, A4, A2
    umulh v, A4, A2

    adds  Z6,  Z6, u
    adcs  Z7,  Z7, v
    adcs  Z8,  Z8, xzr
    adcs  Z9,  Z9, B2
    adcs Z10, Z10, B3
    adcs Z11, Z11, B4
    adcs Z12, Z12, B5
    adc   B1, xzr, xzr

    // Double intermediate results.
    adds  Z1,  Z1,  Z1
    adcs  Z2,  Z2,  Z2
    adcs  Z3,  Z3,  Z3
    adcs  Z4,  Z4,  Z4
    adcs  Z5,  Z5,  Z5
    adcs  Z6,  Z6,  Z6
    adcs  Z7,  Z7,  Z7
    adcs  Z8,  Z8,  Z8
    adcs  Z9,  Z9,  Z9
    adcs Z10, Z10, Z10
    adcs Z11, Z11, Z11
    adcs Z12, Z12, Z12
    adc   B1,  B1,  B1

    // Z0 = A0 * A0
    mul  Z0, A0, A0
    umulh v, A0, A0

    adds Z1, Z1, v

    // Z2 += A1 * A1
    mul   u, A1, A1
    umulh v, A1, A1

    adcs Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 += A2 * A2
    mul   u, A2, A2
    umulh v, A2, A2

    adcs Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 += A3 * A3
    mul   u, A3, A3
    umulh v, A3, A3

    adcs Z6, Z6, u
    adcs Z7, Z7, v

    // Z8 += A4 * A4
    mul   u, A4, A4
    umulh v, A4, A4

    adcs Z8, Z8, u
    adcs Z9, Z9, v

    // Z10 += A5 * A5
    mul   u, A5, A5
    umulh v, A5, A5

    adcs Z10, Z10, u
    adcs Z11, Z11, v

    // Z12 += A6 * A6
    mul   u, A6, A6
    umulh v, A6, A6

    adcs Z12, Z12, u
    adc  Z13,  B1, v

    b L_redc_full

#endif
