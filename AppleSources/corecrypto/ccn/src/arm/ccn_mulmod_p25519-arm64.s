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

#if defined(__arm64__) && CCN_MULMOD_25519_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

#include "ccn_mul_256-arm64.h"

.align 4
.globl _ccn_addmod_p25519
_ccn_addmod_p25519: /* void ccn_addmod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1]

    // Load B.
    ldp B0, B1, [x2], #16
    ldp B2, B3, [x2]

    adds Z0, A0, B0
    adcs Z1, A1, B1
    adcs Z2, A2, B2
    adcs Z3, A3, B3

    mov q, #38

    // Carry once.
    sbc c, c, c
    bic c, q, c

    adds Z0, Z0, c
    adcs Z1, Z1, xzr
    adcs Z2, Z2, xzr
    adcs Z3, Z3, xzr

    // Carry twice.
    sbc c, c, c
    bic c, q, c

    add Z0, Z0, c

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret


.align 4
.globl _ccn_submod_p25519
_ccn_submod_p25519: /* void ccn_submod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1]

    // Load B.
    ldp B0, B1, [x2], #16
    ldp B2, B3, [x2]

    subs Z0, A0, B0
    sbcs Z1, A1, B1
    sbcs Z2, A2, B2
    sbcs Z3, A3, B3

    mov q, #38

    // Carry once.
    sbc c, c, c
    and c, q, c

    subs Z0, Z0, c
    sbcs Z1, Z1, xzr
    sbcs Z2, Z2, xzr
    sbcs Z3, Z3, xzr

    // Carry twice.
    sbc c, c, c
    and c, q, c

    sub Z0, Z0, c

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret


.align 4
.globl _ccn_mulmod_p25519
_ccn_mulmod_p25519: /* void ccn_mulmod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    #include "ccn_mul_256-arm64.s"

L_reduce:
    // Reduce mod 2^256-38.
    mov q, #38

    // (Z0,Z1) += Z4 * 38
    mul   u, Z4, q
    umulh v, Z4, q

    adds Z0, Z0, u
    adcs Z1, Z1, v

    // (Z2,Z3) += Z6 * 38
    mul   u, Z6, q
    umulh v, Z6, q

    adcs Z2, Z2, u
    adcs Z3, Z3, v
    adc   c, xzr, xzr

    // (Z1,Z2) += Z5 * 38
    mul   u, Z5, q
    umulh v, Z5, q

    adds Z1, Z1, u
    adcs Z2, Z2, v

    // (Z3,c) += Z7 * 38
    mul   u, Z7, q
    umulh v, Z7, q

    adcs Z3, Z3, u
    adc   c, c, v

    // Carry once.
    mul c, c, q

    adds Z0, Z0, c
    adcs Z1, Z1, xzr
    adcs Z2, Z2, xzr
    adcs Z3, Z3, xzr

    // Carry twice.
    sbc c, c, c
    bic c, q, c

    add Z0, Z0, c

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret


.align 4
.globl _ccn_sqrmod_p25519
_ccn_sqrmod_p25519: /* void ccn_sqrmod_p25519(cc_unit *r, const cc_unit *a); */
    BRANCH_TARGET_CALL

    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1]

    // Z1 = A0 * A1
    mul   Z1, A0, A1
    umulh Z2, A0, A1

    // Z2 += A0 * A2
    mul    u, A0, A2
    umulh Z3, A0, A2

    // Z3 += A0 * A3
    mul    v, A0, A3
    umulh Z4, A0, A3

    adds Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 += A1 * A3
    mul    u, A1, A3
    umulh Z5, A1, A3

    // Z5 += A2 * A3
    mul    v, A2, A3
    umulh Z6, A2, A3

    adcs Z4, Z4, u
    adcs Z5, Z5, v
    adc  x8, xzr, xzr

    // Z3 += A1 * A2
    mul   u, A1, A2
    umulh v, A1, A2

    adds Z3, Z3, u
    adcs Z4, Z4, v
    adcs Z5, Z5, xzr
    adcs Z6, Z6, x8
    adc  Z7, xzr, xzr

    // Double intermediate results.
    adds Z1, Z1, Z1
    adcs Z2, Z2, Z2
    adcs Z3, Z3, Z3
    adcs Z4, Z4, Z4
    adcs Z5, Z5, Z5
    adcs Z6, Z6, Z6
    adc  Z7, Z7, Z7

    // Z0 = A0 * A0
    mul  Z0, A0, A0
    umulh v, A0, A0

    adds Z1, Z1, v

    // Z2 = A1 * A1
    mul   u, A1, A1
    umulh v, A1, A1

    adcs Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 = A2 * A2
    mul   u, A2, A2
    umulh v, A2, A2

    adcs Z4, Z4, u
    adcs Z5, Z5, v

    // Z6 = A3 * A3
    mul   u, A3, A3
    umulh v, A3, A3

    adcs Z6, Z6, u
    adc  Z7, Z7, v

    // Reduce mod 2^256-38.
    b L_reduce

#endif
