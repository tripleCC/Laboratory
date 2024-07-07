# Copyright (c) (2019-2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__arm64__) && CCN_MULMOD_224_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

#include "ccn_mul_256-arm64.h"

.macro partial_redc
    neg v, $0

    lsl q, v, #32
    lsr u, v, #32

    adds $0, $0, v
    adcs $1, $1, xzr
    adcs $2, $2, xzr
    adcs $3, $3, q
    adc  $0, u, xzr

    subs $1, $1, q
    sbcs $2, $2, u
    sbcs $3, $3, xzr
    sbc  $0, $0, xzr
.endm

.align 4
.globl _ccn_mulmod_p224
_ccn_mulmod_p224: /* void ccn_mulmod_p224(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    #include "ccn_mul_256-arm64.s"

    partial_redc Z0, Z1, Z2, Z3
    partial_redc Z1, Z2, Z3, Z4
    partial_redc Z2, Z3, Z4, Z5
    partial_redc Z3, Z4, Z5, Z6

    adds Z0, Z0, Z4
    adcs Z1, Z1, Z5
    adcs Z2, Z2, Z6
    adc  Z3, Z3, Z7

    // Final subtraction.
    mov u, 0xffffffff00000000 // m[1]
    mov q, 0xffffffffffffffff // m[2]
    mov v, 0x00000000ffffffff // m[3]

    // Subtract M.
    subs Z0, Z0, #1
    sbcs Z1, Z1, u
    sbcs Z2, Z2, q
    sbcs Z3, Z3, v

    // q = (Z < M) ? 0xffffffffffffffff : 0
    ngc q, xzr

    // Clear u,v if (Z >= M).
    and u, u, q
    and v, v, q

    // Add M back, if needed.
    adds Z0, Z0, q, lsr #63
    adcs Z1, Z1, u
    adcs Z2, Z2, q
    adc  Z3, Z3, v

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret

#endif
