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

#if defined(__arm64__) && CCN_MULMOD_256_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

#include "ccn_mul_256-arm64.h"

.macro partial_redc
    lsr   u, $0, #32
    sub   v, $0, $0, lsl #32
    umulh q, $0, c

    adds $1, $1, $0, lsl #32
    adcs $2, $2, u
    adcs $3, $3, v
    adc  $0, q, xzr
.endm

.align 4
.globl _ccn_mulmod_p256
_ccn_mulmod_p256: /* void ccn_mulmod_p256(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    BRANCH_TARGET_CALL

    #include "ccn_mul_256-arm64.s"

    mov c, 0xffffffff00000001 // m[3]

    partial_redc Z0, Z1, Z2, Z3
    partial_redc Z1, Z2, Z3, Z4
    partial_redc Z2, Z3, Z4, Z5
    partial_redc Z3, Z4, Z5, Z6

    adds Z0, Z0, Z4
    adcs Z1, Z1, Z5
    adcs Z2, Z2, Z6
    adcs Z3, Z3, Z7
    adc  Z4, xzr, xzr

    // Final subtraction.
    mov u, 0x00000000ffffffff // m[1]

    // Subtract M.
    subs Z0, Z0, 0xffffffffffffffff
    sbcs Z1, Z1, u
    sbcs Z2, Z2, xzr
    sbcs Z3, Z3, c

    // q = (Z < M) ? 0xffffffffffffffff : 0
    sbc q, Z4, xzr

    // Clear u,v if (Z >= M).
    and u, u, q
    and c, c, q

    // Add M back, if needed.
    adds Z0, Z0, q
    adcs Z1, Z1, u
    adcs Z2, Z2, xzr
    adc  Z3, Z3, c

    // Write Z.
    stp Z0, Z1, [x0], #16
    stp Z2, Z3, [x0]

    ret

#endif
