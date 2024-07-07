# Copyright (c) (2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__arm64__) && CCN_MUL1_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

#define r x1
#define s x2
#define v x3

#define s0 x4
#define s1 x5
#define s2 x6
#define s3 x7

#define r0 x8
#define r1 x9
#define r2 x10
#define r3 x11

#define t0 x12
#define t1 x13

#define cc x14

.align 4
.globl _ccn_mul1_asm
_ccn_mul1_asm: /* cc_unit ccn_mul1_asm(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v); */
    BRANCH_TARGET_CALL

    mov cc, xzr

    // n & 1 == 0?
    ands t0, x0, #1
    b.eq L_do2

L_do1:
    // Load S.
    ldr s0, [s], #8

    // s0 * v
    mul   r0, s0, v
    umulh cc, s0, v

    // Write R.
    str r0, [r], #8

    // count -= 1
    sub x0, x0, #1

L_do2:
    // n & 2 == 0?
    ands t0, x0, #2
    b.eq L_loop4

    // Load S.
    ldp s0, s1, [s], #16

    // s0 * v
    mul   r0, s0, v
    umulh r1, s0, v

    // s1 * v
    mul   t0, s1, v
    umulh t1, s1, v

    adds r0, r0, cc
    adcs r1, r1, t0
    adc  cc, t1, xzr

    // Write R.
    stp r0, r1, [r], #16

    // count -= 2
    sub x0, x0, #2

L_loop4:
    subs x0, x0, #4
    b.lt L_done

    // Load S.
    ldp s0, s1, [s], #16

    // s0 * v
    mul   r0, s0, v
    umulh r1, s0, v

    adds r0, r0, cc

    // Load S.
    ldp s2, s3, [s], #16

    // s1 * v
    mul   t0, s1, v
    umulh t1, s1, v

    adcs r1, r1, t0

    // Write R.
    stp r0, r1, [r], #16

    // s2 * v
    mul   r2, s2, v
    umulh r3, s2, v

    adcs r2, r2, t1

    // s3 * v
    mul   t0, s3, v
    umulh t1, s3, v

    adcs r3, r3, t0
    adc  cc, t1, xzr

    // Write R.
    stp r2, r3, [r], #16

    b L_loop4

L_done:
    mov x0, cc

    ret

#endif
