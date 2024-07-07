# Copyright (c) (2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__arm64__) && CCN_ADD1_ASM

#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols

.text

#define r x1
#define s x2
#define v x3
#define t x4

.align 4
.globl _ccn_add1_asm
_ccn_add1_asm: /* cc_unit ccn_add1_asm(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v); */
    BRANCH_TARGET_CALL

    cbz x0, L_zero

    ldr t, [s], #8
    adds t, t, v
    str t, [r], #8

L_loop:
    sub x0, x0, #1
    cbz x0, L_done

    ldr t, [s], #8
    adcs t, t, xzr
    str t, [r], #8

    b L_loop

L_done:
    adc x0, xzr, xzr
    ret

L_zero:
    mov x0, v
    ret

#endif
