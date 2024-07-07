# Copyright (c) (2015,2016,2019-2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if defined(__arm64__) && CCN_CMP_ASM

#include "ccarm_pac_bti_macros.h"

.text
.align 2

	.globl _ccn_cmp_asm
_ccn_cmp_asm: /* int ccn_cmp_asm(cc_size count, const cc_unit *s, const cc_unit *t); */
	BRANCH_TARGET_CALL
    // if count == 0, return 0
    cbz     x0, 1f

    mov     x4,     x0              // count
    mov     x0,     #0              // default output s=t
    mov     x6,     #1
    mov     x7,     #-1

0:  ldr     x3,    [x1], #8
    ldr     x5,    [x2], #8
    cmp     x3,     x5

    csel    x0, x6, x0, hi          // set return value to +1 if s > t
    csel    x0, x7, x0, lo          // set return value to -1 if s < t

    subs    x4,     x4, #1          // decrement word count.
    b.hi     0b

1:
    ret         lr


#endif /* CCN_CMP_ASM */

