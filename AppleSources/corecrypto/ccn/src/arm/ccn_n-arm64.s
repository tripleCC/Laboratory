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


#if defined(__arm64__) && CCN_N_ASM

#include "ccarm_pac_bti_macros.h"

.text
.align 2

	.globl _ccn_n_asm

_ccn_n_asm: /* cc_size ccn_n_asm(cc_size count, const cc_unit *s); */

    BRANCH_TARGET_CALL
    // if count == 0, return 0
    cbz     x0, 1f

    mov     x4,     x0              // count
    mov     x0,     #0              // default output s=t
    mov     x3,     #0

0:  ldr     x2,    [x1], #8         // read forward a new word
    add     x3,     x3, #1          // i++
    cmp     x2,     #0              // test whether input word is zero
    csel    x0,     x3, x0, ne      // the last count s.t. s[count]!=0

    cmp     x3,     x4
    b.lo     0b

1:
    ret         lr

#endif /* CCN_N_ASM */
