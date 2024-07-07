# Copyright (c) (2010,2011,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if CC_ARM_ARCH_7 && CCN_N_ASM

.text
.align 2
    .syntax unified
    .code   16
    .thumb_func


	.globl _ccn_n_asm

_ccn_n_asm: /* cc_size ccn_n_asm(cc_size count, const cc_unit *s); */
    subs    ip,     r0, #0          // count
    it      ls
    bxls    lr                      // exit if count was zero, returning zero.
    mov     r0,     #0              // default output r0 = 0
    mov     r3,     #0              // r3 = 0 indicates string is still zero
0:
    ldr     r2,    [r1, r3, lsl #2] // read forward a new word

    add     r3, r3, #1
    cmp     r2, #0                  // test whether input word is zero
    it      ne
    movne   r0, r3                  // the last count s.t. s[count]!=0

    cmp     r3, ip
    blo     0b

    bx      lr

#endif /* CCN_N_ASM */

