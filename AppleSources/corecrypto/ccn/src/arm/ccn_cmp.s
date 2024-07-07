# Copyright (c) (2010,2011,2015,2016,2018,2019,2021,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if CC_ARM_ARCH_7 && CCN_CMP_ASM

.text
.align 2
    .syntax unified
    .code   16
    .thumb_func


	.globl _ccn_cmp_asm
_ccn_cmp_asm: /* int ccn_cmp_asm(cc_size count, const cc_unit *s, const cc_unit *t); */

    movs    ip,     r0              // count
    it      eq
    bxeq    lr                      // exit if count was zero, returning zero.
    push    {r9}
    mov     r0,     #0              // default output s=t

0:  ldr     r3,    [r1], #4
    ldr     r9,    [r2], #4
    cmp     r3,     r9
    it      hi
    movhi   r0,     #1              // set return value to +1 if s > t
    it      lo
    mvnlo   r0,     #0              // set return value to -1 if s < t

    subs    ip,     ip, #1          // decrement word count.
    bhi     0b

    pop     {r9}
    bx      lr


#endif /* CCN_CMP_ASM */

