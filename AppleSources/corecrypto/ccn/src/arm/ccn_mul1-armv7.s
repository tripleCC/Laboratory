# Copyright (c) (2010-2012,2014-2016,2019-2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if CC_ARM_ARCH_7 && CCN_MUL1_ASM

.text
.align 2
    .syntax unified
    .code   16
    .thumb_func


	.globl _ccn_mul1_asm

/* Faster version 172  bytes on arm
ccn_mul1           65 ns  |   32 bytes |   2.03 ns/byte
ccn_mul1           89 ns  |   48 bytes |   1.85 ns/byte
ccn_mul1          412 ns  |  256 bytes |   1.61 ns/byte
*/
_ccn_mul1_asm: /* cc_unit ccn_mul1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v); */
    stmfd   sp!, { r4-r6, lr }
	ands	r4, r0, #1
    beq     Lskipcount1
    ldr     lr, [r2], #4
    umull   r12, r4, lr, r3
    str     r12, [r1], #4
Lskipcount1:
    tst     r0, #2
    beq     Lskipcount2
    ldr     lr, [r2], #4
    mov     r12, #0
    umlal   r4, r12, lr, r3
    ldr     lr, [r2], #4
    str     r4, [r1], #4
    mov     r4, #0
    umlal   r12, r4, lr, r3
    str     r12, [r1], #4
Lskipcount2:
    bics    r0, r0, #3
    beq     Ldone

    ldr     lr, [r2], #4
    mov     r12, #0
    umlal   r4, r12, lr, r3
    b       Lfirst4loop

Ldo_count4loop:
    ldr     lr, [r2], #4
    str     r12, [r1], #4
    mov     r12, #0
    umlal   r4, r12, lr, r3
Lfirst4loop:
    ldr     lr, [r2], #4
    str     r4, [r1], #4
    mov     r4, #0
    umlal   r12, r4, lr, r3
    ldr     lr, [r2], #4
    str     r12, [r1], #4
    mov     r12, #0
    umlal   r4, r12, lr, r3
    ldr     lr, [r2], #4
    str     r4, [r1], #4
    mov     r4, #0
    umlal	r12, r4, lr, r3
    subs    r0, r0, #4
    bne     Ldo_count4loop

    str     r12, [r1], #4
Ldone:
    mov     r0, r4
    ldmfd	sp!, { r4-r6, pc }


#endif /* CC_ARM_ARCH_7 && CCN_MUL1_ASM */

