# Copyright (c) (2010,2011,2015,2016,2019-2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if CC_ARM_ARCH_7 && CCN_ADDMUL1_ASM

.text
.align 2
    .syntax unified
    .code   16
    .thumb_func


	.globl _ccn_addmul1_asm

_ccn_addmul1_asm: /* cc_unit ccn_addmul1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v); */
    stmfd   sp!, { r4-r6, lr }
    mov     r4, #0
    adds    r0, r0, #0		/* Clear Carry */
    tst     r0, #1
    beq     Lskipcount1
    ldr     r6, [r2], #4
    ldr     r12, [r1, #0]
    umull   r5, r4, r6, r3
    adds    lr, r12, r5
    str     lr, [r1], #4
Lskipcount1:
    tst     r0, #2
    beq     Lskipcount2
    ldr     r6, [r2], #4
    ldr     r12, [r1, #0]
    mov     r5, #0
    umlal   r4, r5, r6, r3
    ldr     r6, [r2], #4
    adcs    lr, r12, r4
    ldr     r12, [r1, #4]
    mov     r4, #0
    umlal   r5, r4, r6, r3
    str     lr, [r1], #4
    adcs    lr, r12, r5
    str     lr, [r1], #4
Lskipcount2:
    bics    lr, r0, #3
    beq     Lreturn

    ldr     r6, [r2], #4
    ldr     r12, [r1, #0]
    mov     r5, #0
    umlal   r4, r5, r6, r3
    b       Lfirst4loop

Ldo_count4loop:
    ldr     r6, [r2], #4
    adcs    lr, r12, r5
    ldr     r12, [r1, #4]
    mov     r5, #0
    umlal   r4, r5, r6, r3
    str     lr, [r1], #4
Lfirst4loop:
    ldr     r6, [r2], #4
    adcs    lr, r12, r4
    ldr     r12, [r1, #4]
    mov     r4, #0
    umlal   r5, r4, r6, r3
    str     lr, [r1], #4
    ldr     r6, [r2], #4
    adcs	lr, r12, r5
    ldr     r12, [r1, #4]
    mov     r5, #0
    umlal   r4, r5, r6, r3
    str     lr, [r1], #4
    ldr     r6, [r2], #4
    adcs	lr, r12, r4
    ldr     r12, [r1, #4]
    mov     r4, #0
    umlal	r5, r4, r6, r3
    str     lr, [r1], #4
    sub     r0, r0, #4
    bics	lr, r0, #3
    bne     Ldo_count4loop

    adcs	lr, r12, r5
    str     lr, [r1], #4
Lreturn:
    adc     r0, r4, #0
    ldmfd	sp!, { r4-r6, pc }

#endif /* CCN_ADDMUL1_ASM */

