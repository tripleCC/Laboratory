# Copyright (c) (2010-2012,2015,2016,2019-2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if (CC_ARM_ARCH_7 || defined(__arm64__)) && CCN_SUB_ASM

#include "ccarm_pac_bti_macros.h"

.text
.align 2
#if CC_ARM_ARCH_7
    .syntax unified
    .code   16
    .thumb_func
#endif


	.globl _ccn_sub_asm

/* r0 = count, r1 = r, r2 = s, r3 = t */
_ccn_sub_asm: /* cc_unit ccn_sub_asm(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t); */

#if defined(__arm64__)
	BRANCH_TARGET_CALL
	subs		x4, x4, x4		// clear carry signal

	// if count == 0, return with carry = 0
	cbnz		x0, 1f
	ret			lr
1:

	#define	count	w0
	#define	r		x1
	#define	x		x2
	#define	y		x3

	and			w12, count, #1
	cbz			w12, L_skip1
	ldr		x4,[x],#8
	ldr		x8,[y],#8
	subs	x8, x4, x8
	str		x8, [r], #8	
L_skip1:
	and			w12, count, #2
	cbz			w12, L_skip2
	ldp		x4,x5,[x],#16
	ldp		x8,x9,[y],#16
	sbcs	x8, x4, x8
	sbcs	x9, x5, x9
	stp		x8,x9,[r],#16
L_skip2:
    and    count, count, #0xfffffffc
	cbz		count, L_done

	sub		count, count, #4
	ldp		x4,x5,[x],#16
	ldp		x8,x9,[y],#16
	ldp		x6,x7,[x],#16
	ldp		x10,x11,[y],#16

	cbz		count, L_loop4_finishup

L_loop4:

	sbcs	x8, x4, x8
	sbcs	x9, x5, x9
	ldp		x4,x5,[x],#16
	sbcs	x10, x6, x10
	stp		x8,x9,[r],#16
	sbcs	x11, x7, x11
	ldp		x8,x9,[y],#16
	stp		x10,x11,[r],#16
	sub		count, count, #4
	ldp		x6,x7,[x],#16
	ldp		x10,x11,[y],#16

	cbnz	count, L_loop4

L_loop4_finishup:

	sbcs	x8, x4, x8
	sbcs	x9, x5, x9
	sbcs	x10, x6, x10
	sbcs	x11, x7, x11
	stp		x8,x9,[r],#16
	stp		x10,x11,[r],#16

L_done:
	sbc		w0, w0, w0
	and		w0, w0, #1
	ret		lr

#elif CC_ARM_ARCH_7		// arm architecture

    stmfd   sp!, { r4-r10, lr }
	subs	r12, r12, r12
	tst     r0, #1
    beq     Lskipcount1
    ldr     r12, [r2], #4
    ldr     lr, [r3], #4
    subs    r12, r12, lr
    str     r12, [r1], #4
Lskipcount1:
    tst     r0, #2
    beq     Lskipcount2
    ldmia   r2!, { r8, r9 }
    ldmia   r3!, { r12, lr }
    sbcs    r8, r8, r12
    sbcs    r9, r9, lr
    stmia   r1!, { r8, r9 }
Lskipcount2:
    bics    r0, r0, #3
    beq     Ldone
Ldo_count4loop:
    ldmia	r2!, { r4, r5, r6, r10 }
    ldmia	r3!, { r8, r9, r12, lr }
    sbcs	r4, r4, r8
    /* Cache prefetch write line */
#if defined(__arm__)    // _ARM_ARCH_6 
    pld     [r1, #12]
#elif CC_ARM_ARCH_7
    pldw    [r1, #12]
#else
    ldr     r8, [r1, #12]
#endif
    sbcs    r5, r5, r9
    sbcs    r6, r6, r12
    sbcs    r10, r10, lr
    stmia   r1!, { r4, r5, r6, r10 }
    sub     r0, r0, #4
    teq     r0, #0
    bne     Ldo_count4loop
Ldone:
    sbc     r0, r0, r0
    and     r0, r0, #1                  /* Return carry */
    ldmfd	sp!, { r4-r10, pc }

#endif	/* arm64 or arm */

#endif /* (CC_ARM_ARCH_7 || defined(__arm64__)) && CCN_SUB_ASM */


