# Copyright (c) (2016,2018-2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if (CC_ARM_ARCH_7 || defined(__arm64__)) && CCN_SHIFT_RIGHT_ASM
#include "ccarm_pac_bti_macros.h"
	.text
	.align 2

#if defined(__arm__)
    .syntax unified
    .code   16
    .thumb_func
#endif

	.globl _ccn_shift_right_asm

_ccn_shift_right_asm: /* void ccn_shift_right_asm(cc_size count, cc_unit *r, const cc_unit *s, size_t k) */
#if defined(__arm64__) 
	BRANCH_TARGET_CALL


	#define	count	x0
	#define	dst		x1
	#define	src		x2
	#define	k		x3
	#define	rk		x10

    cbnz        count, 1f
    ret         lr          // if count == 0, return x0 = 0
1:

#if CC_KERNEL
    // save v0-v5
    sub     x4, sp, #6*16
    sub     sp, sp, #6*16
    st1.4s  {v0, v1, v2, v3}, [x4], #64
    st1.4s  {v4, v5}, [x4], #32
#endif

    mov         rk, #64
    ldr         x5, [src]
    sub         rk, rk, k           // left shift amount = 64 - k
    sub         x6, xzr, rk, lsr #6 // x6=-1 iff rk=64 and k=0, else x6=0

    // vector implementation
    neg         x7, k               // negative right shift for ushl instruction
    dup.2d      v5, rk              // for left shift
    dup.2d      v4, x7              // for right shift using ushl

    subs    count, count, #4        // pre-subtract count by 4
    b.lt        9f                  // less than 4 elements,
    b.eq        8f                  // with exact 4 elemnts to process, no more element to read

    // 4 elements to process, with at least 1 extra to read
0: 
    ld1.2d {v0, v1}, [src], #2*16  // read 4 data, v0 = 1:0, v1 = 3:2
    ext.16b v2, v0, v1, #8          // form v2 = 2:1,
    ldr     x5, [src]               // 4
    ext.16b v3, v1, v1, #8          // form v2 = 2:3,
    mov     v3.d[1], x5             // v3 = 4:3
    ushl.2d v0, v0, v4
    ushl.2d v1, v1, v4
    ushl.2d v2, v2, v5
    ushl.2d v3, v3, v5
    eor.16b v0, v0, v2
    eor.16b v1, v1, v3
    st1.2d {v0, v1}, [dst], #2*16
    subs    count, count, #4        // subtract count by 4
    b.gt        0b                  // more than 4 elements
    b.lt        9f                  // less than 4 elements left
 
8:  // exactly 4 more elements to process
    ld1.2d {v0, v1}, [src], #2*16   // read 4 data, v0 = 1:0, v1 = 3:2
    ext.16b v2, v0, v1, #8          // form v2 = 2:1,
    mov     x5, #0                  // 4
    ext.16b v3, v1, v1, #8          // form v2 = 2:3,
    mov     v3.d[1], x5             // v3 = 4:3
    ushl.2d v0, v0, v4
    ushl.2d v1, v1, v4
    ushl.2d v2, v2, v5
    ushl.2d v3, v3, v5
    eor.16b v0, v0, v2
    eor.16b v1, v1, v3
    st1.2d {v0, v1}, [dst], #2*16
    b       L_done

9:  add     count, count, #4        // recover count and src for remaining code
    add     src, src, #8

    /* process 2 units per iteration */
    subs        count, count, #2
    b.lt        9f                      // 1 lelment in x5
    b.eq        8f                      // 2 elments, with 1st in x5
0:
    ldp         x7, x8, [src], #16      // read 2 more elements
    lsr         x4, x5, k
    lsr         x5, x7, k
    lsl         x7, x7, rk
    bic         x7, x7, x6
    lsl         x9, x8, rk
    bic         x9, x9, x6
    orr         x4, x4, x7
    orr         x5, x5, x9
    stp         x4, x5, [dst], #16
    mov         x5, x8
    subs        count, count, #2
    b.gt        0b
    b.lt        9f
8:  ldr         x4, [src]               // final src elemnt
    lsr         x7, x5, k
    lsr         x8, x4, k
    lsl         x4, x4, rk
    bic         x4, x4, x6
    orr         x7, x7, x4
    stp         x7, x8, [dst], #16
    b           L_done

9:  lsr         x5, x5, k
    str         x5, [dst]

L_done:
#if CC_KERNEL
    // restore v0-v5
    ld1.4s  {v0, v1, v2, v3}, [sp], #64
    ld1.4s  {v4, v5}, [sp], #32
#endif

    ret         lr

#elif defined(__arm__)

    #define count   r0
    #define dst     r1
    #define src     r2
    #define k       r3

    cbnz        count, 1f
    bx          lr          // if count == 0, return x0 = 0
1:
    rsb     r12, r3, #32
    stmfd   sp!, { r4-r6, r8-r11, lr }

    subs    count, count, #4
    blt     L_lessthan4
0:
    ldmia   src!, {r4-r6, r8}               // read 4 elements
    it      gt
    ldrgt   r9, [src]
    lsr     r4, k
    lsl     r10, r5, r12
    lsl     lr, r6, r12
    lsr     r5, k
    orr     r4, r10
    orr     r5, lr
    lsl     r10, r8, r12
    it      gt
    lslgt   lr, r9, r12
    lsr     r6, k
    lsr     r8, k
    orr     r6, r10
    it      gt
    orrgt   r8, lr
#if defined(__arm__)                    // _ARM_ARCH_6
    pld     [dst, #12]                   /* Cache prefetch write line */
#elif CC_ARM_ARCH_7
    pldw    [dst, #12]                   /* Cache prefetch write line */
#else
    ldr     r9, [dst, #12]               /* Cache prefetch write line */
#endif
    stmia   dst!, { r4-r6, r8 }

    subs    count, count, #4
    bge     0b

L_lessthan4:

    adds    count, count, #2
    blt     L_lessthan2
    ldmia   src!, {r4-r5}               // read 2 elements
    it      gt
    ldrgt   r9, [src]
    lsr     r4, k
    lsl     r10, r5, r12
    lsr     r5, k
    it      gt
    lslgt   lr, r9, r12
    orr     r4, r10
    it      gt
    orrgt   r5, lr
    stmia   dst!, { r4-r5 }

L_lessthan2:

    tst     r0, #1
    beq     1f
    ldr     r4, [src]
    lsr     r4, k
    str     r4, [dst]
1:

L_done:
    ldmfd	sp!, { r4-r6, r8-r11, pc }

#endif	/* __arm64__ */

#endif /* CCN_SHIFT_RIGHT_ASM */

