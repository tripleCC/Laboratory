# Copyright (c) (2018,2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#include <corecrypto/cc_config.h>

#if (defined(__arm64__) && CCN_SHIFT_LEFT_ASM)
#include "ccarm_pac_bti_macros.h"
    .text
    .align 2
    .globl _ccn_shift_left

_ccn_shift_left:

    #define count   x0
    #define dst     x1
    #define src     x2
    #define k       v4
    #define rk      v5

    BRANCH_TARGET_CALL
#if CC_KERNEL
    // save v0-v5
    sub     x4, sp, #6*16
    sub     sp, sp, #6*16
    st1.4s  {v0, v1, v2, v3}, [x4], #64
    st1.4s  {v4, v5}, [x4], #32
#endif

    // point to end of buffers
    add         src, src, count, lsl #3
    add         dst, dst, count, lsl #3

    // set up registers for using ushl.2d
    sub         x5, x3, #64         // -(64-k)
    dup.2d      k, x3           // for left shift 
    dup.2d      rk, x5          // for right shift (using ushl.2d)

    // point at the last element
    sub         src, src, #8

    subs    count, count, #4        // pre-subtract count by 4 + 1 extra block before loop
    b.lt        9f                  // less than 4 elements,
    b.eq        8f                  // exactly 4 elements left

0:
    ldr     q2, [src, #-24] // b,c
    ldr     q3, [src, #-8]  // d,sip1
    ldp     q0, q1, [src, #-32]! // a,b,c,d
    ushl.2d v2, v2, k          // b,c >> m
    ushl.2d v3, v3, k          // d,sip1 >> m
    ushl.2d v0, v0, rk           // a,b << k
    ushl.2d v1, v1, rk           // c,d << k
    eor.16b v0, v0, v2
    eor.16b v1, v1, v3
    stp     q0, q1, [dst, #-32]!
    subs    count, count, #4
    b.gt    0b
    b.lt    9f

8:  // exactly 4 elements left
    movi.4s v0, #0              // clear v0
    ldr     q2, [src, #-24] // b,c
    ldr     q3, [src, #-8]  // d,sip1
    ldr     q1, [src, #-16]     // c,d
    ins.d   v0[1], v2[0]        // 0, b
    ushl.2d v2, v2, k           // b,c >> m
    ushl.2d v3, v3, k           // d,sip1 >> m
    ushl.2d v0, v0, rk           // 0,b << k
    ushl.2d v1, v1, rk           // c,d << k
    eor.16b v0, v0, v2
    eor.16b v1, v1, v3
    stp     q0, q1, [dst, #-32]
    b       L_done

9:  ands    count, count, #3
    b.eq    L_done
    cmp     count, #3
    b.ne    7f              // not 3 elements
    ldr     q2, [src, #-16]
    b       8f

7:  tst     count, #2
    b.eq    9f              // only 1 element

    // 2 more elements
    ldr     x5, [src, #-8] 
    movi.4s v2, #0
    ins.d   v2[1], x5

8:
    ldr     q0, [src, #-8]
    ushl.2d v0, v0, k  
    ushl.2d v2, v2, rk
    eor.16b v0, v0, v2
    sub     src, src, #16
    str     q0, [dst, #-16]!

9:
    tst     count, #1
    b.eq    L_done
    // 1 more element
    ldr     d0, [src, #0]
    ushl.2d v0, v0, k  
    str     d0, [dst, #-8]

L_done:

#if CC_KERNEL
    // restore v0-v5
    ld1.4s  {v0, v1, v2, v3}, [sp], #64
    ld1.4s  {v4, v5}, [sp], #32
#endif

    ret         lr

#endif // (defined(__arm64__) && CCN_SHIFT_LEFT_ASM)
