# Copyright (c) (2018-2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if (CC_ARM_ARCH_7 && CCN_SHIFT_LEFT_ASM)
    .text
    .align 2
    .syntax unified
    .code   16
    .thumb_func

    .globl _ccn_shift_left

_ccn_shift_left:

    #define v0  q0
    #define v1  q1
    #define v2  q2
    #define v3  q3
    #define v4  q8
    #define v5  q9

    #define count   r0
    #define dst     r1
    #define src     r2
    #define k       v4
    #define rk      v5


    push    {r4-r6,lr}
#if CC_KERNEL
    vpush   {q0-q3}
    vpush   {q8-q9}
#endif

    // point to end of buffers
    add         src, src, count, lsl #2
    add         dst, dst, count, lsl #2

    // set up registers for using vshl.u64
    sub         r4, r3, #32        // -(32-k)
    vdup.32     k, r3              // for left shift
    vdup.32     rk, r4             // for right shift (using ushl.2d)

    // point at the last element
    sub         src, src, #4

    subs       count, count, #8    // pre-subtract count by 8
    blt        9f                  // less than 8 elements,
    beq        8f                  // exactly 8 elements left

0:
    sub      r6, src, #28
    sub      src, src, #32
    vld1.32  {v2,v3},[r6]
    vld1.32  {v0,v1},[src]

    vshl.u32 v2, v2, k          // b,c >> m
    vshl.u32 v3, v3, k          // d,sip1 >> m
    vshl.u32 v0, v0, rk         // a,b << k
    vshl.u32 v1, v1, rk         // c,d << k
    sub      dst, dst, #32
    veor    v0, v0, v2
    veor    v1, v1, v3
    vst1.32  {v0,v1},[dst]

    subs    count, count, #8
    bgt    0b
    blt    9f

8:  // exactly 8 elements left
    veor    v0, v0, v0          // clear v0
    sub     r6, src, #16
    sub     src, src, #28
    vld1.32  {v2,v3},[src]
    vld1.32  {v1},[r6]
    vext.8  v0, v0, v2, #12

    vshl.u32 v2, v2, k          // b,c >> m
    vshl.u32 v3, v3, k          // d,sip1 >> m
    vshl.u32 v0, v0, rk         // a,b << k
    vshl.u32 v1, v1, rk         // c,d << k
    sub      dst, dst, #32
    veor    v0, v0, v2
    veor    v1, v1, v3
    vst1.32  {v0,v1},[dst]

    b       L_done

9:  ands    count, count, #7

    subs       count, count, #4    // pre-subtract count by 4
    blt        9f                  // less than 4 elements,
    beq        8f                  // exactly 4 elements left

0:
    sub      r6, src, #12
    sub      src, src, #16
    vld1.32  {v2},[r6]
    vld1.32  {v0},[src]

    vshl.u32 v2, v2, k          // b,c >> m
    vshl.u32 v0, v0, rk         // a,b << k
    sub      dst, dst, #16
    veor    v0, v0, v2
    vst1.32  {v0},[dst]

    subs    count, count, #4
    bgt    0b
    blt    9f

8:  // exactly 4 elements left
    veor    v0, v0, v0          // clear v0
    sub     src, src, #12
    vld1.32  {v2},[src]
    vext.8  v0, v0, v2, #12

    vshl.u32 v2, v2, k        // a,b << k
    vshl.u32 v0, v0, rk       // 0,a << k
    sub      dst, dst, #16
    veor    v0, v0, v2
    vst1.32  {v0},[dst]

    b       L_done

9:  ands    count, count, #3
    beq    L_done

    subs    count, count, #1
    beq     1f
    
0:
    sub     src, src, #4
    vldr    d0, [src] 
    vshl.u64 v0, v0, k          // b,c >> m
    sub     dst, dst, #4
    vstr     s1, [dst]
    subs    count, count, #1
    bgt     0b

1:
    vldr    s0, [src] 
    vshl.u64 v0, v0, k          // b,c >> m
    sub     dst, dst, #4
    vstr     s0, [dst]

L_done:

#if CC_KERNEL
    vpop    {q8-q9}
    vpop    {q0-q1}
    vpop    {q2-q3}
#endif

    pop         {r4-r6,pc}

#endif // (CC_ARM_ARCH_7 && CCN_SHIFT_LEFT_ASM)
