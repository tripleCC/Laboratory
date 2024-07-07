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


#if (defined(__x86_64__) && CCN_SHIFT_LEFT_ASM)

        .text
        .globl  _ccn_shift_left
        .p2align  4, 0x90
_ccn_shift_left:

        pushq   %rbp
        movq    %rsp, %rbp


        /* void ccn_shift_left(cc_size count, cc_unit *r, const cc_unit *s, size_t k) */

        #define count   %rdi            // size in cc_unit (8-bytes)
        #define dst     %rsi            // destination
        #define src     %rdx            // source 1

        #define v0      %xmm0
        #define v1      %xmm1
        #define v2      %xmm2
        #define v3      %xmm3
        #define k       %xmm4           // for shift left
        #define rk      %xmm5           // for shift right

#if CC_KERNEL
        sub     $6*16, %rsp
        movdqa  %xmm0, 0*16(%rsp)
        movdqa  %xmm1, 1*16(%rsp)
        movdqa  %xmm2, 2*16(%rsp)
        movdqa  %xmm3, 3*16(%rsp)
        movdqa  %xmm4, 4*16(%rsp)
        movdqa  %xmm5, 5*16(%rsp)
#endif

        leaq    (src, count, 8), src
        leaq    (dst, count, 8), dst

        movq    %rcx, k     // k, amount to left shift
        subq    $64, %rcx   // k-64
        negq    %rcx        // 64-k, amount to right shift, for carry into next higher significant cc_unit
        movq    %rcx, rk    // rk, amount to right shift, for carry into next higher significant cc_unit

        // point at the last element
        sub     $8, src

        sub     $4, count       // 1 block (pre-loop) + 4 blocks
        jl      9f
        je      8f              // less than or equal to 4 elements
0:
        movdqu  -32(src), v0    // a, b
        movdqu  -16(src), v1    // c, d
        movdqu  -24(src), v2    // b, c
        movdqu  -8(src), v3     // d, sip1
        sub     $2*16, src

        psrlq   rk, v0          // a,b >> rk
        psrlq   rk, v1          // c,d >> rk
        psllq   k, v2           // b,c << k
        psllq   k, v3           // d,sip1 << k

        por     v2, v0
        por     v3, v1

        movdqu  v0, -32(dst)
        movdqu  v1, -16(dst)
        sub     $2*16, dst
        sub     $4, count
        jg      0b
        jl      9f

8:
        /* exactly 4 elements left */
        movq    -24(src), v0    // b
        movdqu  -16(src), v1    // c, d
        movdqu  -24(src), v2    // b, c
        movdqu  -8(src), v3     // d, sip1
        pslldq  $8, v0          // 0, b

        psrlq   rk, v0          // a,b >> rk
        psrlq   rk, v1          // c,d >> rk
        psllq   k, v2           // b,c << k
        psllq   k, v3           // d,sip1 << k

        por     v2, v0
        por     v3, v1
        movdqu  v0, -32(dst)
        movdqu  v1, -16(dst)
        jmp     L_done


9:      and    $3, count 
        cmp    $3, count
        jne     7f      // not 3 elements
        movdqu  -16(src), v2
        jmp     8f

7:      test    $2, count 
        je      9f      // only 1 more element

        /* 2 more elements */
        movq    -8(src), v2
        pslldq  $8, v2
8:
        movdqu  -8(src), v0
        psllq   k, v0
        psrlq   rk, v2
        por     v2, v0
        movdqu  v0, -16(dst)
        sub     $16, dst
        sub     $16, src

9:
        test    $1, count 
        je      L_done
        /* 1 more elements */
        movq    0(src), v0
        psllq   k, v0
        movq    v0, -8(dst)
L_done:
#if CC_KERNEL
        movdqa  0*16(%rsp), %xmm0
        movdqa  1*16(%rsp), %xmm1
        movdqa  2*16(%rsp), %xmm2
        movdqa  3*16(%rsp), %xmm3
        movdqa  4*16(%rsp), %xmm4
        movdqa  5*16(%rsp), %xmm5
        add     $6*16, %rsp
#endif
        popq    %rbp
        ret

#endif // (defined(__x86_64__) && CCN_SHIFT_LEFT_ASM)


