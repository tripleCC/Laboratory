# Copyright (c) (2016,2018-2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if (defined(__x86_64__) && CCN_SHIFT_RIGHT_ASM)

        .text
	    .globl  _ccn_shift_right_asm
        .p2align  4, 0x90
_ccn_shift_right_asm:

        /* void ccn_shift_right_asm(cc_size count, cc_unit *r, const cc_unit *s, size_t k) */

		// push rbp and set up frame base
        pushq   %rbp
        movq    %rsp, %rbp

		// symbolicate used registers

		#define	count	%rdi			// size in cc_unit (8-bytes)
		#define	dst 	%rsi			// destination
		#define	src		%rdx			// source 1

        #define v0      %xmm0
        #define v1      %xmm1
        #define v2      %xmm2
        #define v3      %xmm3
		#define	k		%xmm4			// for shift right
		#define	rk		%xmm5			// for shift left


        mov     $0, %rax
        cmp     $0, count
        jne     1f                      // if count == 0, nothing to be done
        popq    %rbp
        ret
1:
#if CC_KERNEL
        sub     $6*16, %rsp
        movdqa  %xmm0, 0*16(%rsp)
        movdqa  %xmm1, 1*16(%rsp)
        movdqa  %xmm2, 2*16(%rsp)
        movdqa  %xmm3, 3*16(%rsp)
        movdqa  %xmm4, 4*16(%rsp)
        movdqa  %xmm5, 5*16(%rsp)
#endif

        movq    %rcx, k
        subq    $64, %rcx
        negq    %rcx
        movq    %rcx, rk

        sub     $4, count
        jl      9f              // less than 4 elements
        je      8f              // with exact 4 elemnts to process, no more element to read

0:
        movdqu  0(src), v0
        movdqu  16(src), v1
        movdqu  8(src), v2
        movdqu  24(src), v3
        add     $2*16, src
        psrlq   k, v0
        psrlq   k, v1
        psllq   rk, v2
        psllq   rk, v3
        por     v2, v0
        por     v3, v1
        movdqu  v0, (dst)
        movdqu  v1, 16(dst)
        add     $2*16, dst
        sub     $4, count
        jg      0b
        jl      9f

8:      /* exactly 4 elements left */
        movdqu  0(src), v0
        movdqu  16(src), v1
        movdqu  8(src), v2
        movq    24(src), v3
        psrlq   k, v0
        psrlq   k, v1
        psllq   rk, v2
        psllq   rk, v3
        por     v2, v0
        por     v3, v1
        movdqu  v0, (dst)
        movdqu  v1, 16(dst)
        jmp     L_done


9:      add     $2, count       // post add 4, pre-sub 2
        jl      9f              // only 1 element left
        je      8f              // 2 element left

        /* 3 more elements */
        movdqu  0(src), v0
        movq    16(src), v1
        movdqu  8(src), v2
        psrlq   k, v0
        psrlq   k, v1
        psllq   rk, v2
        por     v2, v0
        movdqu  v0, (dst)
        movq    v1, 16(dst)
        jmp     L_done
8:
        /* 2 more elements */
        movdqu  0(src), v0
        movq    8(src), v2
        psrlq   k, v0
        psllq   rk, v2
        por     v2, v0
        movdqu  v0, (dst)
        jmp     L_done

9:
        /* 1 more elements */
        movq    0(src), v0
        psrlq   k, v0
        movq    v0, (dst)
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

#endif

