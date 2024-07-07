# Copyright (c) (2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#include <corecrypto/cc_config.h>
#if  CCAES_INTEL_ASM && defined(__x86_64__)

	.text	
	.p2align	4


	.macro  karatsuba_reduce_to_128
    /* Karatsuba method produces t0 in %xmm3, t1 in %xmm1, t2 in %xmm0 */
    /* %xmm2 = H<<1 mod g(x) */
    movdqa      %xmm0,%xmm1
    pshufd      _IMM(78),%xmm0,%xmm3
    pshufd      _IMM(78),%xmm2,%xmm4
    pxor        %xmm0,%xmm3
    pxor        %xmm2,%xmm4
    pclmulqdq   _IMM(0x0), %xmm2, %xmm0
    pclmulqdq   _IMM(0x11), %xmm2, %xmm1
    pclmulqdq   _IMM(0x0), %xmm4, %xmm3

    /* reduce to 128-bit in %xmm0 */
    pxor       %xmm1, %xmm3
    pxor       %xmm0, %xmm3
    movdqa     %xmm3, %xmm4
    pslldq     _IMM(8), %xmm3
    psrldq     _IMM(8), %xmm4
    pxor       %xmm3, %xmm0
    pxor       %xmm1, %xmm4
    pshufd     _IMM(78), %xmm0, %xmm1
    pclmulqdq  _IMM(0x10), L0x1c2_polynomial(%rip), %xmm0
    pxor       %xmm1, %xmm0
    pshufd     _IMM(78), %xmm0, %xmm1
    pclmulqdq  _IMM(0x10), L0x1c2_polynomial(%rip), %xmm0
    pxor       %xmm1, %xmm4
    pxor       %xmm4, %xmm0
    .endm

	.macro  write_Htable arg0, arg1
    movdqu  %xmm0,\arg0
    pshufd  $78,%xmm0,%xmm3
    pxor    %xmm0,%xmm3
    movdqu  %xmm3,\arg1
    .endm

/*
        void gcm_init(u128 Htable[16], u128 *H);

        the following equation will be used in the computation of A*H

            reflected (A)*reflected (H<<1 mod g(x)) = reflected (A*H) mod g(x)

        this function pre-computes (H^i << 1) mod g(x) for i=1:8
        it also precomputes the corresponding constants that are used in the Karatsuba algorithm. 
*/
.globl	_gcm_init

_gcm_init:

#if CC_KERNEL
    push    %rbp
    mov     %rsp, %rbp
    sub     $5*16, %rsp
    movdqa  %xmm0, 0*16(%rsp)
    movdqa  %xmm1, 1*16(%rsp)
    movdqa  %xmm2, 2*16(%rsp)
    movdqa  %xmm3, 3*16(%rsp)
    movdqa  %xmm4, 4*16(%rsp)
#endif    
	movdqu	(%rsi),%xmm2                    // H = aes_encrypt(0);
	pshufb  L$bswap_mask(%rip), %xmm2       // reflected(H)

    // compute %xmm2 = reflected( H<<1 mod g(x) )
	pshufd	$255,%xmm2,%xmm4                
	movdqa	%xmm2,%xmm3
	psllq	$1,%xmm2
	psrlq	$63,%xmm3
	psrad	$31, %xmm4                       
	pslldq	$8,%xmm3
	por	    %xmm3,%xmm2
	pand	L0x1c2_polynomial(%rip),%xmm4
	pxor	%xmm4,%xmm2                     // reflected(H<<1 mod g(x))

	movdqa	        %xmm2,%xmm0
    write_Htable    0(%rdi), 128(%rdi)
    karatsuba_reduce_to_128
    write_Htable    16(%rdi), 144(%rdi)
    karatsuba_reduce_to_128
    write_Htable    32(%rdi), 160(%rdi)
    karatsuba_reduce_to_128
    write_Htable    48(%rdi), 176(%rdi)
    karatsuba_reduce_to_128
    write_Htable    64(%rdi), 192(%rdi)
    karatsuba_reduce_to_128
    write_Htable    80(%rdi), 208(%rdi)
    karatsuba_reduce_to_128
    write_Htable    96(%rdi), 224(%rdi)
    karatsuba_reduce_to_128
    write_Htable    112(%rdi), 240(%rdi)
#if CC_KERNEL
    movdqa  0*16(%rsp), %xmm0
    movdqa  1*16(%rsp), %xmm1
    movdqa  2*16(%rsp), %xmm2
    movdqa  3*16(%rsp), %xmm3
    movdqa  4*16(%rsp), %xmm4
    mov     %rbp, %rsp
    pop     %rbp
#endif    
	ret

    .globl	_gcm_gmult
    .p2align	4
_gcm_gmult:
#if CC_KERNEL
    push    %rbp
    mov     %rsp, %rbp
    sub     $5*16, %rsp
    movdqa  %xmm0, 0*16(%rsp)
    movdqa  %xmm1, 1*16(%rsp)
    movdqa  %xmm2, 2*16(%rsp)
    movdqa  %xmm3, 3*16(%rsp)
    movdqa  %xmm4, 4*16(%rsp)
#endif    
	movdqu	(%rdi),%xmm0
	movdqu	(%rsi),%xmm2
	pshufb  L$bswap_mask(%rip), %xmm0

    karatsuba_reduce_to_128

	pshufb  L$bswap_mask(%rip), %xmm0
	movdqu	%xmm0,(%rdx)
#if CC_KERNEL
    movdqa  0*16(%rsp), %xmm0
    movdqa  1*16(%rsp), %xmm1
    movdqa  2*16(%rsp), %xmm2
    movdqa  3*16(%rsp), %xmm3
    movdqa  4*16(%rsp), %xmm4
    mov     %rbp, %rsp
    pop     %rbp
#endif    
	ret

.globl	_gcm_ghash

	#define	X		%rdi
	#define	Htable	%rsi
	#define	input	%rdx
	#define	len		%rcx

    /*
        compute (t0,t1,t2) = data[7]*H^1;
        t0 in xmm7, t1 in xmm6, t2 in xmm5
    */
	.macro	initial_Karatsuba
	movdqu	112(input),%xmm4
	pshufb	L$bswap_mask(%rip),%xmm4
	pshufd	_IMM(78),%xmm4,%xmm7
    movdqa  %xmm4, %xmm5
    movdqa  %xmm4, %xmm6
	pxor	%xmm4,%xmm7
	pclmulqdq	_IMM(0),(Htable),%xmm5
	pclmulqdq	_IMM(17),(Htable),%xmm6
	pclmulqdq	_IMM(0),128(Htable),%xmm7
	.endm

    /*
        update (t0,t1,t2) += data[7-i]*H^(1+i);
    */
	.macro	Karatsuba i
	movdqu	112-\i*16(input),%xmm4
	pshufb	L$bswap_mask(%rip),%xmm4
	pshufd	$78,%xmm4,%xmm3
    movdqa  %xmm4, %xmm1
    movdqa  %xmm4, %xmm2
	pxor	%xmm4, %xmm3
	pclmulqdq	$0,16*\i(Htable),%xmm1
	pclmulqdq	$17,16*\i(Htable),%xmm2
	pclmulqdq	$0,128+\i*16(Htable),%xmm3
	pxor	%xmm1,%xmm5
	pxor	%xmm2,%xmm6
	pxor	%xmm3,%xmm7
	.endm

    /*
        update (t0,t1,t2) += (data[0]+T)*H^(1+i);
        T in xmm0
    */
	.macro	final_Karatsuba i
	movdqu	112-\i*16(input),%xmm4
	pshufb	L$bswap_mask(%rip),%xmm4
	pxor	%xmm0,%xmm4
	pshufd	$78,%xmm4,%xmm3
    movdqa  %xmm4, %xmm1
    movdqa  %xmm4, %xmm2
	pxor	%xmm4, %xmm3
	pclmulqdq	$0,16*\i(Htable),%xmm1
	pclmulqdq	$17,16*\i(Htable),%xmm2
	pclmulqdq	$0,128+\i*16(Htable),%xmm3
	pxor	%xmm1,%xmm5
	pxor	%xmm2,%xmm6
	pxor	%xmm3,%xmm7
	.endm

    /*
        reduce Karatsuba intermediate 256-bit (t0,t1,t2) to 128 bit T (in xmm0)
    */
    .macro  reduce
	pxor	%xmm5,%xmm7
	pxor	%xmm6,%xmm7
    movdqa  %xmm7, %xmm0
    movdqa  %xmm7, %xmm1
	pslldq	_IMM(8),%xmm0
	psrldq	_IMM(8),%xmm1
    pxor	%xmm6,%xmm1
	pxor	%xmm5,%xmm0
    pshufd  _IMM(78), L0x1c2_polynomial(%rip), %xmm2
	pclmulqdq	_IMM(0),%xmm0,%xmm2
	pshufd		_IMM(78),%xmm0,%xmm0
	pxor	%xmm2,%xmm0
    pshufd  _IMM(78), L0x1c2_polynomial(%rip), %xmm2
	pclmulqdq	_IMM(0),%xmm0,%xmm2
	pshufd		_IMM(78),%xmm0,%xmm0
	pxor	%xmm2,%xmm0
	pxor	%xmm1,%xmm0
    .endm

    .p2align	4
_gcm_ghash:

#if CC_KERNEL
    push    %rbp
    mov     %rsp, %rbp
    sub     $8*16, %rsp
    movdqa  %xmm0, 0*16(%rsp)
    movdqa  %xmm1, 1*16(%rsp)
    movdqa  %xmm2, 2*16(%rsp)
    movdqa  %xmm3, 3*16(%rsp)
    movdqa  %xmm4, 4*16(%rsp)
    movdqa  %xmm5, 5*16(%rsp)
    movdqa  %xmm6, 6*16(%rsp)
    movdqa  %xmm7, 7*16(%rsp)
#endif    
    // read T and byte swap for hash computation
	movdqu	(X), %xmm0
	pshufb	L$bswap_mask(%rip),%xmm0

    sub     $128, len
    jl      L_singles
    jmp     L_8blocks_loop

    .p2align  6
L_8blocks_loop:
    /*
        per 8 blocks computation loop

        (t0,t1,t2) = data[7]*H^1 + data[6]*H^2 + ... + data[1]*H^7 + (data[0]+T)*H^8;
        update T = reduce(t0,t1,t2);

    */

	initial_Karatsuba
	Karatsuba	1
	Karatsuba	2
	Karatsuba	3
	Karatsuba	4
	Karatsuba	5
	Karatsuba	6
	final_Karatsuba	7
    reduce

    add     $128, input
    sub     $128, len
    jge     L_8blocks_loop

L_singles:
    add     $(128-16), len
    jl      L_done

    /*
        (t0,t1,t2) = (data[len/16-1]+T)*H^(len/16);
        len-=16;
    */
	movdqu	(input),%xmm4
	pshufb	L$bswap_mask(%rip),%xmm4
	pxor	%xmm0,%xmm4
	movdqa	%xmm4,%xmm5
	movdqa	%xmm4,%xmm6
	pshufd	$78,%xmm4,%xmm7
	pxor	%xmm4,%xmm7
	pclmulqdq	$0,(Htable,len), %xmm5
	pclmulqdq	$17,(Htable,len), %xmm6
	pclmulqdq	$0,16*8(Htable,len), %xmm7

	add     $16, input
    sub     $16, len
    jl      L_reduce
    jmp     L_single_loop
    .p2align  6
L_single_loop:

    /*
        (t0,t1,t2) += (data[len/16-1])*H^(len/16);
        len-=16;
    */
	movdqu	    (input),%xmm4
	pshufb	    L$bswap_mask(%rip),%xmm4
    movdqa      %xmm4, %xmm2
	pclmulqdq	$0,(Htable,len),%xmm2
	pxor	    %xmm2,%xmm5
    movdqa      %xmm4, %xmm2
	pclmulqdq	$17,(Htable,len),%xmm2
	pxor	    %xmm2,%xmm6
	pshufd	    $78,%xmm4,%xmm3
	pxor	    %xmm4,%xmm3
	pclmulqdq	$0,128(Htable,len),%xmm3
	pxor	    %xmm3,%xmm7

	add     $16, input
    sub     $16, len
    jge     L_single_loop

L_reduce:

    /*
        update T = reduce(t0,t1,t2);
    */
    reduce

L_done:

    /*
        byte swap T and save
    */
	pshufb	L$bswap_mask(%rip),%xmm0
	movdqu	%xmm0,(X)
#if CC_KERNEL
    movdqa  0*16(%rsp), %xmm0
    movdqa  1*16(%rsp), %xmm1
    movdqa  2*16(%rsp), %xmm2
    movdqa  3*16(%rsp), %xmm3
    movdqa  4*16(%rsp), %xmm4
    movdqa  5*16(%rsp), %xmm5
    movdqa  6*16(%rsp), %xmm6
    movdqa  7*16(%rsp), %xmm7
    mov     %rbp, %rsp
    pop     %rbp
#endif    
    ret

	.p2align	4
L$bswap_mask:
.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
L0x1c2_polynomial:
.byte	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xc2

#endif	// __x86_64__

