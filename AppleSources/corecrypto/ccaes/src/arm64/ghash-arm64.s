# Copyright (c) (2014-2016,2019,2020,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if CCAES_ARM_ASM && defined(__arm64__)
#include "ccarm_pac_bti_macros.h"
	.text	
	.align	4


	// input v0, v2 (v5 = 0), save to $0, and $1
	.macro  karatsuba_reduce_to_128
 
    /* karatsuba */
    ext.16b	v3, v0, v0, #8
    ext.16b	v4, v2, v2, #8
    eor.16b	v3, v0, v3
    eor.16b	v4, v2, v4
    pmull2.1q	v1, v0, v2
    pmull.1q	v0, v0, v2
    pmull.1q	v3, v4, v3

    /* reduce to 128-bit */
    #define Lpoly   v7
    #define Zero    v5
    eor.16b      v3, v1, v3
    eor.16b      v3, v0, v3
    ext.16b      v4, v3, Zero, #8
    eor.16b      v4, v4, v1
    ext.16b      v1, Zero, v3, #8
    eor.16b      v0, v1, v0
    ext.16b      v1, v0, v0, #8
    pmull.1q     v0, Lpoly, v0
    eor.16b      v0, v1, v0
    ext.16b      v1, v0, v0, #8
    pmull.1q     v0, Lpoly, v0
    eor.16b      v0, v1, v0
    eor.16b      v0, v4, v0
    .endm

    .macro  write_Htable
    str	q0, [x0,#$0]				// movdqu  %xmm0,$0
    ext.16b	v3, v0, v0, #8			// pshufd  $$78,%xmm0,%xmm3
    eor.16b	v3, v0, v3				// pxor    %xmm0,%xmm3
    str	q3, [x0,#$1]				// movdqa  %xmm3,$1
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
	BRANCH_TARGET_CALL
	adrp	x2, L$bswap_mask@page
	add		x2, x2, L$bswap_mask@pageoff
#if CC_KERNEL
    sub     sp, sp, #8*16
    mov     x5, sp
    st1.4s  {v0,v1,v2,v3}, [x5], #4*16   
    st1.4s  {v4,v5,v6,v7}, [x5], #4*16   
#endif
	ld1.4s  {v6,v7}, [x2]
	ldr	q2, [x1]
	tbl.16b	v2, {v2}, v6    // H = reflected(H)
    mov.16b v0, v7

    // v2 = H<<1 mod g(x)
	dup.4s	v4, v2[3]				// pshufd	$255,%xmm2,%xmm4
	ext.16b	v0, v0, v0, #8
	ushr.2d	v3, v2, #63				// psrlq	$63,%xmm3
	shl.2d	v2, v2, #1				// psllq	$1,%xmm2
	eor.16b	v5, v5, v5				// pxor	%xmm5,%xmm5
	sshr.4s	v1, v4, #31				// pcmpgtd	%xmm4,%xmm1
	ext.16b	v3, v5, v3, #8			// pslldq	$8,%xmm3
	orr.16b	v2, v3, v2				// por	%xmm3,%xmm2
	and.16b	v1, v0, v1				// pand	L$0x1c2_polynomial(%rip),%xmm1
	eor.16b	v2, v1, v2				// xor	%xmm1,%xmm2

	mov.16b	v0, v2					// movdqa	%xmm2,%xmm0
	write_Htable    0, 128
    karatsuba_reduce_to_128
    write_Htable    16, 144
    karatsuba_reduce_to_128
    write_Htable    32, 160
    karatsuba_reduce_to_128
    write_Htable    48, 176
    karatsuba_reduce_to_128
    write_Htable    64, 192
    karatsuba_reduce_to_128
    write_Htable    80, 208
    karatsuba_reduce_to_128
    write_Htable    96, 224
    karatsuba_reduce_to_128
    write_Htable    112, 240

#if CC_KERNEL
    ld1.4s  {v0,v1,v2,v3}, [sp], #4*16   
    ld1.4s  {v4,v5,v6,v7}, [sp], #4*16   
#endif
	ret		lr

	.align	4
.globl	_gcm_gmult
_gcm_gmult:
	BRANCH_TARGET_CALL
	adrp	x3, L$bswap_mask@page
	add		x3, x3, L$bswap_mask@pageoff
#if CC_KERNEL
    sub     sp, sp, #8*16
    mov     x5, sp
    st1.4s  {v0,v1,v2,v3}, [x5], #4*16   
    st1.4s  {v4,v5,v6,v7}, [x5], #4*16   
#endif
	ld1.4s	{v6,v7}, [x3]

	ldr		q0, [x0]			// movdqu	(%rdi),%xmm0
	ldr		q2, [x1]			// movdqu	(%rsi),%xmm2
	tbl.16b	v0, {v0}, v6 

    eor.16b v5, v5, v5
    karatsuba_reduce_to_128

	tbl.16b	v0, {v0}, v6 
	str		q0, [x2]
#if CC_KERNEL
    ld1.4s  {v0,v1,v2,v3}, [sp], #4*16   
    ld1.4s  {v4,v5,v6,v7}, [sp], #4*16   
#endif
	ret		lr


	.globl	_gcm_ghash
	.align	4

	#define	X		x0
	#define	Htable	x1
	#define	input	x2
	#define	len		x3	

    /*
        update (t0,t1,t2) += data[7-i]*H^(1+i);
        t0 in v7, t1 in v6, t2 in v5
    */
	.macro	initial_Karatsuba
	ldr		    q4, [input, #112]
	tbl.16b	    v4, {v4}, v16
	ldr		    q2, [Htable]
	ext.16b		v1, v4, v4, #8
	ldr		    q3, [Htable, #128]
	eor.16b		v1, v4, v1
	pmull.1q	v5, v2, v4
	pmull2.1q	v6, v2, v4
	pmull.1q	v7, v3, v1
	.endm

	.macro	Karatsuba i
	ldr		    q4, [input, #(112-\i*16)]
	tbl.16b	    v4, {v4}, v16
	ldr		    q2, [Htable, #\i*16]
	ext.16b		v1, v4, v4, #8
	eor.16b		v1, v4, v1
	pmull.1q	v3, v2, v4
	pmull2.1q	v2, v2, v4
    eor.16b     v5, v5, v3
	ldr		    q3, [Htable, #(128+\i*16)]
    eor.16b     v6, v6, v2
	pmull.1q	v1, v3, v1
    eor.16b     v7, v7, v1
	.endm

	.macro	final_Karatsuba i
	ldr		    q4, [input, #(112-\i*16)]
	tbl.16b	    v4, {v4}, v16
	ldr		    q2, [Htable, #\i*16]
    eor.16b     v4, v4, v0
	ext.16b		v1, v4, v4, #8
	eor.16b		v1, v4, v1
	pmull.1q	v3, v2, v4
	pmull2.1q	v2, v2, v4
    eor.16b     v5, v5, v3
	ldr		    q3, [Htable, #(128+\i*16)]
    eor.16b     v6, v6, v2
	pmull.1q	v1, v3, v1
    eor.16b     v7, v7, v1
	.endm

    .macro  reduce
	eor.16b	    v7, v5, v7
	eor.16b	    v7, v6, v7
	ext.16b	    v0, v18, v7, #8
	ext.16b	    v1, v7, v18, #8
	eor.16b	    v1, v6, v1
	eor.16b	    v0, v5, v0
	pmull.1q    v2, v17, v0
	ext.16b     v0, v0, v0, #8
	eor.16b     v0, v2, v0
	pmull.1q    v2, v17, v0
	ext.16b     v0, v0, v0, #8
	eor.16b     v0, v2, v0
	eor.16b     v0, v1, v0
    .endm

_gcm_ghash:
	BRANCH_TARGET_CALL
	adrp	x4, L$bswap_mask@page
	add		x4, x4, L$bswap_mask@pageoff
#if CC_KERNEL
    sub     sp, sp, #11*16
    mov     x5, sp
    st1.4s  {v0,v1,v2,v3}, [x5], #4*16   
    st1.4s  {v4,v5,v6,v7}, [x5], #4*16   
    st1.4s  {v16,v17,v18}, [x5], #3*16   
#endif

    // set up vector constants
	eor.16b	v18, v18, v18           // zero for using in ext.16b
	ld1.4s	{v16, v17}, [x4]        // v16 for byte swap, v17 for L_0x1c2_polynomial

    // read T and byte swap for hash computation
	ld1.4s	{v0}, [X]
	tbl.16b	v0, {v0}, v16 

    subs    len, len, #128
    b.lt    L_singles
    b       L_8blocks_loop
    .align  6
L_8blocks_loop:
    /*
        per 8 blocks computation loop

        (t0,t1,t2) = data[7]*H^1 + data[6]*H^2 + ... + data[1]*H^7 + (data[0]+T)*H^8;
        update T = reduce(t0,t1,t2);

    */
    initial_Karatsuba
    Karatsuba   1
    Karatsuba   2
    Karatsuba   3
    Karatsuba   4
    Karatsuba   5
    Karatsuba   6
    final_Karatsuba 7
    reduce

    add     input, input, #128
    subs    len, len, #128
    b.ge    L_8blocks_loop

L_singles:
    adds    len, len, #(128-16)
    b.lt    L_done

    /*
        (t0,t1,t2) = (data[len/16-1]+T)*H^(len/16);
        len-=16;
    */
	ld1.4s	    {v4}, [input], #16
	tbl.16b	    v4, {v4}, v16 
	eor.16b	    v4, v0, v4
	ext.16b	    v7, v4, v4, #8
	eor.16b	    v7, v4, v7
	add		    x6, Htable, len
	ldr		    q2, [Htable, len]
	ldr		    q3, [x6, #128]
	pmull.1q	v5, v4, v2
	pmull2.1q	v6, v4, v2
	pmull.1q	v7, v7, v3

    subs        len, len, #16
    b.lt        L_reduce
    b           L_single_loop

    .align      6
L_single_loop:

    /*
        (t0,t1,t2) += (data[len/16-1])*H^(len/16);
        len-=16;
    */
    sub         x6, x6, #16
	ld1.4s	    {v4}, [input], #16
	tbl.16b	    v4, {v4}, v16 
	ext.16b	    v1, v4, v4, #8
	eor.16b	    v1, v4, v1
	ldr		    q0, [x6]
	ldr		    q2, [x6, #128]
	pmull.1q	v3, v4, v0
	pmull2.1q	v0, v4, v0
	pmull.1q	v1, v1, v2
    eor.16b     v5, v5, v3
    eor.16b     v6, v6, v0
    eor.16b     v7, v7, v1

    subs        len, len, #16
    b.ge        L_single_loop


L_reduce:

    /*
        update T = reduce(t0,t1,t2);
    */
    reduce

L_done:

    /*
        byte swap T and save
    */
	tbl.16b		v0, {v0}, v16
	st1.4s		{v0}, [X]
#if CC_KERNEL
    ld1.4s  {v0,v1,v2,v3}, [sp], #4*16   
    ld1.4s  {v4,v5,v6,v7}, [sp], #4*16   
    ld1.4s  {v16,v17,v18}, [sp], #3*16   
#endif
	ret			lr


	.align	4
L$bswap_mask:
.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
L$0x1c2_polynomial:
.quad	0xc200000000000000, 0x01

#endif
