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

/*
	This file provides x86_64/i386 hand implementation of the following function

	sha2_void sha256_compile(sha256_ctx ctx[1]);

	which is a C function in CommonCrypto Source/Digest/sha2.c

	The implementation here is modified from another sha256 x86_64/i386 implementation for sha256 in the xnu.
	To modify to fit the new API,
		the old ctx (points to ctx->hashes) shoule be changed to ctx->hashes, 8(ctx).
		the old data (points to ctx->wbuf), should be changed to ctx->wbuf, 40(ctx).

	sha256_compile handles 1 input block (64 bytes) per call.


	The following is comments for the initial xnu-sha256.s.

	void SHA256_Transform(SHA256_ctx *ctx, char *data, unsigned int num_blocks);

	which is a C function in sha2.c (from xnu).

	sha256 algorithm per block description:

		1. W(0:15) = big-endian (per 4 bytes) loading of input data (64 byte)
		2. load 8 digests a-h from ctx->state
		3. for r = 0:15
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
		4. for r = 16:63
				W[r] = W[r-16] + sigma1(W[r-2]) + W[r-7] + sigma0(W[r-15]);
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g

	In the assembly implementation:
		- a circular window of message schedule W(r:r+15) is updated and stored in xmm0-xmm3
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR or m32 (all in GPR for x86_64, and some in m32 for i386)

	the implementation per block looks like

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into xmm0:xmm3
	pre_calculate and store W+K(0:15) in stack

	load digests a-h from ctx->state;

	for (r=0;r<48;r+=4) {
		digests a-h update and permute round r:r+3
		update W([r:r+3]%16) and WK([r:r+3]%16) for the next 4th iteration
	}

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
	}

	ctx->states += digests a-h;

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into xmm0:xmm3
	pre_calculate and store W+K(0:15) in stack

L_loop:

	load digests a-h from ctx->state;

	for (r=0;r<48;r+=4) {
		digests a-h update and permute round r:r+3
		update W([r:r+3]%16) and WK([r:r+3]%16) for the next 4th iteration
	}

	num_block--;
	if (num_block==0)	jmp L_last_block;

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
		load W([r:r+3]%16) (big-endian per 4 bytes) into xmm0:xmm3
		pre_calculate and store W+K([r:r+3]%16) in stack
	}

	ctx->states += digests a-h;

	jmp	L_loop;

L_last_block:

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
	}

	ctx->states += digests a-h;

	------------------------------------------------------------------------

	Apple CoreOS vector & numerics
*/
#if defined __x86_64__


	// associate variables with registers or memory

	#define	sp			%rsp
	#define	ctx			%rdi
	#define num_blocks	%rsi
	#define	data        %rdx

	#define	a			%r8d
	#define	b			%r9d
	#define	c			%r10d
	#define	d			%r11d
	#define	e			%r12d
	#define	f			%r13d
	#define	g			%r14d
	#define	h			%r15d

	#define	K			%rbx
	#define stack_size	(8+32*8+16+16+64)	// num_blocks + ymm0:ymm7 + 16byte (32-byte align) + _i_loop + WK(0:15)
	#define _num_blocks  (-48)(%rbp)	    // + xmm0:xmm7 + L_aligned_bswap + WK(0:15)

	#define	L_aligned_bswap	L_bswap(%rip)		// bswap : big-endian loading of 4-byte words
    #define _i_loop     64(sp)          // use this to save code size
	#define	ymm_save	96(sp)			// starting address for xmm save/restore

	// 2 local variables
	#define	s	%eax
	#define	t	%ecx
	#define	u	%esi

	// a window (16 words) of message scheule
	#define	W0	%xmm0
	#define	W1	%xmm1
	#define	W2	%xmm2
	#define	W3	%xmm3

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   ((x)&15)*4(sp)

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

	.macro Ch arg0, arg1, arg2
	mov		\arg0, t		// x
	mov		\arg0, s		// x
	not		t			// ~x
	and		\arg1, s		// x & y
	and		\arg2, t		// ~x & z
	xor		s, t		// t = ((x) & (y)) ^ ((~(x)) & (z));
	.endm

// #define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

	.macro	Maj arg0, arg1, arg2
	mov	 	\arg1,	t // y
	mov		\arg2,	s // z
	xor		\arg2,	t // y^z
	and		\arg1,	s // y&z
	and		\arg0, 	t // x&(y^z)
	xor		s,	t // Maj(x,y,z)
	.endm

// #define sigma0_256(x)   (S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))

	// performs sigma0_256 on 4 words on an xmm registers
	// use xmm6/xmm7 as intermediate registers
	.macro	sigma0 arg0
	movdqa	\arg0, %xmm6
	movdqa	\arg0, %xmm7
	psrld	$3, \arg0			// SHR3(x)
	psrld	$7, %xmm6		// part of ROTR7
	pslld	$14, %xmm7		// part of ROTR18
	pxor	%xmm6, \arg0
	pxor	%xmm7, \arg0
	psrld	$11, %xmm6		// part of ROTR18
	pslld	$11, %xmm7		// part of ROTR7
	pxor	%xmm6, \arg0
	pxor	%xmm7, \arg0
	.endm

// #define sigma1_256(x)   (S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

	// performs sigma1_256 on 4 words on an xmm registers
	// use xmm6/xmm7 as intermediate registers
	.macro	sigma1 arg0
	movdqa	\arg0, %xmm6
	movdqa	\arg0, %xmm7
	psrld	$10, \arg0		// SHR10(x)
	psrld	$17, %xmm6		// part of ROTR17
	pxor	%xmm6, \arg0
	pslld	$13, %xmm7		// part of ROTR19
	pxor	%xmm7, \arg0
	psrld	$2, %xmm6		// part of ROTR19
	pxor	%xmm6, \arg0
	pslld	$2, %xmm7		// part of ROTR17
	pxor	%xmm7, \arg0
	.endm

// #define Sigma0_256(x)   (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))

	.macro	Sigma0 arg0
	mov		\arg0, t			// x
	mov		\arg0, s			// x
	ror		$2, t			// S32(2,  (x))
	ror		$13, s			// S32(13,  (x))
	xor		s, t			// S32(2,  (x)) ^ S32(13, (x))
	ror		$9, s			// S32(22,  (x))
	xor		s, t			// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
	.endm

// #define Sigma1_256(x)   (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))

	.macro	Sigma1 arg0
	mov		\arg0, s			// x
	ror		$6, s			// S32(6,  (x))
	mov		s, t			// S32(6,  (x))
	ror		$5, s			// S32(11, (x))
	xor		s, t			// S32(6,  (x)) ^ S32(11, (x))
	ror		$14, s			// S32(25, (x))
	xor		s, t			// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	.endm

	// per round digests update
	.macro	round_ref arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
	Sigma1	\arg4				// t = T1
	add		t, \arg7			// use h to store h+Sigma1(e)
	Ch		\arg4, \arg5, \arg6		// t = Ch (e, f, g);
	add		\arg7, t			// t = h+Sigma1(e)+Ch(e,f,g);
	add		WK(\arg8), t		// h = T1
	add		t, \arg3			// d += T1;
	mov		t, \arg7			// h = T1
	Sigma0	\arg0				// t = Sigma0(a);
	add		t, \arg7			// h = T1 + Sigma0(a);
	Maj		\arg0, \arg1, \arg2		// t = Maj(a,b,c)
	add		t, \arg7			// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	/*
		it's possible to use shrd to operate like ror { ror n, eax == shrd n, eax, eax }
		On Westmere/Clarkdale, ror runs significantly better than shrd
		On SNB, shrd is largely improved, and it runs better than ror does
		On IVB, ror is improved, and ror and shrd performs about the same
		On hsw, shrd is a bit better than ror

		Therefore, on pre-SNB processors, we should use ror. For SNB and later, we recommend to use shrd for the purpose of ror.

	*/
	.macro	myror arg0, arg1
	shrd	$(\arg0), \arg1, \arg1	
	.endm

	.macro	round arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
	mov		\arg4, s
	mov		\arg0, t
	myror	(25-11), s
	myror	(22-13), t
	xor		\arg4, s
	mov		\arg5, u
	xor		\arg0, t
	myror	(11-6), s
	xor		\arg6, u
	xor		\arg4, s
	and		\arg4, u
	myror	(13-2), t
	xor		\arg0, t
	xor		\arg6, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(\arg8), u
	mov		\arg0, s
	add		u, \arg7
	mov		\arg0, u
	or		\arg2, s
	add		\arg7, \arg3
	and		\arg2, u
	and		\arg1, s
	add		t, \arg7
	or		u, s
	add		s, \arg7	
	.endm

	// per 4 rounds digests update and permutation
	// permutation is absorbed by rotating the roles of digests a-h
	.macro	rounds arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
	round	\arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, 0+\arg8
	round	\arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, 1+\arg8
	round	\arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, 2+\arg8
	round	\arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, 3+\arg8
	.endm

	.macro	roundsA arg0
	round	a, b, c, d, e, f, g, h, 0+\arg0
	round	h, a, b, c, d, e, f, g, 1+\arg0
	round	g, h, a, b, c, d, e, f, 2+\arg0
	round	f, g, h, a, b, c, d, e, 3+\arg0
	.endm

	.macro	roundsE arg0
	round	e, f, g, h, a, b, c, d, 0+\arg0
	round	d, e, f, g, h, a, b, c, 1+\arg0
	round	c, d, e, f, g, h, a, b, 2+\arg0
	round	b, c, d, e, f, g, h, a, 3+\arg0
	.endm

	// this macro is used in the last 16 rounds of a current block
	// it reads the next message (16 4-byte words), load it into 4 words W[r:r+3], computes WK[r:r+3]
	// and save into stack to prepare for next block

	.macro	roundsA_schedule arg0, arg1, arg2, arg3, arg4
	// round	a, b, c, d, e, f, g, h, 0+\arg4
		vpalignr	$4, \arg2, \arg3, %xmm6		// w[r-7]
	mov		e, s
	mov		a, t
		vpalignr	$4, \arg0, \arg1, %xmm4		// w[r-15] to be applied by sigma0
	myror	(25-11), s
	myror	(22-13), t
	xor		e, s
	mov		f, u
	xor		a, t
		vpaddd		%xmm6, \arg0, \arg0			// \arg0 = w[r-16] + w[r-7]
	myror	(11-6), s
	xor		g, u
		vpslld	$14, %xmm4, %xmm7		// part of ROTR18
	xor		e, s
	and		e, u
		vpsrld	$7, %xmm4, %xmm6		// part of ROTR7
	myror	(13-2), t
	xor		a, t
		vpsrld	$3, %xmm4, %xmm4			// SHR3(x)
	xor		g, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(0+\arg4), u
		vpxor	%xmm7, %xmm4, %xmm4
	mov		a, s
	add		u, h
		vpxor	%xmm6, %xmm4, %xmm4
	mov		a, u
	or		c, s
		vpslld	$11, %xmm7, %xmm7		// part of ROTR7
	add		h, d
	and		c, u
		vpsrld	$11, %xmm6, %xmm6		// part of ROTR18
	and		b, s
	add		t, h
		vpxor	%xmm6, %xmm4, %xmm4
	or		u, s
	add		s, h	
		vunpckhps	\arg3, \arg3, %xmm6




	// round	h, a, b, c, d, e, f, g, 1+\arg4
	mov		d, s
	mov		h, t
		vpxor	%xmm7, %xmm4, %xmm4
	myror	(25-11), s
	myror	(22-13), t
		vpsrlq		$17, %xmm6, %xmm7 
	xor		d, s
	mov		e, u
		vpsrlq		$19, %xmm6, %xmm6 
	xor		h, t
	myror	(11-6), s
		vpaddd	%xmm4, \arg0, \arg0			// \arg0 = W3:W0 + sigma0(W4:W1)
	xor		f, u
	xor		d, s
	and		d, u
	myror	(13-2), t
		vpsrld		$10, \arg3, %xmm4		// SHR10(x)
	xor		h, t
	xor		f, u
	myror	6, s
		vpxor		%xmm7, %xmm6, %xmm6
	myror	2, t
	add		s, u
	add		WK(1+\arg4), u
	mov		h, s
	add		u, g
		vpshufd     $0x80, %xmm6, %xmm6
	mov		h, u
	or		b, s
	add		g, c
	and		b, u
	and		a, s
	add		t, g
		vpxor		%xmm6, %xmm4, %xmm4
	or		u, s
	add		s, g	



	// round	g, h, a, b, c, d, e, f, 2+\arg4
	mov		c, s
	mov		g, t
	myror	(25-11), s
		vpsrldq		$8, %xmm4, %xmm4
	myror	(22-13), t
	xor		c, s
	mov		d, u
		vpaddd	%xmm4, \arg0, \arg0			// sigma1(0,0,W15,W14) + W12:W9 + sigma0(W4:W1) + W3:W0
	xor		g, t
	myror	(11-6), s
	xor		e, u
	xor		c, s
	and		c, u
		vunpcklps	\arg0, \arg0, %xmm6
	myror	(13-2), t
	xor		g, t
	xor		e, u
		vpsrld		$10, \arg0, %xmm4		// SHR10(x)
	myror	6, s
	myror	2, t
	add		s, u
		vpsrlq		$17, %xmm6, %xmm7 
	add		WK(2+\arg4), u
	mov		g, s
	add		u, f
	mov		g, u
		vpsrlq		$19, %xmm6, %xmm6 
	or		a, s
	add		f, b
	and		a, u
	and		h, s
	add		t, f
		vpxor		%xmm7, %xmm6, %xmm6
	or		u, s
	add		s, f	



	// round	f, g, h, a, b, c, d, e, 3+\arg4
	mov		b, s
	mov		f, t
	myror	(25-11), s
		vpshufd     $0x08, %xmm6, %xmm6
	myror	(22-13), t
	xor		b, s
	mov		c, u
	xor		f, t
		vpxor		%xmm6, %xmm4, %xmm4
	myror	(11-6), s
	xor		d, u
	xor		b, s
	and		b, u
	myror	(13-2), t
	xor		f, t
	xor		d, u
	myror	6, s
		vpslldq		$8, %xmm4, %xmm4
	myror	2, t
	add		s, u
	add		WK(3+\arg4), u
	mov		f, s
	add		u, e
		vpaddd		%xmm4, \arg0, \arg0			// sigma1(0,0,W15,W14) + W12:W9 + sigma0(W4:W1) + W3:W0
	mov		f, u
	or		h, s
	add		e, a
	and		h, u
		vpaddd		(K), \arg0, %xmm4			// WK
	and		g, s
	add		t, e
	or		u, s
	add		s, e	

		vmovdqa		%xmm4, WK(\arg4)
		add			$16, K
	.endm

	.macro	roundsE_schedule arg0, arg1, arg2, arg3, arg4
	// round	e, f, g, h, a, b, c, d, 0+\arg4
	mov		a, s
	mov		e, t
	myror	(25-11), s
	myror	(22-13), t
		vpalignr	$4, \arg2, \arg3, %xmm6		// w[r-7]
	xor		a, s
	mov		b, u
	xor		e, t
		vpalignr	$4, \arg0, \arg1, %xmm4		// w[r-15] to be applied by sigma0
	myror	(11-6), s
	xor		c, u
	xor		a, s
	and		a, u
		vpaddd		%xmm6, \arg0, \arg0			// \arg0 = w[r-16] + w[r-7]
	myror	(13-2), t
	xor		e, t
	xor		c, u
		vpslld	$14, %xmm4, %xmm7		// part of ROTR18
	myror	6, s
	myror	2, t
	add		s, u
		vpsrld	$7, %xmm4, %xmm6		// part of ROTR7
	add		WK(0+\arg4), u
	mov		e, s
	add		u, d
		vpsrld	$3, %xmm4, %xmm4			// SHR3(x)
	mov		e, u
	or		g, s
	add		d, h
		vpxor	%xmm7, %xmm4, %xmm4
	and		g, u
	and		f, s
	add		t, d
		vpxor	%xmm6, %xmm4, %xmm4
	or		u, s
	add		s, d	

	// round	d, e, f, g, h, a, b, c, 1+\arg4
	mov		h, s
		vpsrld	$11, %xmm6, %xmm6		// part of ROTR18
	mov		d, t
	myror	(25-11), s
	myror	(22-13), t
		vpslld	$11, %xmm7, %xmm7		// part of ROTR7
	xor		h, s
	mov		a, u
	xor		d, t
		vpxor	%xmm6, %xmm4, %xmm4
	myror	(11-6), s
	xor		b, u
	xor		h, s
	and		h, u
		vpxor	%xmm7, %xmm4, %xmm4
	myror	(13-2), t
	xor		d, t
	xor		b, u
		vpaddd	%xmm4, \arg0, \arg0			// \arg0 = W3:W0 + sigma0(W4:W1)
	myror	6, s
	myror	2, t
	add		s, u
		vunpckhps	\arg3, \arg3, %xmm6
	add		WK(1+\arg4), u
	mov		d, s
	add		u, c
		vpsrld		$10, \arg3, %xmm4		// SHR10(x)
	mov		d, u
	or		f, s
	add		c, g
		vpsrlq		$17, %xmm6, %xmm7 
	and		f, u
	and		e, s
	add		t, c
		vpsrlq		$19, %xmm6, %xmm6 
	or		u, s
	add		s, c	


	//round	c, d, e, f, g, h, a, b, 2+\arg4
	mov		g, s
	mov		c, t
		vpxor		%xmm7, %xmm6, %xmm6
	myror	(25-11), s
	myror	(22-13), t
	xor		g, s
		vpshufd     $0x80, %xmm6, %xmm6
	mov		h, u
	xor		c, t
	myror	(11-6), s
		vpxor		%xmm6, %xmm4, %xmm4
	xor		a, u
	xor		g, s
	and		g, u
		vpsrldq		$8, %xmm4, %xmm4
	myror	(13-2), t
	xor		c, t
	xor		a, u
		vpaddd	%xmm4, \arg0, \arg0			// sigma1(0,0,W15,W14) + W12:W9 + sigma0(W4:W1) + W3:W0
	myror	6, s
	myror	2, t
	add		s, u
		vunpcklps	\arg0, \arg0, %xmm6
	add		WK(2+\arg4), u
	mov		c, s
	add		u, b
		vpsrld		$10, \arg0, %xmm4		// SHR10(x)
	mov		c, u
	or		e, s
	add		b, f
		vpsrlq		$17, %xmm6, %xmm7 
	and		e, u
	and		d, s
	add		t, b
		vpsrlq		$19, %xmm6, %xmm6 
	or		u, s
	add		s, b	


	// round	b, c, d, e, f, g, h, a, 3+\arg4
	mov		f, s
	mov		b, t
		vpxor		%xmm7, %xmm6, %xmm6
	myror	(25-11), s
	myror	(22-13), t
	xor		f, s
	mov		g, u
		vpshufd     $0x08, %xmm6, %xmm6
	xor		b, t
	myror	(11-6), s
	xor		h, u
	xor		f, s
		vpxor		%xmm6, %xmm4, %xmm4
	and		f, u
	myror	(13-2), t
	xor		b, t
	xor		h, u
		vpslldq		$8, %xmm4, %xmm4
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(3+\arg4), u
	mov		b, s
		vpaddd		%xmm4, \arg0, \arg0			// sigma1(0,0,W15,W14) + W12:W9 + sigma0(W4:W1) + W3:W0
	add		u, a
	mov		b, u
	or		d, s
	add		a, e
		vpaddd		(K), \arg0, %xmm4			// WK
	and		d, u
	and		c, s
	add		t, a
	or		u, s
	add		s, a	

		vmovdqa		%xmm4, WK(\arg4)
		add			$16, K


	.endm

	.macro	roundsA_update arg0, arg1
	// round	a, b, c, d, e, f, g, h, 0+\arg0
		vmovdqu	((\arg0&12)*4)(data), \arg1		// read 4 4-byte words
	mov		e, s
	mov		a, t
	myror	(25-11), s
	myror	(22-13), t
	xor		e, s
	mov		f, u
	xor		a, t
	myror	(11-6), s
	xor		g, u
	xor		e, s
	and		e, u
	myror	(13-2), t
	xor		a, t
	xor		g, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(0+\arg0), u
	mov		a, s
	add		u, h
	mov		a, u
	or		c, s
	add		h, d
	and		c, u
	and		b, s
	add		t, h
	or		u, s
	add		s, h	

	// round	h, a, b, c, d, e, f, g, 1+\arg0
		vpshufb	L_aligned_bswap, \arg1, \arg1	// big-endian of each 4-byte word, W[r:r+3]
	mov		d, s
	mov		h, t
	myror	(25-11), s
	myror	(22-13), t
	xor		d, s
	mov		e, u
	xor		h, t
	myror	(11-6), s
	xor		f, u
	xor		d, s
	and		d, u
	myror	(13-2), t
	xor		h, t
	xor		f, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(1+\arg0), u
	mov		h, s
	add		u, g
	mov		h, u
	or		b, s
	add		g, c
	and		b, u
	and		a, s
	add		t, g
	or		u, s
	add		s, g	

	// round	g, h, a, b, c, d, e, f, 2+\arg0
	mov		c, s
	mov		g, t
	myror	(25-11), s
	myror	(22-13), t
	xor		c, s
	mov		d, u
	xor		g, t
	myror	(11-6), s
	xor		e, u
	xor		c, s
	and		c, u
	myror	(13-2), t
	xor		g, t
	xor		e, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(2+\arg0), u
	mov		g, s
	add		u, f
	mov		g, u
	or		a, s
	add		f, b
	and		a, u
	and		h, s
	add		t, f
	or		u, s
	add		s, f	

	// round	f, g, h, a, b, c, d, e, 3+\arg0
		vpaddd	((\arg0&12)*4)(K), \arg1, %xmm4			// WK[r:r+3]
	mov		b, s
	mov		f, t
	myror	(25-11), s
	myror	(22-13), t
	xor		b, s
	mov		c, u
	xor		f, t
	myror	(11-6), s
	xor		d, u
	xor		b, s
	and		b, u
	myror	(13-2), t
	xor		f, t
	xor		d, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(3+\arg0), u
	mov		f, s
	add		u, e
	mov		f, u
	or		h, s
	add		e, a
	and		h, u
	and		g, s
	add		t, e
	or		u, s
	add		s, e	

		vmovdqa	%xmm4, WK(\arg0&12)		// save WK[r:r+3] into stack circular buffer

	.endm

	.macro	roundsE_update arg0, arg1
	// round	e, f, g, h, a, b, c, d, 0+\arg0
		vmovdqu	((\arg0&12)*4)(data), \arg1		// read 4 4-byte words
	mov		a, s
	mov		e, t
	myror	(25-11), s
	myror	(22-13), t
	xor		a, s
	mov		b, u
	xor		e, t
	myror	(11-6), s
	xor		c, u
	xor		a, s
	and		a, u
	myror	(13-2), t
	xor		e, t
	xor		c, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(0+\arg0), u
	mov		e, s
	add		u, d
	mov		e, u
	or		g, s
	add		d, h
	and		g, u
	and		f, s
	add		t, d
	or		u, s
	add		s, d	

	// round	d, e, f, g, h, a, b, c, 1+\arg0
		vpshufb	L_aligned_bswap, \arg1, \arg1	// big-endian of each 4-byte word, W[r:r+3]
	mov		h, s
	mov		d, t
	myror	(25-11), s
	myror	(22-13), t
	xor		h, s
	mov		a, u
	xor		d, t
	myror	(11-6), s
	xor		b, u
	xor		h, s
	and		h, u
	myror	(13-2), t
	xor		d, t
	xor		b, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(1+\arg0), u
	mov		d, s
	add		u, c
	mov		d, u
	or		f, s
	add		c, g
	and		f, u
	and		e, s
	add		t, c
	or		u, s
	add		s, c	

	//round	c, d, e, f, g, h, a, b, 2+\arg0
	mov		g, s
	mov		c, t
	myror	(25-11), s
	myror	(22-13), t
	xor		g, s
	mov		h, u
	xor		c, t
	myror	(11-6), s
	xor		a, u
	xor		g, s
	and		g, u
	myror	(13-2), t
	xor		c, t
	xor		a, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(2+\arg0), u
	mov		c, s
	add		u, b
	mov		c, u
	or		e, s
	add		b, f
	and		e, u
	and		d, s
	add		t, b
	or		u, s
	add		s, b	

	// round	b, c, d, e, f, g, h, a, 3+\arg0
		vpaddd	((\arg0&12)*4)(K), \arg1, %xmm4			// WK[r:r+3]
	mov		f, s
	mov		b, t
	myror	(25-11), s
	myror	(22-13), t
	xor		f, s
	mov		g, u
	xor		b, t
	myror	(11-6), s
	xor		h, u
	xor		f, s
	and		f, u
	myror	(13-2), t
	xor		b, t
	xor		h, u
	myror	6, s
	myror	2, t
	add		s, u
	add		WK(3+\arg0), u
	mov		b, s
	add		u, a
	mov		b, u
	or		d, s
	add		a, e
	and		d, u
	and		c, s
	add		t, a
	or		u, s
	add		s, a	

		vmovdqa	%xmm4, WK(\arg0&12)		// save WK[r:r+3] into stack circular buffer
	.endm

	.text
    .globl	_AccelerateCrypto_SHA256_compress_AVX1
_AccelerateCrypto_SHA256_compress_AVX1:

	// push callee-saved registers
	push	%rbp
    movq    %rsp, %rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	// allocate stack space
	sub		$stack_size, sp

	// if kernel code, save used ymm registers
#if BUILDKERNEL
    leaq    ymm_save, %rax
    andq    $-32, %rax
	vmovdqa	%ymm0, 0*32(%rax)
	vmovdqa	%ymm1, 1*32(%rax)
	vmovdqa	%ymm2, 2*32(%rax)
	vmovdqa	%ymm3, 3*32(%rax)
	vmovdqa	%ymm4, 4*32(%rax)
	vmovdqa	%ymm5, 5*32(%rax)
	vmovdqa	%ymm6, 6*32(%rax)
	vmovdqa	%ymm7, 7*32(%rax)
#endif

    movq    num_blocks, _num_blocks

	// set up bswap parameters in the aligned stack space and pointer to table K256[]
	lea		CC_C_LABEL(sha256_K)(%rip), K

	// load W[0:15] into xmm0-xmm3
	vmovdqu	0*16(data), W0
	vmovdqu	1*16(data), W1
	vmovdqu	2*16(data), W2
	vmovdqu	3*16(data), W3
	addq	$64, data

	vpshufb	L_aligned_bswap, W0, W0
	vpshufb	L_aligned_bswap, W1, W1
	vpshufb	L_aligned_bswap, W2, W2
	vpshufb	L_aligned_bswap, W3, W3

	// compute WK[0:15] and save in stack
	vpaddd	0*16(K), %xmm0, %xmm4
	vpaddd	1*16(K), %xmm1, %xmm5
	vpaddd	2*16(K), %xmm2, %xmm6
	vpaddd	3*16(K), %xmm3, %xmm7
    addq	$64, K
	vmovdqa	%xmm4, WK(0)
	vmovdqa	%xmm5, WK(4)
	vmovdqa	%xmm6, WK(8)
	vmovdqa	%xmm7, WK(12)

L_loop:

	// digests a-h = ctx->states;
	mov		0*4(ctx), a
	mov		1*4(ctx), b
	mov		2*4(ctx), c
	mov		3*4(ctx), d
	mov		4*4(ctx), e
	mov		5*4(ctx), f
	mov		6*4(ctx), g
	mov		7*4(ctx), h

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    movq    $3, _i_loop
L_i_loop:
	roundsA_schedule W0,W1,W2,W3,16
	roundsE_schedule W1,W2,W3,W0,20
	roundsA_schedule W2,W3,W0,W1,24
	roundsE_schedule W3,W0,W1,W2,28
    subq    $1, _i_loop
    jg      L_i_loop

	// revert K to the beginning of K256[]
	subq		$256, K
	subq		$1, _num_blocks				// num_blocks--

	je		L_final_block				// if final block, wrap up final rounds

	// rounds 48:63 interleaved with W/WK initialization for next block rounds 0:15
	roundsA_update	48, W0
	roundsE_update	52, W1
	roundsA_update	56, W2
	roundsE_update	60, W3

	addq	$64, K
	addq	$64, data

	// ctx->states += digests a-h
	add		a, 0*4(ctx)
	add		b, 1*4(ctx)
	add		c, 2*4(ctx)
	add		d, 3*4(ctx)
	add		e, 4*4(ctx)
	add		f, 5*4(ctx)
	add		g, 6*4(ctx)
	add		h, 7*4(ctx)

	jmp		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
	roundsA	48
	roundsE	52
	roundsA	56
	roundsE	60

	// ctx->states += digests a-h
	add		a, 0*4(ctx)
	add		b, 1*4(ctx)
	add		c, 2*4(ctx)
	add		d, 3*4(ctx)
	add		e, 4*4(ctx)
	add		f, 5*4(ctx)
	add		g, 6*4(ctx)
	add		h, 7*4(ctx)

	// if kernel, restore xmm0-xmm7
#if BUILDKERNEL
    leaq    ymm_save, %rax
    andq    $-32, %rax
	vmovdqa	0*32(%rax), %ymm0
	vmovdqa	1*32(%rax), %ymm1
	vmovdqa	2*32(%rax), %ymm2
	vmovdqa	3*32(%rax), %ymm3
	vmovdqa	4*32(%rax), %ymm4
	vmovdqa	5*32(%rax), %ymm5
	vmovdqa	6*32(%rax), %ymm6
	vmovdqa	7*32(%rax), %ymm7
#endif

	// free allocated stack memory
	add		$stack_size, sp

	// restore callee-saved registers
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	pop		%rbx
	pop		%rbp

	// return
	ret

	// data for using ssse3 pshufb instruction (big-endian loading of data)
    CC_ASM_SECTION_CONST
    .p2align  4, 0x90

L_bswap:
    .long   0x00010203
    .long   0x04050607
    .long   0x08090a0b
    .long   0x0c0d0e0f


#endif      // x86_64

