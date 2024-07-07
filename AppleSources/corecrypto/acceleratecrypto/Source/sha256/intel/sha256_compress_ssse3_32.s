# Copyright (c) (2010,2011,2012,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
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
	This file provides i386 hand implementation of the following function

	sha2_void sha256_compile(sha256_ctx ctx[1]);

	which is a C function in CommonCrypto Source/Digest/sha2.c

	The implementation here is modified from another sha256 i386 implementation for sha256 in the xnu.
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
#if defined __i386__ 

	// associate variables with registers or memory

	#define	sp 	%esp
	#define stack_size	(12+16*8+16+16+64)	// 12 (align) + xmm0:xmm7 + 16 (c,f,h,K) + L_aligned_bswap + WK(0:15)
	#define	ctx_addr	20+stack_size(sp)	// ret_addr + 4 registers = 20, 1st caller argument
	#define	num_blocks	24+stack_size(sp)	// 2nd caller argument
	#define	data_addr	28+stack_size(sp)	// 3rd caller argument

	#define	a	%ebx
	#define	b	%edx
	#define	c	64(sp)
	#define	d	%ebp
	#define	e	%esi
	#define	f	68(sp)
	#define	g	%edi
	#define	h	72(sp)

	#define	K	76(sp)					// pointer to K256[] table
	#define	L_aligned_bswap	80(sp)		// bswap : big-endian loading of 4-byte words
	#define	xmm_save	96(sp)			// starting address for xmm save/restore

	// 2 local variables
	#define	t	%eax
	#define	s	%ecx

	// a window (16 words) of message scheule
	#define	W0	%xmm0
	#define	W1	%xmm1
	#define	W2	%xmm2
	#define	W3	%xmm3

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   ((x)&15)*4(sp)

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

	.macro Ch
	mov		$0, t		// x
	mov		$0, s		// x
	not		t			// ~x
	and		$1, s		// x & y
	and		$2, t		// ~x & z
	xor		s, t		// t = ((x) & (y)) ^ ((~(x)) & (z));
	.endm

// #define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

	.macro	Maj
	mov	 	$1,	t // y
	mov		$2,	s // z
	xor		$2,	t // y^z
	and		$1,	s // y&z
	and		$0, 	t // x&(y^z)
	xor		s,	t // Maj(x,y,z)
	.endm

// #define sigma0_256(x)   (S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))

	// performs sigma0_256 on 4 words on an xmm registers
	// use xmm6/xmm7 as intermediate registers
	.macro	sigma0
	movdqa	$0, %xmm6
	movdqa	$0, %xmm7
	psrld	$$3, $0			// SHR3(x)
	psrld	$$7, %xmm6		// part of ROTR7
	pslld	$$14, %xmm7		// part of ROTR18
	pxor	%xmm6, $0
	pxor	%xmm7, $0
	psrld	$$11, %xmm6		// part of ROTR18
	pslld	$$11, %xmm7		// part of ROTR7
	pxor	%xmm6, $0
	pxor	%xmm7, $0
	.endm

// #define sigma1_256(x)   (S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

	// performs sigma1_256 on 4 words on an xmm registers
	// use xmm6/xmm7 as intermediate registers
	.macro	sigma1
	movdqa	$0, %xmm6
	movdqa	$0, %xmm7
	psrld	$$10, $0		// SHR10(x)
	psrld	$$17, %xmm6		// part of ROTR17
	pxor	%xmm6, $0
	pslld	$$13, %xmm7		// part of ROTR19
	pxor	%xmm7, $0
	psrld	$$2, %xmm6		// part of ROTR19
	pxor	%xmm6, $0
	pslld	$$2, %xmm7		// part of ROTR17
	pxor	%xmm7, $0
	.endm

// #define Sigma0_256(x)   (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))

	.macro	Sigma0
	mov		$0, t			// x
	mov		$0, s			// x
	ror		$$2, t			// S32(2,  (x))
	ror		$$13, s			// S32(13,  (x))
	xor		s, t			// S32(2,  (x)) ^ S32(13, (x))
	ror		$$9, s			// S32(22,  (x))
	xor		s, t			// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
	.endm

// #define Sigma1_256(x)   (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))

	.macro	Sigma1
	mov		$0, s			// x
	ror		$$6, s			// S32(6,  (x))
	mov		s, t			// S32(6,  (x))
	ror		$$5, s			// S32(11, (x))
	xor		s, t			// S32(6,  (x)) ^ S32(11, (x))
	ror		$$14, s			// S32(25, (x))
	xor		s, t			// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	.endm

	// per round digests update
	.macro	round
	Sigma1	$4				// t = T1
	add		t, $7			// use h to store h+Sigma1(e)
	Ch		$4, $5, $6		// t = Ch (e, f, g);
	add		$7, t			// t = h+Sigma1(e)+Ch(e,f,g);
	add		WK($8), t		// h = T1
	add		t, $3			// d += T1;
	mov		t, $7			// h = T1
	Sigma0	$0				// t = Sigma0(a);
	add		t, $7			// h = T1 + Sigma0(a);
	Maj		$0, $1, $2		// t = Maj(a,b,c)
	add		t, $7			// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	// per 4 rounds digests update and permutation
	// permutation is absorbed by rotating the roles of digests a-h
	.macro	rounds
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
	.endm

	// update the message schedule W and W+K (4 rounds) 16 rounds ahead in the future
	.macro	message_schedule

	// 4 32-bit K256 words in xmm5
	mov		K, t
	movdqu	(t), %xmm5
	addl	$$16, K				// K points to next K256 word for next iteration
	movdqa	$1, %xmm4 			// W7:W4
	palignr	$$4, $0, %xmm4		// W4:W1
	sigma0	%xmm4				// sigma0(W4:W1)
	movdqa	$3, %xmm6 			// W15:W12
	paddd	%xmm4, $0			// $0 = W3:W0 + sigma0(W4:W1)
	palignr	$$4, $2, %xmm6		// W12:W9
	paddd	%xmm6, $0			// $0 = W12:W9 + sigma0(W4:W1) + W3:W0
	movdqa	$3, %xmm4			// W15:W12
	psrldq	$$8, %xmm4			// 0,0,W15,W14
	sigma1	%xmm4				// sigma1(0,0,W15,W14)
	paddd	%xmm4, $0			// sigma1(0,0,W15,W14) + W12:W9 + sigma0(W4:W1) + W3:W0
	movdqa	$0, %xmm4			// W19-sigma1(W17), W18-sigma1(W16), W17, W16
	pslldq	$$8, %xmm4			// W17, W16, 0, 0
	sigma1	%xmm4				// sigma1(W17,W16,0,0)
	paddd	%xmm4, $0			// W19:W16
	paddd	$0, %xmm5			// WK
	movdqa	%xmm5, WK($4)
	.endm

	// this macro is used in the last 16 rounds of a current block
	// it reads the next message (16 4-byte words), load it into 4 words W[r:r+3], computes WK[r:r+3]
	// and save into stack to prepare for next block

	.macro	update_W_WK
	mov		data_addr, t
	movdqu	$0*16(t), $1		// read 4 4-byte words
	pshufb	L_aligned_bswap, $1	// big-endian of each 4-byte word, W[r:r+3]
	mov		K, t
	movdqu	$0*16(t), %xmm4		// K[r:r+3]
	paddd	$1, %xmm4			// WK[r:r+3]
	movdqa	%xmm4, WK($0*4)		// save WK[r:r+3] into stack circular buffer
	.endm

    .section    __IMPORT,__pointers,non_lazy_symbol_pointers
L_sha256_K$non_lazy_ptr:
.indirect_symbol CC_C_LABEL(sha256_K)
    .long   0

	.text
    .globl	_AccelerateCrypto_SHA256_compress_ssse3
_AccelerateCrypto_SHA256_compress_ssse3:

	// push callee-saved registers
    push    %ebp
	push    %ebx
    push    %esi
    push    %edi

	// allocate stack space
	sub		$stack_size, sp

	// if kernel code, save used xmm registers
#if BUILDKERNEL
	movdqa	%xmm0, 0*16+xmm_save
	movdqa	%xmm1, 1*16+xmm_save
	movdqa	%xmm2, 2*16+xmm_save
	movdqa	%xmm3, 3*16+xmm_save
	movdqa	%xmm4, 4*16+xmm_save
	movdqa	%xmm5, 5*16+xmm_save
	movdqa	%xmm6, 6*16+xmm_save
	movdqa	%xmm7, 7*16+xmm_save
#endif

	// set up bswap parameters in the aligned stack space and pointer to table K256[]
	call    0f          // Push program counter onto stack.
0:	pop     t      // Get program counter.
	mov L_sha256_K$non_lazy_ptr-0b(t), t
	mov		t, K
	call    0f          // Push program counter onto stack.
0:	pop     %eax		// Get program counter.
	lea		L_bswap-0b(%eax), %eax
	movdqa	(%eax), %xmm0
	movdqa	%xmm0, L_aligned_bswap

	// load W[0:15] into xmm0-xmm3
	mov		data_addr, t
	movdqu	0*16(t), W0
	movdqu	1*16(t), W1
	movdqu	2*16(t), W2
	movdqu	3*16(t), W3
	addl	$64, data_addr

	pshufb	L_aligned_bswap, W0
	pshufb	L_aligned_bswap, W1
	pshufb	L_aligned_bswap, W2
	pshufb	L_aligned_bswap, W3

	// compute WK[0:15] and save in stack
	mov		K, t
	movdqu	0*16(t), %xmm4
	movdqu	1*16(t), %xmm5
	movdqu	2*16(t), %xmm6
	movdqu	3*16(t), %xmm7
    addl	$64, K
	paddd	%xmm0, %xmm4
	paddd	%xmm1, %xmm5
	paddd	%xmm2, %xmm6
	paddd	%xmm3, %xmm7
	movdqa	%xmm4, WK(0)
	movdqa	%xmm5, WK(4)
	movdqa	%xmm6, WK(8)
	movdqa	%xmm7, WK(12)

L_loop:

	// digests a-h = ctx->states;
	mov		ctx_addr, t
	mov 	0*4(t), a
	mov 	1*4(t), b
	mov 	2*4(t), s
	mov		s, c
	mov 	3*4(t), d
	mov 	4*4(t), e
	mov 	5*4(t), s
	mov		s, f
	mov 	6*4(t), g
	mov 	7*4(t), s
	mov		s, h

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
	rounds	a, b, c, d, e, f, g, h, 0
	message_schedule W0,W1,W2,W3,16
	rounds	e, f, g, h, a, b, c, d, 4
	message_schedule W1,W2,W3,W0,20
	rounds	a, b, c, d, e, f, g, h, 8
	message_schedule W2,W3,W0,W1,24
	rounds	e, f, g, h, a, b, c, d, 12
	message_schedule W3,W0,W1,W2,28
	rounds	a, b, c, d, e, f, g, h, 16
	message_schedule W0,W1,W2,W3,32
	rounds	e, f, g, h, a, b, c, d, 20
	message_schedule W1,W2,W3,W0,36
	rounds	a, b, c, d, e, f, g, h, 24
	message_schedule W2,W3,W0,W1,40
	rounds	e, f, g, h, a, b, c, d, 28
	message_schedule W3,W0,W1,W2,44
	rounds	a, b, c, d, e, f, g, h, 32
	message_schedule W0,W1,W2,W3,48
	rounds	e, f, g, h, a, b, c, d, 36
	message_schedule W1,W2,W3,W0,52
	rounds	a, b, c, d, e, f, g, h, 40
	message_schedule W2,W3,W0,W1,56
	rounds	e, f, g, h, a, b, c, d, 44
	message_schedule W3,W0,W1,W2,60

	// revert K to the beginning of K256[]
	subl		$256, K
	subl		$1, num_blocks				// num_blocks--

	je		L_final_block				// if final block, wrap up final rounds

	// rounds 48:63 interleaved with W/WK initialization for next block rounds 0:15
	rounds	a, b, c, d, e, f, g, h, 48
	update_W_WK	0, W0
	rounds	e, f, g, h, a, b, c, d, 52
	update_W_WK	1, W1
	rounds	a, b, c, d, e, f, g, h, 56
	update_W_WK	2, W2
	rounds	e, f, g, h, a, b, c, d, 60
	update_W_WK	3, W3

	addl	$64, K
	addl	$64, data_addr

	// ctx->states += digests a-h
	mov		ctx_addr, t
	add		a, 0*4(t)
	add		b, 1*4(t)
	mov		c, s
	add		s, 2*4(t)
	add		d, 3*4(t)
	add		e, 4*4(t)
	mov		f, s
	add		s, 5*4(t)
	add		g, 6*4(t)
	mov		h, s
	add		s, 7*4(t)

	jmp		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
	rounds	a, b, c, d, e, f, g, h, 48
	rounds	e, f, g, h, a, b, c, d, 52
	rounds	a, b, c, d, e, f, g, h, 56
	rounds	e, f, g, h, a, b, c, d, 60

	// ctx->states += digests a-h
	mov		ctx_addr, t
	add		a, 0*4(t)
	add		b, 1*4(t)
	mov		c, s
	add		s, 2*4(t)
	add		d, 3*4(t)
	add		e, 4*4(t)
	mov		f, s
	add		s, 5*4(t)
	add		g, 6*4(t)
	mov		h, s
	add		s, 7*4(t)

	// if kernel, restore xmm0-xmm7
#if BUILDKERNEL
	movdqa	0*16+xmm_save, %xmm0
	movdqa	1*16+xmm_save, %xmm1
	movdqa	2*16+xmm_save, %xmm2
	movdqa	3*16+xmm_save, %xmm3
	movdqa	4*16+xmm_save, %xmm4
	movdqa	5*16+xmm_save, %xmm5
	movdqa	6*16+xmm_save, %xmm6
	movdqa	7*16+xmm_save, %xmm7
#endif

	// free allocated stack memory
	add		$stack_size, sp

	// restore callee-saved registers
    pop		%edi
    pop		%esi
	pop		%ebx
    pop		%ebp

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


#endif      // i386 

