# Copyright (c) (2016,2018,2019) Apple Inc. All rights reserved.
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
	This file provides x86_64 hand implementation of the following function

    void sha512_compress(uint64_t *state, size_t nblocks, const void *in);

	sha512 algorithm per block description:

		1. W(0:15) = big-endian (per 8 bytes) loading of input data (128 bytes)
		2. load 8 digests (each 64bit) a-h from state
		3. for r = 0:15
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
		4. for r = 16:79
				W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g

	In the assembly implementation:
		- a circular window of message schedule W(r:r+15) is updated and stored in xmm0-xmm7 (or ymm0-ymm3/zmm0-zmm1 for avx1/avx2)
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR (%r8-%r15) 

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 8 bytes) into xmm0:xmm7
	pre_calculate and store W+K(0:15) in stack

L_loop:

	load digests a-h from ctx->state;

	for (r=0;r<64;r+=2) {
		digests a-h update and permute round r:r+1
		update W([r:r+1]%16) and WK([r:r+1]%16) for the next 8th iteration
	}

	num_block--;
	if (num_block==0)	jmp L_last_block;

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+1
		load W([r:r+1]%16) (big-endian per 8 bytes) into xmm0:xmm7
		pre_calculate and store W+K([r:r+1]%16) in stack
	}

	ctx->states += digests a-h;

	jmp	L_loop;

L_last_block:

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+2
	}

	ctx->states += digests a-h;

	------------------------------------------------------------------------

	Apple CoreOS vector & numerics
*/
#if defined __x86_64__

	// associate variables with registers or memory

	#define	sp			%rsp
	#define	ctx			%rdi
	#define num_blocks	%rsi        // later move this to stack, use %rsi for temp variable u
	#define	data        %rdx

	#define	a			%r8
	#define	b			%r9
	#define	c			%r10
	#define	d			%r11
	#define	e			%r12
	#define	f			%r13
	#define	g			%r14
	#define	h			%r15

	#define	K			%rbx
    #define _num_blocks  (-48)(%rbp)        // rbx/r12-r15 
	#define stack_size	(8+32*12+128+16)	    // 8 (_num_blocks) + ymm0:ymm11 + WK(0:15) + 16byte for 32-byte alignment

	#define	L_aligned_bswap	L_bswap(%rip)   // bswap : big-endian loading of 4-byte words
	#define	ymm_save	128(sp)			    // starting address for xmm save/restore

	// 3 local variables
	#define	s	%rax
	#define	t	%rcx
	#define	u	%rsi

	// a window (16 quad-words) of message scheule
	#define	W0	%xmm0
	#define	W1	%xmm1
	#define	W2	%xmm2
	#define	W3	%xmm3
	#define	W4	%xmm4
	#define	W5	%xmm5
	#define	W6	%xmm6
	#define	W7	%xmm7

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   ((x)&15)*8(sp)

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

	.macro Ch arg0, arg1, arg2
#if 1
    mov     \arg2, t
    xor     \arg1, t
    and     \arg0, t
    xor     \arg2, t
#else
	mov		\arg0, t		// x
	mov		\arg0, s		// x
	not		t			// ~x
	and		\arg1, s		// x & y
	and		\arg2, t		// ~x & z
	xor		s, t		// t = ((x) & (y)) ^ ((~(x)) & (z));
#endif
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

// #define Gamma0(x)   (S64(1,  (x)) ^ S64(8, (x)) ^ R(7 ,   (x)))

	// performs Gamma0_512 on 2 words on an xmm registers
	// use xmm8/xmm9 as intermediate registers
	.macro	Gamma0 arg0
    vpsrlq  $1, \arg0, %xmm8      // part of S64(1, x)
    vpsllq  $56, \arg0, %xmm9     // part of S64(8, x)
    vpsrlq  $7, \arg0, \arg0         // R(7, x)
    vpxor   %xmm8, \arg0, \arg0
    vpsrlq  $7, %xmm8, %xmm8   // part of S64(8, x)
    vpxor   %xmm9, \arg0, \arg0
    vpsllq  $7, %xmm9, %xmm9   // part of S64(1, x)
    vpxor   %xmm8, \arg0, \arg0
    vpxor   %xmm9, \arg0, \arg0
	.endm

// #define Gamma1(x)   (S64(19, (x)) ^ S64(61, (x)) ^ R(6,   (x)))

	// performs Gamma1_512 on 2 words on an xmm registers
	// use xmm8/xmm9 as intermediate registers
	.macro	Gamma1 arg0
    vpsrlq  $19, \arg0, %xmm8     // part of S64(19, x)
    vpsllq  $3, \arg0, %xmm9      // part of S64(61, x)
    vpsrlq  $6, \arg0, \arg0         // R(6, x)
    vpxor   %xmm8, \arg0, \arg0
    vpsrlq  $42, %xmm8, %xmm8  // part of S64(61, x)
    vpxor   %xmm9, \arg0, \arg0
    vpsllq  $42, %xmm9, %xmm9  // part of S64(19, x)
    vpxor   %xmm8, \arg0, \arg0
    vpxor   %xmm9, \arg0, \arg0
	.endm

    // W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
    /*
        W0 W1 W2 W3 W4 W5 W6 W7
        
        update 2 quad words in W0 = W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1)). 
        use %xmm10, %xmm11 for temp
    */
    .macro  message_update2 arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7
    vpalignr $8, \arg4, \arg5, %xmm10     // vext(W4,W5)
    vpalignr $8, \arg0, \arg1, %xmm11     // vext(W0,W1)
    vpaddq   %xmm10, \arg0, \arg0          // W0 + vext(W4,W5)
    // vmovdqa  \arg7, %xmm10
    // Gamma1  %xmm10                   // Gamma1(W7)
    vpsrlq  $19, \arg7, %xmm8     // part of S64(19, x)
    vpsllq  $3, \arg7, %xmm9      // part of S64(61, x)
    vpsrlq  $6, \arg7, %xmm10        // R(6, x)
    vpxor   %xmm8, %xmm10, %xmm10
    vpsrlq  $42, %xmm8, %xmm8  // part of S64(61, x)
    vpxor   %xmm9, %xmm10, %xmm10
    vpsllq  $42, %xmm9, %xmm9  // part of S64(19, x)
    vpxor   %xmm8, %xmm10, %xmm10
    vpxor   %xmm9, %xmm10, %xmm10
    Gamma0  %xmm11                   // Gamma0(vext(W0,W1))
    vpaddq   %xmm10, \arg0, \arg0          // W0 + Gamma1(W7) + vext(W4,W5)
    vpaddq   %xmm11, \arg0, \arg0          // W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1))
    .endm 

// #define Sigma0(x)   (S64(28,  (x)) ^ S64(34, (x)) ^ S64(39, (x)))

	.macro	Sigma0 arg0
	mov		\arg0, t			// x
	mov		\arg0, s			// x
	ror		$28, t			// S(28,  (x))
	ror		$34, s			// S(34,  (x))
	xor		s, t			// S(28,  (x)) ^ S(34, (x))
	ror		$5, s			// S(39,  (x))
	xor		s, t			// t = (S(28,  (x)) ^ S(34, (x)) ^ S(39, (x)))
	.endm

// #define Sigma1(x)   (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))

	.macro	Sigma1 arg0
	mov		\arg0, s			// x
	ror		$14, s			// S(14,  (x))
	mov		s, t			// S(14,  (x))
	ror		$4, s			// S(18, (x))
	xor		s, t			// S(14,  (x)) ^ S(18, (x))
	ror		$23, s			// S(41, (x))
	xor		s, t			// t = (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))
	.endm

	// per round digests update
	.macro	round_ref arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
	Sigma1	\arg4				// t = Sigma1(e);
	add		t, \arg7			// h = h+Sigma1(e)
	Ch		\arg4, \arg5, \arg6		// t = Ch (e, f, g);
	add		t, \arg7			// h = h+Sigma1(e)+Ch(e,f,g);
	add		WK(\arg8), \arg7		// h = h+Sigma1(e)+Ch(e,f,g)+WK
	add		\arg7, \arg3			// d += h;
	Sigma0	\arg0				// t = Sigma0(a);
	add		t, \arg7			// h += Sigma0(a);
	Maj		\arg0, \arg1, \arg2		// t = Maj(a,b,c)
	add		t, \arg7			// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	.macro	round arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
	mov		\arg4, s
	mov		\arg0, t
	ror		$(41-18), s
	ror		$(39-34), t
	xor		\arg4, s
	mov		\arg5, u
	xor		\arg0, t
	ror		$(18-14), s
	xor		\arg6, u
	xor		\arg4, s
	ror		$(34-28), t
	and		\arg4, u
	xor		\arg0, t
	xor		\arg6, u
	ror		$14, s
	ror		$28, t
	add		s, u
	mov		\arg0, s
	add		WK(\arg8), u
	or		\arg2, s
	add		u, \arg7
	mov		\arg0, u
	add		\arg7, \arg3
	and		\arg1, s
	and		\arg2, u
	or		u, s
	add		t, \arg7
	add		s, \arg7	
	.endm

    /*
        16 rounds of hash update, update input schedule W (in vector register xmm0-xmm7) and WK = W + K (in stack)
    */
	.macro	rounds_schedule arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
    message_update2 W0, W1, W2, W3, W4, W5, W6, W7
    vmovdqa  0*16(K), %xmm8
	round	\arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, 0+\arg8
    vpaddq  W0, %xmm8, %xmm8
	round	\arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, 1+\arg8
    vmovdqa  %xmm8, WK(0)

    message_update2 W1, W2, W3, W4, W5, W6, W7, W0
    vmovdqa  1*16(K), %xmm8
	round	\arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, 2+\arg8
    vpaddq   W1, %xmm8, %xmm8
	round	\arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, 3+\arg8
    vmovdqa  %xmm8, WK(2)

    message_update2 W2, W3, W4, W5, W6, W7, W0, W1
    vmovdqa  2*16(K), %xmm8
	round	\arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, 4+\arg8
    vpaddq   W2, %xmm8, %xmm8
	round	\arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, 5+\arg8
    vmovdqa  %xmm8, WK(4)

    message_update2 W3, W4, W5, W6, W7, W0, W1, W2
    vmovdqa  3*16(K), %xmm8
	round	\arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, 6+\arg8
    vpaddq   W3, %xmm8, %xmm8
	round	\arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, 7+\arg8
    vmovdqa  %xmm8, WK(6)

    message_update2 W4, W5, W6, W7, W0, W1, W2, W3
    movdqa  4*16(K), %xmm8
	round	\arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, 8+\arg8
    paddq   W4, %xmm8
	round	\arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, 9+\arg8
    movdqa  %xmm8, WK(8)

    message_update2 W5, W6, W7, W0, W1, W2, W3, W4
    vmovdqa  5*16(K), %xmm8
	round	\arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, 10+\arg8
    vpaddq   W5, %xmm8, %xmm8
	round	\arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, 11+\arg8
    vmovdqa  %xmm8, WK(10)

    message_update2 W6, W7, W0, W1, W2, W3, W4, W5
    vmovdqa  6*16(K), %xmm8
	round	\arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, 12+\arg8
    vpaddq   W6, %xmm8, %xmm8
	round	\arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, 13+\arg8
    vmovdqa  %xmm8, WK(12)

    message_update2 W7, W0, W1, W2, W3, W4, W5, W6
    vmovdqa  7*16(K), %xmm8
	round	\arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, 14+\arg8
    vpaddq   W7, %xmm8, %xmm8
	round	\arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, 15+\arg8
    vmovdqa  %xmm8, WK(14)

    addq    $128, K
	.endm

    /*
        16 rounds of hash update, load new input schedule W (in vector register xmm0-xmm7) and update WK = W + K (in stack)
    */
	.macro	rounds_schedule_initial arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
    vmovdqu  0*16(data), W0
    vmovdqa  0*16(K), %xmm8
    vpshufb  L_aligned_bswap, W0, W0
	round	\arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, 0+\arg8
    vpaddq   W0, %xmm8, %xmm8
	round	\arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, 1+\arg8
    vmovdqa  %xmm8, WK(0)

    vmovdqu  1*16(data), W1
    vmovdqa  1*16(K), %xmm8
    vpshufb  L_aligned_bswap, W1, W1
	round	\arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, 2+\arg8
    vpaddq   W1, %xmm8, %xmm8
	round	\arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, 3+\arg8
    vmovdqa  %xmm8, WK(2)

    vmovdqu  2*16(data), W2
    vmovdqa  2*16(K), %xmm8
    vpshufb  L_aligned_bswap, W2, W2
	round	\arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, 4+\arg8
    vpaddq   W2, %xmm8, %xmm8
	round	\arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, 5+\arg8
    vmovdqa  %xmm8, WK(4)

    vmovdqu  3*16(data), W3
    vmovdqa  3*16(K), %xmm8
    vpshufb  L_aligned_bswap, W3, W3
	round	\arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, 6+\arg8
    vpaddq   W3, %xmm8, %xmm8
	round	\arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, 7+\arg8
    vmovdqa  %xmm8, WK(6)

    vmovdqu  4*16(data), W4
    vmovdqa  4*16(K), %xmm8
    vpshufb  L_aligned_bswap, W4, W4
	round	\arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, 8+\arg8
    vpaddq   W4, %xmm8, %xmm8
	round	\arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, 9+\arg8
    vmovdqa  %xmm8, WK(8)

    vmovdqu  5*16(data), W5
    vmovdqa  5*16(K), %xmm8
    vpshufb  L_aligned_bswap, W5, W5
	round	\arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, 10+\arg8
    vpaddq   W5, %xmm8, %xmm8
	round	\arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, 11+\arg8
    vmovdqa  %xmm8, WK(10)

    vmovdqu  6*16(data), W6
    vmovdqa  6*16(K), %xmm8
    vpshufb  L_aligned_bswap, W6, W6
	round	\arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, 12+\arg8
    vpaddq   W6, %xmm8, %xmm8
	round	\arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, 13+\arg8
    vmovdqa  %xmm8, WK(12)

    vmovdqu  7*16(data), W7
    vmovdqa  7*16(K), %xmm8
    vpshufb  L_aligned_bswap, W7, W7
	round	\arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, 14+\arg8
    vpaddq   W7, %xmm8, %xmm8
	round	\arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, 15+\arg8
    vmovdqa  %xmm8, WK(14)

    addq    $128, K
    addq    $128, data 
	.endm

    /*
        16 rounds of hash update
    */
	.macro	rounds_schedule_final arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
	round	\arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, 0+\arg8
	round	\arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, 1+\arg8

	round	\arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, 2+\arg8
	round	\arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, 3+\arg8

	round	\arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, 4+\arg8
	round	\arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, 5+\arg8

	round	\arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, 6+\arg8
	round	\arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, 7+\arg8

	round	\arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, 8+\arg8
	round	\arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, \arg6, 9+\arg8

	round	\arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, \arg5, 10+\arg8
	round	\arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, \arg4, 11+\arg8

	round	\arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, \arg3, 12+\arg8
	round	\arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, \arg2, 13+\arg8

	round	\arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, \arg1, 14+\arg8
	round	\arg1, \arg2, \arg3, \arg4, \arg5, \arg6, \arg7, \arg0, 15+\arg8
	.endm

	.text
    .globl	_AccelerateCrypto_SHA512_compress_AVX1
_AccelerateCrypto_SHA512_compress_AVX1:

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
    andq    $-32, sp                // aligned sp to 32-bytes

	// if kernel code, save used xmm registers
#if BUILDKERNEL
	vmovdqa	%ymm0, 0*32+ymm_save
	vmovdqa	%ymm1, 1*32+ymm_save
	vmovdqa	%ymm2, 2*32+ymm_save
	vmovdqa	%ymm3, 3*32+ymm_save
	vmovdqa	%ymm4, 4*32+ymm_save
	vmovdqa	%ymm5, 5*32+ymm_save
	vmovdqa	%ymm6, 6*32+ymm_save
	vmovdqa	%ymm7, 7*32+ymm_save
	vmovdqa	%ymm8, 8*32+ymm_save
	vmovdqa	%ymm9, 9*32+ymm_save
	vmovdqa	%ymm10, 10*32+ymm_save
	vmovdqa	%ymm11, 11*32+ymm_save
#endif

    movq    num_blocks, _num_blocks

	// set up bswap parameters in the aligned stack space and pointer to table K512[]
	lea		CC_C_LABEL(sha512_K)(%rip), K

	// load W[0:15] into xmm0-xmm7
	vmovdqu	0*16(data), W0
	vmovdqu	1*16(data), W1
	vmovdqu	2*16(data), W2
	vmovdqu	3*16(data), W3
	vmovdqu	4*16(data), W4
	vmovdqu	5*16(data), W5
	vmovdqu	6*16(data), W6
	vmovdqu	7*16(data), W7
	addq	$128, data

    vmovdqa  L_aligned_bswap, %xmm8
	vpshufb	%xmm8, W0, W0
	vpshufb	%xmm8, W1, W1
	vpshufb	%xmm8, W2, W2
	vpshufb	%xmm8, W3, W3
	vpshufb	%xmm8, W4, W4
	vpshufb	%xmm8, W5, W5
	vpshufb	%xmm8, W6, W6
	vpshufb	%xmm8, W7, W7

	// compute WK[0:15] and save in stack
	vpaddq	0*16(K), %xmm0, %xmm8
	vpaddq	1*16(K), %xmm1, %xmm9
	vpaddq	2*16(K), %xmm2, %xmm10
	vpaddq	3*16(K), %xmm3, %xmm11
	vmovdqa	%xmm8, WK(0)
	vmovdqa	%xmm9, WK(2)
	vmovdqa	%xmm10, WK(4)
	vmovdqa	%xmm11, WK(6)

	vpaddq	4*16(K), %xmm4, %xmm8
	vpaddq	5*16(K), %xmm5, %xmm9
	vpaddq	6*16(K), %xmm6, %xmm10
	vpaddq	7*16(K), %xmm7, %xmm11
	vmovdqa	%xmm8, WK(8)
	vmovdqa	%xmm9, WK(10)
	vmovdqa	%xmm10, WK(12)
	vmovdqa	%xmm11, WK(14)
    addq	$128, K

L_loop:

	// digests a-h = ctx->states;
	mov		0*8(ctx), a
	mov		1*8(ctx), b
	mov		2*8(ctx), c
	mov		3*8(ctx), d
	mov		4*8(ctx), e
	mov		5*8(ctx), f
	mov		6*8(ctx), g
	mov		7*8(ctx), h

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    rounds_schedule a, b, c, d, e, f, g, h, 16
    rounds_schedule a, b, c, d, e, f, g, h, 32
    rounds_schedule a, b, c, d, e, f, g, h, 48
    rounds_schedule a, b, c, d, e, f, g, h, 64

	// revert K to the beginning of K256[]
	subq		$640, K
	subq		$1, _num_blocks				// num_blocks--

	je		L_final_block				// if final block, wrap up final rounds

    rounds_schedule_initial a, b, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
	add		a, 0*8(ctx)
	add		b, 1*8(ctx)
	add		c, 2*8(ctx)
	add		d, 3*8(ctx)
	add		e, 4*8(ctx)
	add		f, 5*8(ctx)
	add		g, 6*8(ctx)
	add		h, 7*8(ctx)

	jmp		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
    rounds_schedule_final a, b, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
	add		a, 0*8(ctx)
	add		b, 1*8(ctx)
	add		c, 2*8(ctx)
	add		d, 3*8(ctx)
	add		e, 4*8(ctx)
	add		f, 5*8(ctx)
	add		g, 6*8(ctx)
	add		h, 7*8(ctx)

	// if kernel, restore ymm0-ymm11
#if BUILDKERNEL
	vmovdqa	0*32+ymm_save, %ymm0
	vmovdqa	1*32+ymm_save, %ymm1
	vmovdqa	2*32+ymm_save, %ymm2
	vmovdqa	3*32+ymm_save, %ymm3
	vmovdqa	4*32+ymm_save, %ymm4
	vmovdqa	5*32+ymm_save, %ymm5
	vmovdqa	6*32+ymm_save, %ymm6
	vmovdqa	7*32+ymm_save, %ymm7
	vmovdqa	8*32+ymm_save, %ymm8
	vmovdqa	9*32+ymm_save, %ymm9
	vmovdqa	10*32+ymm_save, %ymm10
	vmovdqa	11*32+ymm_save, %ymm11
#endif

	// free allocated stack memory
    leaq    -40(%rbp), sp

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
    .p2align  4

L_bswap:
    .quad   0x0001020304050607
    .quad   0x08090a0b0c0d0e0f

#endif      // x86_64

