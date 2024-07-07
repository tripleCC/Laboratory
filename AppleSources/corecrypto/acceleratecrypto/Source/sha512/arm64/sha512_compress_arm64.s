# Copyright (c) (2016,2018-2020,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

/*
	This file provides arm64 hand implementation of the following function

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
		- a circular window of message schedule W(r:r+15) is updated and stored in v0-v7
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR (%r8-%r15) 

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 8 bytes) into v0:v7
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
		load W([r:r+1]%16) (big-endian per 8 bytes) into v0:v7
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

#if defined(__arm64__) && defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)

#include "ccarm_pac_bti_macros.h"
	// associate variables with registers or memory

    #define stack_size     (16*8) 

	#define	ctx			x0
	#define num_blocks	x1
	#define	data        x2

	#define	a			x4
	#define	bb			x5
	#define	c			x6
	#define	d			x7
	#define	e			x8
	#define	f			x9
	#define	g			x10
	#define	h			x11

	#define	K			x3

	// 3 local variables
	#define	s	x12
	#define	t	x13
	#define	u	x14

	// a window (16 quad-words) of message scheule
	#define	W0	v0
	#define	W1	v1
	#define	W2	v2
	#define	W3	v3
	#define	W4	v4
	#define	W5	v5
	#define	W6	v6
	#define	W7	v7

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   [sp,#((x)&15)*8]

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

    /* t = Ch($0, $1, $2) */
	.macro Ch
    eor     t, $1, $2  
    and     t, t, $0
    eor     t, t, $2
	.endm

// #define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

    
    /* t = Maj($0, $1, $2) */
	.macro	Maj
	eor     t, $1, $2  // y^z
	and		s, $1,$2   // y&z
	and		t, t, $0   // x&(y^z)
	eor		t, t, s    // Maj(x,y,z)
	.endm

// #define Gamma0(x)   (S64(1,  (x)) ^ S64(8, (x)) ^ R(7 ,   (x)))

	// performs Gamma0_512 on 2 words on an vector registers
	// use v20/v21 as intermediate registers
	.macro	Gamma0
    ushr.2d v20, $0, #1         // part of S64(1, x)
    shl.2d  v21, $0, #56        // part of S64(8, x)
    ushr.2d $0, $0, #7          // R(7, x)
    eor.16b $0, $0, v20
    ushr.2d v20, v20, #7        // part of S64(8, x)
    eor.16b $0, $0, v21
    shl.2d  v21,v21, #7         // part of S64(1, x)
    eor.16b $0, $0, v20
    eor.16b $0, $0, v21
	.endm

// #define Gamma1(x)   (S64(19, (x)) ^ S64(61, (x)) ^ R(6,   (x)))

	// performs Gamma1_512 on 2 words on an vector registers
	// use v16/v17 as intermediate registers
	.macro	Gamma1
    ushr.2d v16, $0, #19        // part of S64(19, x)
    shl.2d  v17, $0, #3         // part of S64(61, x)
    ushr.2d $0, $0, #6          // R(6, x)
    eor.16b $0, $0, v16
    ushr.2d v16, v16, #42       // part of S64(61, x)
    eor.16b $0, $0, v17
    shl.2d  v17,v17, #42        // part of S64(19, x)
    eor.16b $0, $0, v16
    eor.16b $0, $0, v17
	.endm

    // W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
    /*
        W0 W1 W2 W3 W4 W5 W6 W7
        
        update 2 quad words in W0 = W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1)). 
        use v16-v19 for temp
    */
    .macro  message_update2 vec0, vec1, vec2, vec3, vec4, vec5, vec6, vec7
    ext.16b v18, \vec4, \vec5, #8         // vext(W4,W5)
    ext.16b v19, \vec0, \vec1, #8         // vext(W0,W1)

    ushr.2d  v16, \vec7, #19            // part of S64(19, x)
    shl.2d  v17, \vec7, #3             // part of S64(61, x)
    add.2d  \vec0, \vec0, v18             // W0 + vext(W4,W5)
    ushr.2d v18, \vec7, #6             // R(6,x)
    ushr.2d v20, v19, #1         // part of S64(1, x)
    shl.2d  v21, v19, #56        // part of S64(8, x)
    ushr.2d v19, v19, #7          // R(7, x)

    eor.16b v18, v18, v16
    ushr.2d v16, v16, #42           // part of S64(61, x)
    eor.16b v19, v19, v20
    ushr.2d v20, v20, #7        // part of S64(8, x)

    eor.16b v18, v18, v17
    shl.2d  v17, v17, #42           // part of S64(19, x)
    eor.16b v19, v19, v21
    shl.2d  v21,v21, #7         // part of S64(1, x)
    eor.16b v18, v18, v16
    eor.16b v19, v19, v20

    eor.16b v18, v18, v17
    eor.16b v19, v19, v21

    add.2d  \vec0, \vec0, v18             // W0 + Gamma1(W7) + vext(W4,W5)
    add.2d  \vec0, \vec0, v19             // W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1))
    .endm 

// #define Sigma0(x)   (S64(28,  (x)) ^ S64(34, (x)) ^ S64(39, (x)))

	.macro	Sigma0
    ror     t, $0, #28
    eor     t, t, $0, ror #34
    eor     t, t, $0, ror #39
	.endm

// #define Sigma1(x)   (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))

	.macro	Sigma1
    ror     t, $0, #14
    eor     t, t, $0, ror #18
    eor     t, t, $0, ror #41
	.endm

	// per round digests update
	.macro	round_ref
	Sigma1	$4				// t = Sigma1(e);
	add		$7, $7, t		// h = h+Sigma1(e)
	Ch		$4, $5, $6		// t = Ch (e, f, g);
    ldr     s, WK($8)       // s = WK
	add		$7, $7, t		// h = h+Sigma1(e)+Ch(e,f,g);
	add		$7, $7, s		// h = h+Sigma1(e)+Ch(e,f,g)+WK
	add		$3, $3, $7		// d += h;
	Sigma0	$0				// t = Sigma0(a);
	add		$7, $7, t		// h += Sigma0(a);
	Maj		$0, $1, $2		// t = Maj(a,b,c)
	add		$7, $7, t		// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	.macro	round s0, s1, s2, s3, s4, s5, s6, s7, s8
    ror     t, \s4, #14
    eor     s, \s5, \s6  
    ldr     u, WK(\s8)       // t = WK
    eor     t, t, \s4, ror #18
    and     s, s, \s4
	add		\s7, \s7, u		// h = h+WK
    eor     t, t, \s4, ror #41
    eor     s, s, \s6
	add		\s7, \s7, t		// h = h+WK+Sigma1(e)
	eor     t, \s1, \s2  // y^z
	add		\s7, \s7, s		// h = h+WK+Sigma1(e)+Ch(e,f,g);
    ror     s, \s0, #28
	add		\s3, \s3, \s7		// d += h;
	and		u, \s1,\s2   // y&z
    eor     s, s, \s0, ror #34
	and		t, t, \s0   // x&(y^z)
    eor     s, s, \s0, ror #39
	eor		t, t, u    // Maj(x,y,z)
	add		\s7, \s7, s		// h += Sigma0(a);
	add		\s7, \s7, t		// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

    .macro  combined_message_round_update2 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, vec0, vec1, vec2, vec3, vec4, vec5, vec6, vec7

    //
    // message_update2 \vec0, \vec1, \vec2, \vec3, \vec4, \vec5, \vec6, \vec7
	// round	\s0, \s1, \s2, \s3, \s4, \s5, \s6, \s7, 0+\s8+\s9
	// round	\s7, \s0, \s1, \s2, \s3, \s4, \s5, \s6, 1+\s8+\s9

    ror     t, \s4, #14
    ldr     u, WK(0+\s8+\s9)       // t = WK
    eor     s, \s5, \s6
    ext.16b v18, \vec4, \vec5, #8         // vext(W4,W5)
    eor     t, t, \s4, ror #18
    and     s, s, \s4
    ext.16b v19, \vec0, \vec1, #8         // vext(W0,W1)

    add     \s7, \s7, u     // h = h+WK
    eor     t, t, \s4, ror #41
    ushr.2d  v16, \vec7, #19            // part of S64(19, x)
    eor     s, s, \s6
    add     \s7, \s7, t     // h = h+WK+Sigma1(e)
    shl.2d  v17, \vec7, #3             // part of S64(61, x)
    eor     t, \s1, \s2  // y^z
    add.2d  \vec0, \vec0, v18             // W0 + vext(W4,W5)
    ushr.2d v18, \vec7, #6             // R(6,x)
    add     \s7, \s7, s     // h = h+WK+Sigma1(e)+Ch(e,f,g);
    ushr.2d v20, v19, #1         // part of S64(1, x)
    ror     s, \s0, #28
    shl.2d  v21, v19, #56        // part of S64(8, x)
    add     \s3, \s3, \s7       // d += h;
    ushr.2d v19, v19, #7          // R(7, x)
    and     u, \s1,\s2   // y&z

    eor.16b v18, v18, v16
    eor     s, s, \s0, ror #34
    ushr.2d v16, v16, #42           // part of S64(61, x)
    and     t, t, \s0   // x&(y^z)
    eor.16b v19, v19, v20
    eor     s, s, \s0, ror #39
    ushr.2d v20, v20, #7        // part of S64(8, x)
    eor     t, t, u    // Maj(x,y,z)

    eor.16b v18, v18, v17
    add     \s7, \s7, s     // h += Sigma0(a);
    shl.2d  v17, v17, #42           // part of S64(19, x)
    add     \s7, \s7, t     // h = T1 + Sigma0(a) + Maj(a,b,c);
    eor.16b v19, v19, v21
    ror     t, \s3, #14
    shl.2d  v21,v21, #7         // part of S64(1, x)
    ldr     u, WK(1+\s8+\s9)       // t = WK
    eor     s, \s4, \s5
    eor.16b v18, v18, v16
    ldr     q16, [K]
    eor     t, t, \s3, ror #18
    eor.16b v19, v19, v20
    add     K, K, #16

    eor.16b v18, v18, v17
    and     s, s, \s3
    eor.16b v19, v19, v21
    add     \s6, \s6, u     // h = h+WK

    add.2d  \vec0, \vec0, v18             // W0 + Gamma1(W7) + vext(W4,W5)
    eor     t, t, \s3, ror #41
    add.2d  \vec0, \vec0, v19             // W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1))
    eor     s, s, \s5
    add     \s6, \s6, t     // h = h+WK+Sigma1(e)
    eor     t, \s0, \s1  // y^z
    add.2d  v16, v16, \vec0
    add     \s6, \s6, s     // h = h+WK+Sigma1(e)+Ch(e,f,g);
    ror     s, \s7, #28
    add     \s2, \s2, \s6       // d += h;
    and     u, \s0,\s1   // y&z
    eor     s, s, \s7, ror #34
    and     t, t, \s7   // x&(y^z)
    eor     s, s, \s7, ror #39
    eor     t, t, u    // Maj(x,y,z)
    add     \s6, \s6, s     // h += Sigma0(a);
    add     \s6, \s6, t     // h = T1 + Sigma0(a) + Maj(a,b,c);

    str     q16, WK(\s9)
    .endm

    /*
        16 rounds of hash update, update input schedule W (in vector register v0-v7) and WK = W + K (in stack)
    */
	.macro	rounds_schedule

    combined_message_round_update2  $0, $1, $2, $3, $4, $5, $6, $7, $8, 0, W0, W1, W2, W3, W4, W5, W6, W7
    combined_message_round_update2  $6, $7, $0, $1, $2, $3, $4, $5, $8, 2, W1, W2, W3, W4, W5, W6, W7, W0
    combined_message_round_update2  $4, $5, $6, $7, $0, $1, $2, $3, $8, 4, W2, W3, W4, W5, W6, W7, W0, W1
    combined_message_round_update2  $2, $3, $4, $5, $6, $7, $0, $1, $8, 6, W3, W4, W5, W6, W7, W0, W1, W2
    combined_message_round_update2  $0, $1, $2, $3, $4, $5, $6, $7, $8, 8, W4, W5, W6, W7, W0, W1, W2, W3
    combined_message_round_update2  $6, $7, $0, $1, $2, $3, $4, $5, $8,10, W5, W6, W7, W0, W1, W2, W3, W4
    combined_message_round_update2  $4, $5, $6, $7, $0, $1, $2, $3, $8,12, W6, W7, W0, W1, W2, W3, W4, W5
    combined_message_round_update2  $2, $3, $4, $5, $6, $7, $0, $1, $8,14, W7, W0, W1, W2, W3, W4, W5, W6

	.endm

    /*
        16 rounds of hash update, load new input schedule W (in vector register v0-v7) and update WK = W + K (in stack)
    */
    .macro  combined_initial_round_update2 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, vec0

    ror     t, \s4, #14
    ldr     u, WK(0+\s8+\s9)       // t = WK
    eor     s, \s5, \s6  
    ld1.16b {\vec0}, [data], #16
    eor     t, t, \s4, ror #18
    and     s, s, \s4
	add		\s7, \s7, u		// h = h+WK
    eor     t, t, \s4, ror #41
    eor     s, s, \s6
	add		\s7, \s7, t		// h = h+WK+Sigma1(e)
	eor     t, \s1, \s2  // y^z
	add		\s7, \s7, s		// h = h+WK+Sigma1(e)+Ch(e,f,g);
    ror     s, \s0, #28
    ld1.2d  {v16}, [K], #16

	add		\s3, \s3, \s7		// d += h;
	and		u, \s1,\s2   // y&z
    eor     s, s, \s0, ror #34
	and		t, t, \s0   // x&(y^z)

    

    eor     s, s, \s0, ror #39
	eor		t, t, u    // Maj(x,y,z)
	add		\s7, \s7, s		// h += Sigma0(a);
	add		\s7, \s7, t		// h = T1 + Sigma0(a) + Maj(a,b,c);
    ror     t, \s3, #14
    eor     s, \s4, \s5
    ldr     u, WK(1+\s8+\s9)       // t = WK

    eor     t, t, \s3, ror #18
    and     s, s, \s3

	add		\s6, \s6, u		// h = h+WK

    rev64.16b   \vec0, \vec0

    eor     t, t, \s3, ror #41
    eor     s, s, \s5
	add		\s6, \s6, t		// h = h+WK+Sigma1(e)
	eor     t, \s0, \s1  // y^z
	add		\s6, \s6, s		// h = h+WK+Sigma1(e)+Ch(e,f,g);
    ror     s, \s7, #28
    add.2d  v16, v16, \vec0
	add		\s2, \s2, \s6		// d += h;
	and		u, \s0,\s1   // y&z
    eor     s, s, \s7, ror #34
	and		t, t, \s7   // x&(y^z)
    eor     s, s, \s7, ror #39
	eor		t, t, u    // Maj(x,y,z)
	add		\s6, \s6, s		// h += Sigma0(a);
    str     q16, WK(\s9)
	add		\s6, \s6, t		// h = T1 + Sigma0(a) + Maj(a,b,c);

    .endm

	.macro	rounds_schedule_initial

    combined_initial_round_update2  $0, $1, $2, $3, $4, $5, $6, $7, $8, 0, W0
    combined_initial_round_update2  $6, $7, $0, $1, $2, $3, $4, $5, $8, 2, W1
    combined_initial_round_update2  $4, $5, $6, $7, $0, $1, $2, $3, $8, 4, W2
    combined_initial_round_update2  $2, $3, $4, $5, $6, $7, $0, $1, $8, 6, W3
    combined_initial_round_update2  $0, $1, $2, $3, $4, $5, $6, $7, $8, 8, W4
    combined_initial_round_update2  $6, $7, $0, $1, $2, $3, $4, $5, $8,10, W5
    combined_initial_round_update2  $4, $5, $6, $7, $0, $1, $2, $3, $8,12, W6
    combined_initial_round_update2  $2, $3, $4, $5, $6, $7, $0, $1, $8,14, W7
    
	.endm

    /*
        16 rounds of hash update
    */
	.macro	rounds_schedule_final
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8

	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
	.endm

.subsections_via_symbols
	.text
    .p2align  4
    .globl	_AccelerateCrypto_SHA512_compress
_AccelerateCrypto_SHA512_compress:
    BRANCH_TARGET_CALL

#ifdef __ILP32__
    uxtw    num_blocks, num_blocks        // in arm64_32 size_t is 32-bit, so we need to extend it
#endif


    adrp    K, _sha512_K@page
    cbnz    num_blocks, 1f                       // if number of blocks is nonzero, go on for sha256 transform operation
    ret     lr                          // otherwise, return
1:
    add     K, K, _sha512_K@pageoff 

#if BUILDKERNEL
    // v0-v7, v16-v23
    sub     x4, sp, #16*16
    sub     sp, sp, #16*16
    st1.4s  {v0, v1, v2, v3}, [x4], #64
    st1.4s  {v4, v5, v6, v7}, [x4], #64
    st1.4s  {v16, v17, v18, v19}, [x4], #64
    st1.4s  {v20, v21, v22, v23}, [x4], #64
#endif


	// allocate stack space for WK[0:15]
	sub		sp, sp, #stack_size
    ldr     q0, [data], #128
    ldr     q1, [data, #-112]
    ldr     q2, [data, #-96]

    ldr     q3, [data, #-80]
    rev64.16b   v0, v0
    ldr     q4, [data, #-64]
    rev64.16b   v1, v1
    ldr     q5, [data, #-48]
    rev64.16b   v2, v2
    ldr     q6, [data, #-32]
    rev64.16b   v3, v3
    ldr     q7, [data, #-16]
    rev64.16b   v4, v4
    ldr     q16, [K], #64
    rev64.16b   v5, v5
    ldr     q17, [K, #-48]
    rev64.16b   v6, v6
    ldr     q18, [K, #-32]
    rev64.16b   v7, v7
    ldr     q19, [K, #-16]


	// compute WK[0:15] and save in stack
    add.2d  v20, v16, v0
    ldr     q16, [K], #64
    add.2d  v21, v17, v1
    ldr     q17, [K, #-48]
    add.2d  v22, v18, v2
    ldr     q18, [K, #-32]
    add.2d  v23, v19, v3
    ldr     q19, [K, #-16]
    add.2d  v16, v16, v4
    str     q20, [sp]
    add.2d  v17, v17, v5
    str     q21, [sp, #16*1]
    add.2d  v18, v18, v6
    str     q22, [sp, #16*2]
    add.2d  v19, v19, v7
    str     q23, [sp, #16*3]
    str     q16, [sp, #16*4]
    str     q17, [sp, #16*5]
    str     q18, [sp, #16*6]
    str     q19, [sp, #16*7]

L_loop:

	// digests a-h = ctx->states;
    ldp     a, bb, [ctx]
    ldp     c, d, [ctx, #16]
    ldp     e, f, [ctx, #32]
    ldp     g, h, [ctx, #48]

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    mov     w15, #4
L_i_loop:
    rounds_schedule a, bb, c, d, e, f, g, h, 16
    subs    w15, w15, #1
    b.gt    L_i_loop

	// revert K to the beginning of K256[]
	sub		K, K, #640
	subs    num_blocks, num_blocks, #1				// num_blocks--

	b.eq	L_final_block				// if final block, wrap up final rounds

    rounds_schedule_initial a, bb, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
    ldp     s, t, [ctx]
    add     s, s, a
    add     t, t, bb
    stp     s, t, [ctx]
    ldp     s, t, [ctx, #16]
    add     s, s, c
    add     t, t, d
    stp     s, t, [ctx, #16]
    ldp     s, t, [ctx, #32]
    add     s, s, e
    add     t, t, f
    stp     s, t, [ctx, #32]
    ldp     s, t, [ctx, #48]
    add     s, s, g
    add     t, t, h
    stp     s, t, [ctx, #48]

	b		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
    rounds_schedule_final a, bb, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
    ldp     s, t, [ctx]
    add     s, s, a
    add     t, t, bb
    stp     s, t, [ctx]
    ldp     s, t, [ctx, #16]
    add     s, s, c
    add     t, t, d
    stp     s, t, [ctx, #16]
    ldp     s, t, [ctx, #32]
    add     s, s, e
    add     t, t, f
    stp     s, t, [ctx, #32]
    ldp     s, t, [ctx, #48]
    add     s, s, g
    add     t, t, h
    stp     s, t, [ctx, #48]

	// if kernel, restore used vector registers
#if BUILDKERNEL
    ld1.4s  {v0, v1, v2, v3}, [sp], #64
    ld1.4s  {v4, v5, v6, v7}, [sp], #64
    ld1.4s  {v16, v17, v18, v19}, [sp], #64
    ld1.4s  {v20, v21, v22, v23}, [sp], #64
#endif

	// free allocated stack memory
    add     sp, sp, #stack_size

	// return
	ret     lr

#endif      // __arm64__
