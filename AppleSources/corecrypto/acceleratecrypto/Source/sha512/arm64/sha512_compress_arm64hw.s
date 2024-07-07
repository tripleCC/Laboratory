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

#if defined(__arm64__) && defined(__ARM_FEATURE_SHA512)

#include "ccarm_pac_bti_macros.h"

    .macro  swap_hilo
    ext.16b $0, $0, $0, #8
    .endm

    .macro  ext16b
    ext.16b $0, $1, $2, #8
    .endm


	.text
    .align  4
    .globl  _AccelerateCrypto_SHA512_compress_hwassist

_AccelerateCrypto_SHA512_compress_hwassist:

    BRANCH_TARGET_CALL


	#define	hashes		x0
	#define	numblocks	x1
	#define	data		x2
	#define	ktable		x3

#ifdef __ILP32__
    uxtw    numblocks, numblocks        // in arm64_32 size_t is 32-bit, so we need to extend it
#endif


	adrp	ktable, _ccsha512_K@page
	cbnz	numblocks, 1f						
	ret		lr							// otherwise, return
1:
	add		ktable, ktable, _ccsha512_K@pageoff

#if BUILDKERNEL
	sub		x4, sp, #28*16
	sub		sp, sp, #28*16
	st1.4s	{v0, v1, v2, v3}, [x4], #64
	st1.4s	{v4, v5, v6, v7}, [x4], #64
	st1.4s	{v16, v17, v18, v19}, [x4], #64
	st1.4s	{v20, v21, v22, v23}, [x4], #64
	st1.4s	{v24, v25, v26, v27}, [x4], #64
	st1.4s	{v28, v29, v30, v31}, [x4], #64
#else
	sub		x4, sp, #4*16
	sub		sp, sp, #4*16
#endif
	st1.4s	{v8, v9, v10, v11}, [x4], #64

	ld1.2d	{v8,v9,v10,v11}, [hashes]				// (a,b) (c,d) (e,f) (g,h)

L_loop:

    mov.16b     v24, v8
    ldr         q0, [data, #0*16]
    mov.16b     v25, v9
    ldr         q1, [data, #1*16]
    mov.16b     v26, v10
    ldr         q2, [data, #2*16]
    mov.16b     v27, v11
    ldr         q3, [data, #3*16]

    rev64.16b   v0, v0
    ldr         q4, [data, #4*16]
    rev64.16b   v1, v1
    ldr         q5, [data, #5*16]
    rev64.16b   v2, v2
    ldr         q6, [data, #6*16]
    rev64.16b   v3, v3
    ldr         q7, [data, #7*16]
    rev64.16b   v4, v4
    ldr         q16, [ktable, #0*16]
    rev64.16b   v5, v5
    ldr         q17, [ktable, #1*16]
    rev64.16b   v6, v6
    ldr         q18, [ktable, #2*16]
    rev64.16b   v7, v7
    ldr         q19, [ktable, #3*16]

    add.2d		v16, v16, v0
    ldr         q20, [ktable, #4*16]
    add.2d		v17, v17, v1
    ldr         q21, [ktable, #5*16]
    add.2d		v18, v18, v2
    ldr         q22, [ktable, #6*16]
    add.2d		v19, v19, v3
    ldr         q23, [ktable, #7*16]
    add.2d		v20, v20, v4
    add         data, data, #8*16
    add.2d		v21, v21, v5
    add         ktable, ktable, #8*16
    add.2d		v22, v22, v6
    add.2d		v23, v23, v7

    .macro  sha512_round S0, S1, S2, S3, WK, w0, w1, w4, w5, w7, i
    ext16b  \WK, \WK, \WK
    ext16b  v29, \S2, \S3
    ext16b  v28, \S1, \S2
    add.2d  \S3, \S3, \WK
                                ext16b  v31, \w4, \w5
                                ldr         q30, [ktable, #\i*16]
    sha512h.2d \S3, v29, v28 
                                sha512su0.2d   \w0, \w1 
    mov.16b v28, \S3
    sha512h2.2d \S3, \S1, \S0
                                sha512su1.2d   \w0, \w7, v31
    add.2d  \S1, \S1, v28
                                add.2d      \WK, \w0, v30 
    .endm

    .macro sha512_8_rounds
    sha512_round    v24, v25, v26, v27, v16, v0, v1, v4, v5, v7, 0
    sha512_round    v27, v24, v25, v26, v17, v1, v2, v5, v6, v0, 1
    sha512_round    v26, v27, v24, v25, v18, v2, v3, v6, v7, v1, 2
    sha512_round    v25, v26, v27, v24, v19, v3, v4, v7, v0, v2, 3
    sha512_round    v24, v25, v26, v27, v20, v4, v5, v0, v1, v3, 4
    sha512_round    v27, v24, v25, v26, v21, v5, v6, v1, v2, v4, 5
    sha512_round    v26, v27, v24, v25, v22, v6, v7, v2, v3, v5, 6
    sha512_round    v25, v26, v27, v24, v23, v7, v0, v3, v4, v6, 7
    add     ktable, ktable, #16*8
    .endm

    .macro  sha512_round_final S0, S1, S2, S3, WK, w0, w1, w4, w5, w7
                                ext16b      \WK, \WK, \WK
    ext16b  v29, \S2, \S3
    ext16b  v28, \S1, \S2
    add.2d  v30, \S3, \WK
    sha512h.2d v30, v29, v28 
    mov.16b \S3, v30
    sha512h2.2d \S3, \S1, \S0
    add.2d  \S1, \S1, v30
    .endm

    .macro  sha512_8_rounds_final
    sha512_round_final    v24, v25, v26, v27, v16
    sha512_round_final    v27, v24, v25, v26, v17
    sha512_round_final    v26, v27, v24, v25, v18
    sha512_round_final    v25, v26, v27, v24, v19
    sha512_round_final    v24, v25, v26, v27, v20
    sha512_round_final    v27, v24, v25, v26, v21
    sha512_round_final    v26, v27, v24, v25, v22
    sha512_round_final    v25, v26, v27, v24, v23
    .endm

    sha512_8_rounds
    sha512_8_rounds
    sha512_8_rounds
    sha512_8_rounds
    sha512_8_rounds_final

    add.2d  v8, v8, v24
    add.2d  v9, v9, v25
    add.2d  v10, v10, v26
    add.2d  v11, v11, v27

	subs 		numblocks, numblocks, #1	// pre-decrement num_blocks by 1
	sub			ktable, ktable, #640
	b.gt		L_loop

    st1.2d  {v8,v9,v10,v11}, [hashes]

#if BUILDKERNEL
	ld1.4s	{v0, v1, v2, v3}, [sp], #64
	ld1.4s	{v4, v5, v6, v7}, [sp], #64
	ld1.4s	{v16, v17, v18, v19}, [sp], #64
	ld1.4s	{v20, v21, v22, v23}, [sp], #64
	ld1.4s	{v24, v25, v26, v27}, [sp], #64
	ld1.4s	{v28, v29, v30, v31}, [sp], #64
#endif
	ld1.4s	{v8, v9, v10, v11}, [sp], #64

	ret		lr

#endif

