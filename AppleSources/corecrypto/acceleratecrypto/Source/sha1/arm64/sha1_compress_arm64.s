# Copyright (c) (2018-2020,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

/*

void SHA1( int HASH[], int MESSAGE[] )
{
	int A[81], B[81], C[81], D[81], E[81];
	int W[80];
	int i, FN;

	A[0] = HASH[0]; B[0] = HASH[1]; C[0] = HASH[2]; D[0] = HASH[3]; E[0] = HASH[4];

	for ( i=0; i<80; ++i ) {
		if ( i < 16 )
			W[i] = BIG_ENDIAN_LOAD( MESSAGE[i] );
		else
		 	W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 ); 

		FN = F( i, B[i], C[i], D[i] );
		A[i+1] = FN + E[i] + ROTATE_LEFT( A[i], 5 ) + W[i] + K(i);
		B[i+1] = A[i];
		C[i+1] = ROTATE_LEFT( B[i], 30 );
		D[i+1] = C[i];
		E[i+1] = D[i];
	}

	HASH[0] += A[80]; HASH[1] += B[80]; HASH[2] += C[80]; HASH[3] += D[80]; HASH[4] += E[80];
} 


	For i=0:15, W[i] is simply big-endian loading of MESSAGE[i]. 
	For i=16:79, W[i] is updated according to W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );

    The approach (by Dean Gaudet) can be used to vectorize the computation of W[i] for i=16:79,

    1. update 4 consequtive W[i] (stored in a single 16-byte register)
    W[i  ] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1
    W[i+1] = (W[i-2] ^ W[i-7] ^ W[i-13] ^ W[i-15]) rol 1
    W[i+2] = (W[i-1] ^ W[i-6] ^ W[i-12] ^ W[i-14]) rol 1
    W[i+3] = (   0   ^ W[i-5] ^ W[i-11] ^ W[i-13]) rol 1

    2. this additional calculation unfortunately requires many additional operations
    W[i+3] ^= W[i] rol 1

    3. once we have 4 W[i] values in a Q register, we can also add four K values with one instruction
    W[i:i+3] += {K,K,K,K}

    Let W0 = {W[i] W[i+1] W[i+2] W[i+3]} be the current W-vector to be computed, 
		W4 = {W[i-4] W[i-3] W[i-2] W[i-1]} be the previous vector, and so on

    The Dean Gaudet approach can be expressed as

    1. W0 = rotate_left(left_shift(W4,32) ^ W8 ^ left_shift(concatenate(W16,W12),64) ^ W16,1);
    2. W[i+3] ^= W[i] rol 1
    3. W0 += {K,K,K,K}

    For i>=32, the Intel online article suggests that (using a basic identity (X rol 1) rol 1 = X rol 2) 
	the update equation is equivalent to

    1. W0 = rotate_left(left_shift(concatenate(W8,W4),64) ^ W16 ^ W28 ^ W32, 2); 

    Note:
    1. In total, we need 8 16-byte registers or memory for W0,W4,...,W28. W0 and W32 can be the same register or memory.
    2. The registers are used in a circular buffering mode. For example, we start with W28,W24,...,W0 
		(with W0 indicating the most recent 16-byte) 
		i=0, W28,W24,...,W0
        i=4, W24,W20,...,W28
        i=8, W20,W16,...,W24
        .
        .
        and so forth.
    3. once W-vector is computed, W+K is then computed and saved in the stack memory, this will be used later when
		updating the digests A/B/C/D/E 

	the execution flow (for 1 single 64-byte block) looks like

	W_PRECALC_00_15		// big-endian loading of 64-bytes into 4 W-vectors, compute WK=W+K, save WK in the stack memory

	W_PRECALC_16_31		// for each vector, update digests, update W (Gaudet) and WK=W+K, save WK in the stack memory

	W_PRECALC_32_79		// for each vector, update digests, update W (Intel) and WK=W+K, save WK in the stack memory 

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block 
    into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into 4 Q registers
    pre_calculate and store WK = W+K(0:15) in 16-byte aligned stack memory

L_loop:

    load digests a-e from ctx->state;

    for (r=0;r<16;r+=4) {
        digests a-e update and permute round r:r+3
        update W([r:r+3]%16) (Gaudet) and WK([r:r+3]%16) for the next 4th iteration 
    }

    for (r=16;r<64;r+=4) {
        digests a-e update and permute round r:r+3
        update W([r:r+3]%16) (Intel) and WK([r:r+3]%16) for the next 4th iteration 
    }

    num_block--;
    if (num_block==0)   jmp L_last_block;

    for (r=64;r<80;r+=4) {
        digests a-e update and permute round r:r+3
        load W([r:r+3]%16) (big-endian per 4 bytes) into 4 Q registers
        pre_calculate and store W+K([r:r+3]%16) in stack
    }

    ctx->states += digests a-e;

    jmp L_loop;

L_last_block:

    for (r=64;r<80;r+=4) {
        digests a-e update and permute round r:r+3
    }

    ctx->states += digests a-e;


	----------------------------------------------------------------------------------------------------------
	
*/

#if defined(__arm64__) && defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)

#include "arm64_isa_compatibility.h"
#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols
	.text

	.p2align	4

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

K_XMM_AR:
    .long	K1
	.long	K1
	.long	K1
	.long	K1
    .long	K2
	.long	K2
	.long	K2
	.long	K2
    .long	K3
	.long	K3
	.long	K3
	.long	K3
    .long	K4
	.long	K4
	.long	K4
	.long	K4

	.p2align	4

    .globl _AccelerateCrypto_SHA1_compress
_AccelerateCrypto_SHA1_compress:


	#define hashes		x0
	#define	numblocks	x1
	#define	data		x2
	#define	ktable		x3

	BRANCH_TARGET_CALL

#ifdef __ILP32__
    uxtw    numblocks, numblocks        // in arm64_32 size_t is 32-bit, so we need to extend it
#endif

	// early exit if input number of blocks is zero

    adrp    ktable, K_XMM_AR@page
	cbnz	numblocks, 1f
	ret		lr
1:
    add     ktable, ktable, K_XMM_AR@pageoff	// K table

#if BUILDKERNEL

	// saved vector registers that will be used in the computation v0-v7, v16-v21

	sub		x4, sp, #17*16
	sub		sp, sp, #17*16

	st1.4s	{v0,v1,v2,v3}, [x4], #64
	st1.4s	{v4,v5,v6,v7}, [x4], #64
	st1.4s	{v16,v17,v18,v19}, [x4], #64
	st1.4s	{v20,v21,v22,v23}, [x4], #64
	st1.4s	{v24}, [x4], #16

#endif

	ld1.4s	{v0,v1,v2,v3}, [data], #64			// w0,w1,w2,w3 need to bswap into big-endian
	ld1.4s	{v21,v22,v23,v24}, [ktable], #64	// k1,k2,k3,k4
	ldr		q16, [hashes], #16
	ldr		s17, [hashes], #-16

    rev32.16b	v0, v0					// byte swap of 1st 4 ints
    rev32.16b	v1, v1					// byte swap of 2nd 4 ints
    rev32.16b	v2, v2					// byte swap of 3rd 4 ints
    rev32.16b	v3, v3					// byte swap of 4th 4 ints

	mov.16b		v18, v16
    add.4s		v4, v0, v21				// 1st 4 input + K256
    add.4s		v5, v1, v21				// 2nd 4 input + K256
	mov.16b		v19, v17
    add.4s		v6, v2, v21				// 3rd 4 input + K256
    add.4s		v7, v3, v21				// 4th 4 input + K256


	.macro	sha1c_round
	SHA1SU0	$0, $1, $2
	mov.16b		v20, v18
	SHA1C	18, 19, $4
	SHA1H	19, 20
	SHA1SU1	$0, $3
	add.4s		$6, $5, $7
	.endm

	.macro	sha1p_round
	SHA1SU0	$0, $1, $2
	mov.16b		v20, v18
	SHA1P	18, 19, $4
	SHA1H	19, 20
	SHA1SU1	$0, $3
	add.4s		$6, $5, $7
	.endm

	.macro	sha1m_round
	SHA1SU0	$0, $1, $2
	mov.16b		v20, v18
	SHA1M	18, 19, $4
	SHA1H	19, 20
	SHA1SU1	$0, $3
	add.4s		$6, $5, $7
	.endm

	// 4 vector hashes update and load next vector rounds
	.macro	sha1p_hash_load_round
    rev32.16b	$1, $1
	mov.16b		v20, v18
	SHA1P	18, 19, $0
	SHA1H	19, 20
    add.4s		$2, $1, $3
	.endm

	.macro	sha1p_hash_round
	mov.16b		v20, v18
	SHA1P	18, 19, $0
	SHA1H	19, 20
	.endm

	sha1c_round			0, 1, 2, 3, 4, v0, v4, v21
	sha1c_round			1, 2, 3, 0, 5, v1, v5, v22
	sha1c_round			2, 3, 0, 1, 6, v2, v6, v22
	sha1c_round			3, 0, 1, 2, 7, v3, v7, v22

	sha1c_round			0, 1, 2, 3, 4, v0, v4, v22
	sha1p_round			1, 2, 3, 0, 5, v1, v5, v22
	sha1p_round			2, 3, 0, 1, 6, v2, v6, v23
	sha1p_round			3, 0, 1, 2, 7, v3, v7, v23

	sha1p_round			0, 1, 2, 3, 4, v0, v4, v23
	sha1p_round			1, 2, 3, 0, 5, v1, v5, v23
	sha1m_round			2, 3, 0, 1, 6, v2, v6, v23
	sha1m_round			3, 0, 1, 2, 7, v3, v7, v24

	sha1m_round			0, 1, 2, 3, 4, v0, v4, v24
	sha1m_round			1, 2, 3, 0, 5, v1, v5, v24
	sha1m_round			2, 3, 0, 1, 6, v2, v6, v24
	sha1p_round			3, 0, 1, 2, 7, v3, v7, v24

	subs 		numblocks, numblocks, #1	// pre-decrement num_blocks by 1
	b.le		L_wrapup


L_loop:

	ld1.4s	{v0,v1,v2,v3}, [data], #64			// w0,w1,w2,w3 need to bswap into big-endian

	sha1p_hash_load_round	4, v0, v4, v21
	sha1p_hash_load_round	5, v1, v5, v21
	sha1p_hash_load_round	6, v2, v6, v21
	sha1p_hash_load_round	7, v3, v7, v21

	add.4s		v18, v16, v18
	add.4s		v19, v17, v19
	mov.16b		v16, v18
	mov.16b		v17, v19

	sha1c_round			0, 1, 2, 3, 4, v0, v4, v21
	sha1c_round			1, 2, 3, 0, 5, v1, v5, v22
	sha1c_round			2, 3, 0, 1, 6, v2, v6, v22
	sha1c_round			3, 0, 1, 2, 7, v3, v7, v22

	sha1c_round			0, 1, 2, 3, 4, v0, v4, v22
	sha1p_round			1, 2, 3, 0, 5, v1, v5, v22
	sha1p_round			2, 3, 0, 1, 6, v2, v6, v23
	sha1p_round			3, 0, 1, 2, 7, v3, v7, v23

	sha1p_round			0, 1, 2, 3, 4, v0, v4, v23
	sha1p_round			1, 2, 3, 0, 5, v1, v5, v23
	sha1m_round			2, 3, 0, 1, 6, v2, v6, v23
	sha1m_round			3, 0, 1, 2, 7, v3, v7, v24

	sha1m_round			0, 1, 2, 3, 4, v0, v4, v24
	sha1m_round			1, 2, 3, 0, 5, v1, v5, v24
	sha1m_round			2, 3, 0, 1, 6, v2, v6, v24
	sha1p_round			3, 0, 1, 2, 7, v3, v7, v24

	subs 		numblocks, numblocks, #1	// pre-decrement num_blocks by 1
	b.gt		L_loop

L_wrapup:

	sha1p_hash_round	4
	sha1p_hash_round	5
	sha1p_hash_round	6
	sha1p_hash_round	7

	add.4s		v16, v16, v18
	add.4s		v17, v17, v19
	str			q16,[hashes], #16
	str			s17,[hashes]



#if BUILDKERNEL

	// restore vector registers that have be used clobbered in the computation v0-v7, v16-v21

	ld1.4s	{v0,v1,v2,v3}, [sp], #64
	ld1.4s	{v4,v5,v6,v7}, [sp], #64
	ld1.4s	{v16,v17,v18,v19}, [sp], #64
	ld1.4s	{v20,v21,v22,v23}, [sp], #64
	ld1.4s	{v24}, [sp], #16

#endif

	ret			lr

#endif // define(__arm64__)

