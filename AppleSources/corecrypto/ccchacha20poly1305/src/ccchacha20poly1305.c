/* Copyright (c) (2016-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/cc.h>
#include "cc_macros.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

// COMPILER_CLANG

#if( defined( __clang__ ) && __clang__ )
	#define COMPILER_CLANG			( ( __clang_major__ * 10000 ) + ( __clang_minor__ * 100 ) + __clang_patchlevel__ )
#else
	#define COMPILER_CLANG			0
#endif

// TARGET_HAS_NEON

#if( defined( __ARM_NEON__ ) && __ARM_NEON__)
	#define TARGET_HAS_NEON		1
#else
	#define TARGET_HAS_NEON		0
#endif

// TARGET_HAS_SSE

#if( defined( __SSE4_2__ ) && __SSE4_2__ && !CC_KERNEL)
	#define TARGET_HAS_SSE		42
#elif( defined( __SSE4_1__ ) && __SSE4_1__ && !CC_KERNEL)
	#define TARGET_HAS_SSE		41
#elif( defined( __SSE3__ ) && __SSE3__ && !CC_KERNEL)
	#define TARGET_HAS_SSE		30
#elif( defined( __SSE2__ ) && __SSE2__ && !CC_KERNEL)
	#define TARGET_HAS_SSE		20
#elif( defined( __SSE__ ) && __SSE__ && !CC_KERNEL)
	#define TARGET_HAS_SSE		10
#else
	#define TARGET_HAS_SSE		0
#endif
#define SSE_VERSION( MAJOR, MINOR )		( ( (MAJOR) * 10 ) + (MINOR) )

// TARGET_HAS_SSSE (Supplemental SSE)

#if( defined( __SSSE3__ ) && __SSSE3__ )
	#define TARGET_HAS_SSSE		3
#else
	#define TARGET_HAS_SSSE		0
#endif
#define SSSE_VERSION( X )		( (X) )

// uint32x4_t

#if( defined( __SSE2__ ) && __SSE2__ )
typedef uint32_t	uint32x4_t __attribute__( ( vector_size( 16 ) ) );
#endif

//===========================================================================================================================
//	ccchacha20
//
//	Based on DJB's public domain chacha20 code: <http://cr.yp.to/chacha.html>.
//===========================================================================================================================

#if( TARGET_HAS_NEON || ( TARGET_HAS_SSE >= SSE_VERSION( 2, 0 ) ) )
	#define CHACHA20_SIMD		1
#else
	#define CHACHA20_SIMD		0
#endif

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32-(n))))

#define CHACHA20_QUARTERROUND( a, b, c, d ) \
	a += b; d = ROTL32( d ^ a, 16 ); \
	c += d; b = ROTL32( b ^ c, 12 ); \
	a += b; d = ROTL32( d ^ a,  8 ); \
	c += d; b = ROTL32( b ^ c,  7 );

// "expand 32-byte k", as 4 little endian 32-bit unsigned integers.
#if( CHACHA20_SIMD )
__attribute__( ( aligned( 16 ) ) )
#endif
static const uint32_t		kChaCha20Constants[ 4 ] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

static void	_ccchacha20_xor(ccchacha20_ctx *ctx, size_t nbytes, uint8_t *out, const uint8_t *in);

int ccchacha20(const uint8_t *key, const uint8_t *nonce, uint32_t counter, size_t nbytes, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

	ccchacha20_ctx		ctx;

	ccchacha20_init(&ctx, key);
    ccchacha20_setnonce(&ctx, nonce);
    ccchacha20_setcounter(&ctx, counter);
	_ccchacha20_xor(&ctx, nbytes, out, in);
    ccchacha20_final(&ctx);

    return 0;
}

int	ccchacha20_init(ccchacha20_ctx *ctx, const uint8_t *key)
{
    CC_ENSURE_DIT_ENABLED

    ctx->state[  0 ] = kChaCha20Constants[ 0 ];
    ctx->state[  1 ] = kChaCha20Constants[ 1 ];
    ctx->state[  2 ] = kChaCha20Constants[ 2 ];
    ctx->state[  3 ] = kChaCha20Constants[ 3 ];

    ctx->state[  4 ] = cc_load32_le( key +  0 );
    ctx->state[  5 ] = cc_load32_le( key +  4 );
    ctx->state[  6 ] = cc_load32_le( key +  8 );
    ctx->state[  7 ] = cc_load32_le( key + 12 );

    ctx->state[  8 ] = cc_load32_le( key + 16 );
    ctx->state[  9 ] = cc_load32_le( key + 20 );
    ctx->state[ 10 ] = cc_load32_le( key + 24 );
    ctx->state[ 11 ] = cc_load32_le( key + 28 );

    ccchacha20_reset(ctx);

    return 0;
}

int	ccchacha20_reset(ccchacha20_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    ctx->state[ 12 ] = 0;

    ctx->leftover = 0;

    return 0;
}

int	ccchacha20_setnonce(ccchacha20_ctx *ctx, const uint8_t *nonce)
{
    CC_ENSURE_DIT_ENABLED

    ctx->state[ 13 ] = cc_load32_le( nonce + 0 );
    ctx->state[ 14 ] = cc_load32_le( nonce + 4 );
    ctx->state[ 15 ] = cc_load32_le( nonce + 8 );
    return 0;
}

int	ccchacha20_setcounter(ccchacha20_ctx *ctx, uint32_t counter)
{
    CC_ENSURE_DIT_ENABLED

    ctx->state[ 12 ] = counter;
    return 0;
}

static const uint8_t	kZero64[ 64 ] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

int	ccchacha20_update( ccchacha20_ctx *ctx, size_t nbytes, const void *in, void *out )
{
    CC_ENSURE_DIT_ENABLED

	const uint8_t *		in_bytes = (const uint8_t *) in;
	uint8_t *			out_bytes = (uint8_t *) out;
	size_t				j, n;

	j = ctx->leftover;
	if( j )
	{
		n = CCCHACHA20_BLOCK_NBYTES - j;
		if( n > nbytes ) n = nbytes;
        cc_xor(n, out_bytes, in_bytes, ctx->buffer + ctx->leftover);
        in_bytes += n;
        nbytes -= n;
        out_bytes += n;
        ctx->leftover += n;
        ctx->leftover &= (CCCHACHA20_BLOCK_NBITS - 1);
	}
	if( nbytes >= CCCHACHA20_BLOCK_NBYTES )
	{
		n = nbytes & ~( (size_t)( CCCHACHA20_BLOCK_NBYTES - 1 ) );
		_ccchacha20_xor(ctx, n, out_bytes, in_bytes);
		in_bytes += n;
		out_bytes += n;
		nbytes &= (CCCHACHA20_BLOCK_NBYTES - 1);
	}
	if( nbytes )
	{
        _ccchacha20_xor(ctx, CCCHACHA20_BLOCK_NBYTES, ctx->buffer, kZero64);
        cc_xor(nbytes, out_bytes, in_bytes, ctx->buffer);
		ctx->leftover = nbytes;
	}

	return 0;
}

int	ccchacha20_final(ccchacha20_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

	cc_clear(sizeof (*ctx), ctx);
	return 0;
}

#if( !CHACHA20_SIMD )

static void	_ccchacha20_xor(ccchacha20_ctx *ctx, size_t nbytes, uint8_t *out, const uint8_t *in)
{
	uint32_t		x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
	uint32_t		j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
	uint8_t *		ctarget = out;
	uint8_t			tmp[CCCHACHA20_BLOCK_NBYTES];
	size_t			i;

	j0 = ctx->state[ 0 ];
	j1 = ctx->state[ 1 ];
	j2 = ctx->state[ 2 ];
	j3 = ctx->state[ 3 ];
	j4 = ctx->state[ 4 ];
	j5 = ctx->state[ 5 ];
	j6 = ctx->state[ 6 ];
	j7 = ctx->state[ 7 ];
	j8 = ctx->state[ 8 ];
	j9 = ctx->state[ 9 ];
	j10 = ctx->state[ 10 ];
	j11 = ctx->state[ 11 ];
	j12 = ctx->state[ 12 ];
	j13 = ctx->state[ 13 ];
	j14 = ctx->state[ 14 ];
	j15 = ctx->state[ 15 ];

	for( ;; )
	{
		if( nbytes < CCCHACHA20_BLOCK_NBYTES )
		{
			for( i = 0; i < nbytes; ++i ) tmp[ i ] = in[ i ];
			in	= tmp;
			ctarget	= out;
			out	= tmp;
		}
		 x0 = j0;
		 x1 = j1;
		 x2 = j2;
		 x3 = j3;
		 x4 = j4;
		 x5 = j5;
		 x6 = j6;
		 x7 = j7;
		 x8 = j8;
		 x9 = j9;
		x10 = j10;
		x11 = j11;
		x12 = j12;
		x13 = j13;
		x14 = j14;
		x15 = j15;
		for( i = 20; i > 0; i -= 2 )
		{
			CHACHA20_QUARTERROUND( x0, x4,  x8, x12 )
			CHACHA20_QUARTERROUND( x1, x5,  x9, x13 )
			CHACHA20_QUARTERROUND( x2, x6, x10, x14 )
			CHACHA20_QUARTERROUND( x3, x7, x11, x15 )
			CHACHA20_QUARTERROUND( x0, x5, x10, x15 )
			CHACHA20_QUARTERROUND( x1, x6, x11, x12 )
			CHACHA20_QUARTERROUND( x2, x7,  x8, x13 )
			CHACHA20_QUARTERROUND( x3, x4,  x9, x14 )
		}
		 x0 += j0;
		 x1 += j1;
		 x2 += j2;
		 x3 += j3;
		 x4 += j4;
		 x5 += j5;
		 x6 += j6;
		 x7 += j7;
		 x8 += j8;
		 x9 += j9;
		x10 += j10;
		x11 += j11;
		x12 += j12;
		x13 += j13;
		x14 += j14;
		x15 += j15;

		 x0 ^= cc_load32_le( in +  0 );
		 x1 ^= cc_load32_le( in +  4 );
		 x2 ^= cc_load32_le( in +  8 );
		 x3 ^= cc_load32_le( in + 12 );
		 x4 ^= cc_load32_le( in + 16 );
		 x5 ^= cc_load32_le( in + 20 );
		 x6 ^= cc_load32_le( in + 24 );
		 x7 ^= cc_load32_le( in + 28 );
		 x8 ^= cc_load32_le( in + 32 );
		 x9 ^= cc_load32_le( in + 36 );
		x10 ^= cc_load32_le( in + 40 );
		x11 ^= cc_load32_le( in + 44 );
		x12 ^= cc_load32_le( in + 48 );
		x13 ^= cc_load32_le( in + 52 );
		x14 ^= cc_load32_le( in + 56 );
		x15 ^= cc_load32_le( in + 60 );

        j12 += 1;   // Stopping at 2^38 bytes per nonce is the caller's responsibility.

		cc_store32_le( x0, out +  0 );
		cc_store32_le( x1, out +  4 );
		cc_store32_le( x2, out +  8 );
		cc_store32_le( x3, out + 12 );
		cc_store32_le( x4, out + 16 );
		cc_store32_le( x5, out + 20 );
		cc_store32_le( x6, out + 24 );
		cc_store32_le( x7, out + 28 );
		cc_store32_le( x8, out + 32 );
		cc_store32_le( x9, out + 36 );
		cc_store32_le( x10, out + 40 );
		cc_store32_le( x11, out + 44 );
		cc_store32_le( x12, out + 48 );
		cc_store32_le( x13, out + 52 );
		cc_store32_le( x14, out + 56 );
		cc_store32_le( x15, out + 60 );

		if( nbytes <= CCCHACHA20_BLOCK_NBYTES )
		{
			if( nbytes < CCCHACHA20_BLOCK_NBYTES )
			{
				for( i = 0; i < nbytes; ++i ) ctarget[ i ] = out[ i ];
			}
			ctx->state[ 12 ] = j12;
			return;
		}
		nbytes -= CCCHACHA20_BLOCK_NBYTES;
		out += CCCHACHA20_BLOCK_NBYTES;
		in += CCCHACHA20_BLOCK_NBYTES;
	}
}
#endif // !CHACHA20_SIMD

#if( CHACHA20_SIMD )
//===========================================================================================================================
//	_ccchacha20_xor
//
//	Based on public domain implementation by Ted Krovetz (ted@krovetz.net).
//===========================================================================================================================

#ifndef CHACHA_RNDS
#define CHACHA_RNDS 20	/* 8 (high speed), 20 (conservative), 12 (middle) */
#endif

// This implementation is designed for Neon and SSE machines. The following specify how to do certain vector operations
// efficiently on each architecture, using intrinsics. This implementation supports parallel processing of multiple blocks,
// including potentially using general-purpose registers.

#if( TARGET_HAS_NEON )
	#include <arm_neon.h>
	#define GPR_TOO			1
	#define VBPI			2
	#define ONE				(uint32x4_t)vsetq_lane_u32(1,vdupq_n_u32(0),0)
	#define LOAD(m)			(uint32x4_t)vld1q_u8((const uint8_t *)(m))
	#define STORE(m,r)		vst1q_u8((uint8_t *)(m),(uint8x16_t)(r))
	#define ROTV1(x)		(uint32x4_t)vextq_u32((uint32x4_t)x,(uint32x4_t)x,1)
	#define ROTV2(x)		(uint32x4_t)vextq_u32((uint32x4_t)x,(uint32x4_t)x,2)
	#define ROTV3(x)		(uint32x4_t)vextq_u32((uint32x4_t)x,(uint32x4_t)x,3)
	#define ROTW16(x)		(uint32x4_t)vrev32q_u16((uint16x8_t)x)
	#if COMPILER_CLANG
		#define ROTW7(x)	(x << ((uint32x4_t){ 7, 7, 7, 7})) ^ (x >> ((uint32x4_t){25,25,25,25}))
		#define ROTW8(x)	(x << ((uint32x4_t){ 8, 8, 8, 8})) ^ (x >> ((uint32x4_t){24,24,24,24}))
		#define ROTW12(x)	(x << ((uint32x4_t){12,12,12,12})) ^ (x >> ((uint32x4_t){20,20,20,20}))
	#else
		#define ROTW7(x)	(uint32x4_t)vsriq_n_u32(vshlq_n_u32((uint32x4_t)x,7),(uint32x4_t)x,25)
		#define ROTW8(x)	(uint32x4_t)vsriq_n_u32(vshlq_n_u32((uint32x4_t)x,8),(uint32x4_t)x,24)
		#define ROTW12(x)	(uint32x4_t)vsriq_n_u32(vshlq_n_u32((uint32x4_t)x,12),(uint32x4_t)x,20)
	#endif
#elif( TARGET_HAS_SSE >= SSE_VERSION( 2, 0 ) )
	#include <emmintrin.h>
	#define GPR_TOO			0
	#if COMPILER_CLANG
		#define VBPI		4
	#else
		#define VBPI		3
	#endif
	#define ONE				(uint32x4_t)_mm_set_epi32(0,0,0,1)
	#define LOAD(m)			(uint32x4_t)_mm_loadu_si128((const __m128i*)(m))
	#define STORE(m,r)		_mm_storeu_si128((__m128i*)(m), (__m128i) (r))
	#define ROTV1(x)		(uint32x4_t)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(0,3,2,1))
	#define ROTV2(x)		(uint32x4_t)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(1,0,3,2))
	#define ROTV3(x)		(uint32x4_t)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(2,1,0,3))
	#define ROTW7(x)		(uint32x4_t)(_mm_slli_epi32((__m128i)x, 7) ^ _mm_srli_epi32((__m128i)x,25))
	#define ROTW12(x)		(uint32x4_t)(_mm_slli_epi32((__m128i)x,12) ^ _mm_srli_epi32((__m128i)x,20))
	#if( TARGET_HAS_SSSE >= SSSE_VERSION( 3 ) )
		#include <tmmintrin.h>
		#define ROTW8(x)	(uint32x4_t)_mm_shuffle_epi8((__m128i)x,_mm_set_epi8(14,13,12,15,10,9,8,11,6,5,4,7,2,1,0,3))
		#define ROTW16(x)	(uint32x4_t)_mm_shuffle_epi8((__m128i)x,_mm_set_epi8(13,12,15,14,9,8,11,10,5,4,7,6,1,0,3,2))
	#else
		#define ROTW8(x)	(uint32x4_t)(_mm_slli_epi32((__m128i)x, 8) ^ _mm_srli_epi32((__m128i)x,24))
		#define ROTW16(x)	(uint32x4_t)(_mm_slli_epi32((__m128i)x,16) ^ _mm_srli_epi32((__m128i)x,16))
	#endif
#else
	#error "SIMD implementation not supported on this platform"
#endif

#ifndef REVV_BE
#define REVV_BE(x)	(x)
#endif

#ifndef REVW_BE
#define REVW_BE(x)	(x)
#endif

#define BPI			(VBPI + GPR_TOO) // Blocks computed per loop iteration.

#define DQROUND_VECTORS(a,b,c,d) \
	a += b; d ^= a; d = ROTW16(d); \
	c += d; b ^= c; b = ROTW12(b); \
	a += b; d ^= a; d = ROTW8(d); \
	c += d; b ^= c; b = ROTW7(b); \
	b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d); \
	a += b; d ^= a; d = ROTW16(d); \
	c += d; b ^= c; b = ROTW12(b); \
	a += b; d ^= a; d = ROTW8(d); \
	c += d; b ^= c; b = ROTW7(b); \
	b = ROTV3(b); c = ROTV2(c); d = ROTV1(d);

#define QROUND_WORDS(a,b,c,d) \
	a = a+b; d ^= a; d = d<<16 | d>>16; \
	c = c+d; b ^= c; b = b<<12 | b>>20; \
	a = a+b; d ^= a; d = d<< 8 | d>>24; \
	c = c+d; b ^= c; b = b<< 7 | b>>25;

#define WRITE_XOR(in, op, d, v0, v1, v2, v3) \
	STORE(op + d + 0, LOAD(in + d + 0) ^ REVV_BE(v0)); \
	STORE(op + d + 4, LOAD(in + d + 4) ^ REVV_BE(v1)); \
	STORE(op + d + 8, LOAD(in + d + 8) ^ REVV_BE(v2)); \
	STORE(op + d +12, LOAD(in + d +12) ^ REVV_BE(v3));

static void	_ccchacha20_xor(ccchacha20_ctx *ctx, size_t nbytes, uint8_t *out, const uint8_t *in)
{
	size_t iters, i;
    unsigned *op=(unsigned *)out;
    const unsigned *ip=(const unsigned *)in, *kp;
#if GPR_TOO
	const unsigned *np = (const unsigned*) (const unsigned char *) &ctx->state[13];
#endif
	uint32x4_t s0, s1, s2, s3;
	kp = &ctx->state[4];
	s0 = LOAD(kChaCha20Constants);
	s1 = LOAD(&((const uint32x4_t*)kp)[0]);
	s2 = LOAD(&((const uint32x4_t*)kp)[1]);
	s3 = LOAD(&ctx->state[12]);

	for (iters = 0; iters < nbytes/(BPI*64); iters++) {
#if GPR_TOO
	register unsigned x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
#endif
#if VBPI > 2
	uint32x4_t v8,v9,v10,v11;
#endif
#if VBPI > 3
	uint32x4_t v12,v13,v14,v15;
#endif

	uint32x4_t v0,v1,v2,v3,v4,v5,v6,v7;
	v4 = v0 = s0; v5 = v1 = s1; v6 = v2 = s2; v3 = s3;
	v7 = v3 + ONE;
#if VBPI > 2
	v8 = v4; v9 = v5; v10 = v6;
	v11 =  v7 + ONE;
#endif
#if VBPI > 3
	v12 = v8; v13 = v9; v14 = v10;
	v15 = v11 + ONE;
#endif
#if GPR_TOO
	x0 = kChaCha20Constants[0]; x1 = kChaCha20Constants[1];
	x2 = kChaCha20Constants[2]; x3 = kChaCha20Constants[3];
	x4 = kp[0]; x5 = kp[1]; x6  = kp[2]; x7  = kp[3];
	x8 = kp[4]; x9 = kp[5]; x10 = kp[6]; x11 = kp[7];
	x12 = (ctx->state[12])+((unsigned)(BPI*iters+(BPI-1))); x13 = np[0]; x14 = np[1]; x15 = np[2];
#endif
	for (i = CHACHA_RNDS/2; i; i--) {
		DQROUND_VECTORS(v0,v1,v2,v3)
		DQROUND_VECTORS(v4,v5,v6,v7)
#if VBPI > 2
		DQROUND_VECTORS(v8,v9,v10,v11)
#endif
#if VBPI > 3
		DQROUND_VECTORS(v12,v13,v14,v15)
#endif
#if GPR_TOO
		QROUND_WORDS( x0, x4, x8,x12)
		QROUND_WORDS( x1, x5, x9,x13)
		QROUND_WORDS( x2, x6,x10,x14)
		QROUND_WORDS( x3, x7,x11,x15)
		QROUND_WORDS( x0, x5,x10,x15)
		QROUND_WORDS( x1, x6,x11,x12)
		QROUND_WORDS( x2, x7, x8,x13)
		QROUND_WORDS( x3, x4, x9,x14)
#endif
	}

	WRITE_XOR(ip, op, 0, v0+s0, v1+s1, v2+s2, v3+s3)
	s3 += ONE;
	WRITE_XOR(ip, op, 16, v4+s0, v5+s1, v6+s2, v7+s3)
	s3 += ONE;
#if VBPI > 2
	WRITE_XOR(ip, op, 32, v8+s0, v9+s1, v10+s2, v11+s3)
	s3 += ONE;
#endif
#if VBPI > 3
	WRITE_XOR(ip, op, 48, v12+s0, v13+s1, v14+s2, v15+s3)
	s3 += ONE;
#endif
	ip += VBPI*16;
	op += VBPI*16;
#if GPR_TOO
	op[0]  = REVW_BE(REVW_BE(ip[0])  ^ (x0  + kChaCha20Constants[0]));
	op[1]  = REVW_BE(REVW_BE(ip[1])  ^ (x1  + kChaCha20Constants[1]));
	op[2]  = REVW_BE(REVW_BE(ip[2])  ^ (x2  + kChaCha20Constants[2]));
	op[3]  = REVW_BE(REVW_BE(ip[3])  ^ (x3  + kChaCha20Constants[3]));
	op[4]  = REVW_BE(REVW_BE(ip[4])  ^ (x4  + kp[0]));
	op[5]  = REVW_BE(REVW_BE(ip[5])  ^ (x5  + kp[1]));
	op[6]  = REVW_BE(REVW_BE(ip[6])  ^ (x6  + kp[2]));
	op[7]  = REVW_BE(REVW_BE(ip[7])  ^ (x7  + kp[3]));
	op[8]  = REVW_BE(REVW_BE(ip[8])  ^ (x8  + kp[4]));
	op[9]  = REVW_BE(REVW_BE(ip[9])  ^ (x9  + kp[5]));
	op[10] = REVW_BE(REVW_BE(ip[10]) ^ (x10 + kp[6]));
	op[11] = REVW_BE(REVW_BE(ip[11]) ^ (x11 + kp[7]));
	op[12] = REVW_BE(REVW_BE(ip[12]) ^ (x12 + (ctx->state[12])+((unsigned)(BPI*iters+(BPI-1)))));
	op[13] = REVW_BE(REVW_BE(ip[13]) ^ (x13 + np[0]));
	op[14] = REVW_BE(REVW_BE(ip[14]) ^ (x14 + np[1]));
	op[15] = REVW_BE(REVW_BE(ip[15]) ^ (x15 + np[2]));
	s3 += ONE;
	ip += 16;
	op += 16;
#endif
	}

	for (iters = nbytes%(BPI*64)/64; iters != 0; iters--) {
		uint32x4_t v0 = s0, v1 = s1, v2 = s2, v3 = s3;
		for (i = CHACHA_RNDS/2; i; i--) {
			DQROUND_VECTORS(v0,v1,v2,v3);
		}
		WRITE_XOR(ip, op, 0, v0+s0, v1+s1, v2+s2, v3+s3)
		s3 += ONE;
		ip += 16;
		op += 16;
	}

	nbytes = nbytes & 0x3f; // mod 64
	if (nbytes) {
		__attribute__ ((aligned (16))) uint32x4_t buf[4];
		uint32x4_t v0,v1,v2,v3;
		v0 = s0; v1 = s1; v2 = s2; v3 = s3;
		for (i = CHACHA_RNDS/2; i; i--) {
			DQROUND_VECTORS(v0,v1,v2,v3);
		}

		if (nbytes >= 16) {
			STORE(op + 0, LOAD(ip + 0) ^ REVV_BE(v0 + s0));
			if (nbytes >= 32) {
				STORE(op + 4, LOAD(ip + 4) ^ REVV_BE(v1 + s1));
				if (nbytes >= 48) {
					STORE(op + 8, LOAD(ip + 8) ^ REVV_BE(v2 + s2));
					buf[3] = REVV_BE(v3 + s3);
				} else {
					buf[2] = REVV_BE(v2 + s2);
				}
			} else {
				buf[1] = REVV_BE(v1 + s1);
			}
		} else {
			buf[0] = REVV_BE(v0 + s0);
		}

		for (i=nbytes & ~((size_t)15); i<nbytes; i++) {
			((char *)op)[i] = ((const char *)ip)[i] ^ ((char *)buf)[i];
		}
	}
	ctx->state[12] = s3[0];
}
#endif // CHACHA20_SIMD

//===========================================================================================================================
//	ccpoly1305
//
//	Based on floodyberry's Poly1305 code: <https://github.com/floodyberry/poly1305-donna>.
//	Based on DJB's Poly1305: <http://cr.yp.to/mac.html>.
//===========================================================================================================================

#define U8TO32_LE( PTR )			cc_load32_le( (PTR) )
#define U32TO8_LE( PTR, VALUE )		cc_store32_le( (VALUE), (PTR) )
#define mul32x32_64(a,b)			((uint64_t)(a) * (b))

static void _ccpoly1305_update(ccpoly1305_ctx *ctx, size_t nbytes, const uint8_t *in);

int ccpoly1305_init(ccpoly1305_ctx *ctx, const uint8_t *key)
{
    CC_ENSURE_DIT_ENABLED

	uint32_t t0,t1,t2,t3;
	size_t i;

	t0 = U8TO32_LE(key+0);
	t1 = U8TO32_LE(key+4);
	t2 = U8TO32_LE(key+8);
	t3 = U8TO32_LE(key+12);

	/* precompute multipliers */
	ctx->r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
	ctx->r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
	ctx->r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
	ctx->r3 = t2 & 0x3f03fff; t3 >>= 8;
	ctx->r4 = t3 & 0x00fffff;

	ctx->s1 = ctx->r1 * 5;
	ctx->s2 = ctx->r2 * 5;
	ctx->s3 = ctx->r3 * 5;
	ctx->s4 = ctx->r4 * 5;

	/* init state */
	ctx->h0 = 0;
	ctx->h1 = 0;
	ctx->h2 = 0;
	ctx->h3 = 0;
	ctx->h4 = 0;

	ctx->buf_used = 0;
	for (i = 0; i < 16; ++i)
		ctx->key[i] = key[i + 16];

    return 0;
}

int ccpoly1305_update(ccpoly1305_ctx *ctx, size_t nbytes, const uint8_t *in)
{
    CC_ENSURE_DIT_ENABLED

	size_t i, n;

	if (ctx->buf_used) {
		n = 16 - ctx->buf_used;
		if (n > nbytes)
			n = nbytes;
		for (i = 0; i < n; i++)
			ctx->buf[ctx->buf_used + i] = in[i];
		ctx->buf_used += n;
		nbytes -= n;
		in += n;

		if (ctx->buf_used == 16) {
			_ccpoly1305_update(ctx, 16, ctx->buf);
			ctx->buf_used = 0;
		}
	}

	if (nbytes >= 16) {
		n = nbytes & ~((size_t)0xf);
		_ccpoly1305_update(ctx, n, in);
		in += n;
		nbytes &= 0xf;
	}

	if (nbytes) {
		for (i = 0; i < nbytes; i++)
			ctx->buf[i] = in[i];
		ctx->buf_used = nbytes;
	}

    return 0;
}

int ccpoly1305_final(ccpoly1305_ctx *ctx, uint8_t *tag)
{
    CC_ENSURE_DIT_ENABLED

	uint64_t f0,f1,f2,f3;
	uint32_t g0,g1,g2,g3,g4;
	uint32_t b, nb;

	if (ctx->buf_used)
		_ccpoly1305_update(ctx, ctx->buf_used, ctx->buf);

	                    b = ctx->h0 >> 26; ctx->h0 = ctx->h0 & 0x3ffffff;
	ctx->h1 +=     b; b = ctx->h1 >> 26; ctx->h1 = ctx->h1 & 0x3ffffff;
	ctx->h2 +=     b; b = ctx->h2 >> 26; ctx->h2 = ctx->h2 & 0x3ffffff;
	ctx->h3 +=     b; b = ctx->h3 >> 26; ctx->h3 = ctx->h3 & 0x3ffffff;
	ctx->h4 +=     b; b = ctx->h4 >> 26; ctx->h4 = ctx->h4 & 0x3ffffff;
	ctx->h0 += b * 5;

	g0 = ctx->h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
	g1 = ctx->h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
	g2 = ctx->h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
	g3 = ctx->h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
	g4 = ctx->h4 + b - (1 << 26);

	b = (g4 >> 31) - 1;
	nb = ~b;
	ctx->h0 = (ctx->h0 & nb) | (g0 & b);
	ctx->h1 = (ctx->h1 & nb) | (g1 & b);
	ctx->h2 = (ctx->h2 & nb) | (g2 & b);
	ctx->h3 = (ctx->h3 & nb) | (g3 & b);
	ctx->h4 = (ctx->h4 & nb) | (g4 & b);

	f0 = ((ctx->h0      ) | (ctx->h1 << 26)) + (uint64_t)U8TO32_LE(&ctx->key[0]);
	f1 = ((ctx->h1 >>  6) | (ctx->h2 << 20)) + (uint64_t)U8TO32_LE(&ctx->key[4]);
	f2 = ((ctx->h2 >> 12) | (ctx->h3 << 14)) + (uint64_t)U8TO32_LE(&ctx->key[8]);
	f3 = ((ctx->h3 >> 18) | (ctx->h4 <<  8)) + (uint64_t)U8TO32_LE(&ctx->key[12]);

	U32TO8_LE(&tag[ 0], (uint32_t) f0); f1 += (f0 >> 32);
	U32TO8_LE(&tag[ 4], (uint32_t) f1); f2 += (f1 >> 32);
	U32TO8_LE(&tag[ 8], (uint32_t) f2); f3 += (f2 >> 32);
	U32TO8_LE(&tag[12], (uint32_t) f3);

    return 0;
}

static void _ccpoly1305_update(ccpoly1305_ctx *ctx, size_t nbytes, const uint8_t *in)
{
	uint32_t t0,t1,t2,t3;
	uint64_t t[5];
	uint32_t b;
	uint64_t c;
	size_t j;
	uint8_t mp[16];

	if (nbytes < 16)
		goto poly1305_donna_atmost15bytes;

poly1305_donna_16bytes:
	t0 = U8TO32_LE(in);
	t1 = U8TO32_LE(in+4);
	t2 = U8TO32_LE(in+8);
	t3 = U8TO32_LE(in+12);

	in += 16;
	nbytes -= 16;

	ctx->h0 += t0 & 0x3ffffff;
	ctx->h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
	ctx->h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
	ctx->h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
	ctx->h4 += (t3 >> 8) | (1 << 24);

poly1305_donna_mul:
	t[0] = mul32x32_64(ctx->h0,ctx->r0) +
	       mul32x32_64(ctx->h1,ctx->s4) +
	       mul32x32_64(ctx->h2,ctx->s3) +
	       mul32x32_64(ctx->h3,ctx->s2) +
	       mul32x32_64(ctx->h4,ctx->s1);
	t[1] = mul32x32_64(ctx->h0,ctx->r1) +
	       mul32x32_64(ctx->h1,ctx->r0) +
	       mul32x32_64(ctx->h2,ctx->s4) +
	       mul32x32_64(ctx->h3,ctx->s3) +
	       mul32x32_64(ctx->h4,ctx->s2);
	t[2] = mul32x32_64(ctx->h0,ctx->r2) +
	       mul32x32_64(ctx->h1,ctx->r1) +
	       mul32x32_64(ctx->h2,ctx->r0) +
	       mul32x32_64(ctx->h3,ctx->s4) +
	       mul32x32_64(ctx->h4,ctx->s3);
	t[3] = mul32x32_64(ctx->h0,ctx->r3) +
	       mul32x32_64(ctx->h1,ctx->r2) +
	       mul32x32_64(ctx->h2,ctx->r1) +
	       mul32x32_64(ctx->h3,ctx->r0) +
	       mul32x32_64(ctx->h4,ctx->s4);
	t[4] = mul32x32_64(ctx->h0,ctx->r4) +
	       mul32x32_64(ctx->h1,ctx->r3) +
	       mul32x32_64(ctx->h2,ctx->r2) +
	       mul32x32_64(ctx->h3,ctx->r1) +
	       mul32x32_64(ctx->h4,ctx->r0);

	           ctx->h0 = (uint32_t)t[0] & 0x3ffffff; c =           (t[0] >> 26);
	t[1] += c; ctx->h1 = (uint32_t)t[1] & 0x3ffffff; b = (uint32_t)(t[1] >> 26);
	t[2] += b; ctx->h2 = (uint32_t)t[2] & 0x3ffffff; b = (uint32_t)(t[2] >> 26);
	t[3] += b; ctx->h3 = (uint32_t)t[3] & 0x3ffffff; b = (uint32_t)(t[3] >> 26);
	t[4] += b; ctx->h4 = (uint32_t)t[4] & 0x3ffffff; b = (uint32_t)(t[4] >> 26);
	ctx->h0 += b * 5;

	if (nbytes >= 16)
		goto poly1305_donna_16bytes;

	/* final bytes */
poly1305_donna_atmost15bytes:
	if (!nbytes)
		return;

	for (j = 0; j < nbytes; j++)
		mp[j] = in[j];
	mp[j++] = 1;
	for (; j < 16; j++)
		mp[j] = 0;
	nbytes = 0;

	t0 = U8TO32_LE(mp+0);
	t1 = U8TO32_LE(mp+4);
	t2 = U8TO32_LE(mp+8);
	t3 = U8TO32_LE(mp+12);

	ctx->h0 += t0 & 0x3ffffff;
	ctx->h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
	ctx->h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
	ctx->h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
	ctx->h4 += (t3 >> 8);

	goto poly1305_donna_mul;
}

int	ccpoly1305(const uint8_t *key, size_t nbytes, const uint8_t *data, uint8_t *out)
{
    CC_ENSURE_DIT_ENABLED

	ccpoly1305_ctx ctx;

	ccpoly1305_init(&ctx, key);
	ccpoly1305_update(&ctx, nbytes, data);
	ccpoly1305_final(&ctx, out);

    return 0;
}

const struct ccchacha20poly1305_info ccchacha20poly1305_info_default;

const struct ccchacha20poly1305_info *ccchacha20poly1305_info(void)
{
    return &ccchacha20poly1305_info_default;
}

int	ccchacha20poly1305_init(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *key)
{
    CC_ENSURE_DIT_ENABLED

    ccchacha20_init(&ctx->chacha20_ctx, key);
    ccchacha20poly1305_reset(info, ctx);

    return 0;
}

int ccchacha20poly1305_reset(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    ctx->aad_nbytes	= 0;
    ctx->text_nbytes = 0;
    ctx->state = CCCHACHA20POLY1305_STATE_SETNONCE;

    ccchacha20_reset(&ctx->chacha20_ctx);

    return 0;
}

int ccchacha20poly1305_setnonce(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *nonce)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t	block[CCCHACHA20_BLOCK_NBYTES];

    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_SETNONCE, err);

    ccchacha20_setnonce(&ctx->chacha20_ctx, nonce);
    _ccchacha20_xor(&ctx->chacha20_ctx, sizeof (kZero64), block, kZero64);
    ccpoly1305_init(&ctx->poly1305_ctx, block);
    ctx->state = CCCHACHA20POLY1305_STATE_AAD;

    return 0;

err:
    return 1;
}

int ccchacha20poly1305_incnonce(CC_UNUSED const struct ccchacha20poly1305_info *info, CC_UNUSED ccchacha20poly1305_ctx *ctx, CC_UNUSED uint8_t *nonce)
{
    CC_ENSURE_DIT_ENABLED

    // not implemented
    return 1;
}

int	ccchacha20poly1305_aad(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *aad)
{
    CC_ENSURE_DIT_ENABLED

    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_AAD, err);

	ccpoly1305_update(&ctx->poly1305_ctx, nbytes, aad);
	ctx->aad_nbytes += nbytes;

    return 0;

err:
    return 1;
}

static size_t pad_nbytes(uint64_t nbytes)
{
    return (16 - (nbytes & 0xf)) & 0xf; // mod 16
}

static int finalize_aad(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, uint8_t state)
{
    if (ctx->state == CCCHACHA20POLY1305_STATE_AAD) {
        ccpoly1305_update(&ctx->poly1305_ctx, pad_nbytes(ctx->aad_nbytes), kZero64);
        ctx->state = state;
    }

    return 0;
}

int	ccchacha20poly1305_encrypt(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    finalize_aad(info, ctx, CCCHACHA20POLY1305_STATE_ENCRYPT);
    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_ENCRYPT, err);
    cc_require(UINT64_MAX - ctx->text_nbytes >= nbytes, err);
    cc_require(ctx->text_nbytes + nbytes <= CCCHACHA20POLY1305_TEXT_MAX_NBYTES, err);

	ccchacha20_update(&ctx->chacha20_ctx, nbytes, in, out);
    ccpoly1305_update(&ctx->poly1305_ctx, nbytes, out);
    ctx->text_nbytes += nbytes;

	return 0;

err:
    return 1;
}

int	ccchacha20poly1305_decrypt(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    finalize_aad(info, ctx, CCCHACHA20POLY1305_STATE_DECRYPT);
    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_DECRYPT, err);
    cc_require(UINT64_MAX - ctx->text_nbytes >= nbytes, err);
    cc_require(ctx->text_nbytes + nbytes <= CCCHACHA20POLY1305_TEXT_MAX_NBYTES, err);

	ccpoly1305_update(&ctx->poly1305_ctx, nbytes, in);
	ccchacha20_update(&ctx->chacha20_ctx, nbytes, in, out);
	ctx->text_nbytes += nbytes;

	return 0;

err:
    return 1;
}

int	ccchacha20poly1305_finalize(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, uint8_t *tag)
{
    CC_ENSURE_DIT_ENABLED

	uint8_t		buf[ 8 ];

    finalize_aad(info, ctx, CCCHACHA20POLY1305_STATE_ENCRYPT);
    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_ENCRYPT, err);

    ccpoly1305_update(&ctx->poly1305_ctx, pad_nbytes(ctx->text_nbytes), kZero64);

    cc_store64_le(ctx->aad_nbytes, buf);
    ccpoly1305_update(&ctx->poly1305_ctx, sizeof (uint64_t), buf);
	cc_store64_le(ctx->text_nbytes, buf);
	ccpoly1305_update(&ctx->poly1305_ctx, sizeof (uint64_t), buf);

	ccpoly1305_final(&ctx->poly1305_ctx, tag);

    ctx->state = CCCHACHA20POLY1305_STATE_FINAL;

    return 0;

err:
    return 1;
}

int	ccchacha20poly1305_verify(CC_UNUSED const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *tag)
{
    CC_ENSURE_DIT_ENABLED

	uint8_t		buf[ 8 ];
	uint8_t		calc_tag[ 16 ];

    finalize_aad(info, ctx, CCCHACHA20POLY1305_STATE_DECRYPT);
    cc_require(ctx->state == CCCHACHA20POLY1305_STATE_DECRYPT, err);

    ccpoly1305_update(&ctx->poly1305_ctx, pad_nbytes(ctx->text_nbytes), kZero64);

    cc_store64_le(ctx->aad_nbytes, buf);
    ccpoly1305_update(&ctx->poly1305_ctx, sizeof (uint64_t), buf);
    cc_store64_le(ctx->text_nbytes, buf);
    ccpoly1305_update(&ctx->poly1305_ctx, sizeof (uint64_t), buf);

	ccpoly1305_final(&ctx->poly1305_ctx, calc_tag);

    ctx->state = CCCHACHA20POLY1305_STATE_FINAL;

	return ( cc_cmp_safe( 16, calc_tag, tag ) == 0 ) ? 0 : -1;

err:
    return 1;
}

int ccchacha20poly1305_encrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce, size_t aad_nbytes, const void *aad, size_t ptext_nbytes, const void *ptext, void *ctext, uint8_t *tag)
{
    CC_ENSURE_DIT_ENABLED

	ccchacha20poly1305_ctx          ctx;

	ccchacha20poly1305_init(info, &ctx, key);
    ccchacha20poly1305_setnonce(info, &ctx, nonce);
    ccchacha20poly1305_aad(info, &ctx, aad_nbytes, aad);
    ccchacha20poly1305_encrypt(info, &ctx, ptext_nbytes, ptext, ctext);
    ccchacha20poly1305_finalize(info, &ctx, tag);
    ccchacha20_final(&ctx.chacha20_ctx);
    return 0;
}

int ccchacha20poly1305_decrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce, size_t aad_nbytes, const void *aad, size_t ctext_nbytes, const void *ctext, void *ptext, const uint8_t *tag)
{
    CC_ENSURE_DIT_ENABLED

	ccchacha20poly1305_ctx		ctx;

    ccchacha20poly1305_init(info, &ctx, key);
    ccchacha20poly1305_setnonce(info, &ctx, nonce);
    ccchacha20poly1305_aad(info, &ctx, aad_nbytes, aad);
    ccchacha20poly1305_decrypt(info, &ctx, ctext_nbytes, ctext, ptext);
    int rv = ccchacha20poly1305_verify(info, &ctx, tag);
    ccchacha20_final(&ctx.chacha20_ctx);
    return rv;
}
