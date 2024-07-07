/* Copyright (c) (2010-2012,2015-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*
 * Parts of this code adapted from LibTomCrypt
 *
 * LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/ccmd4.h>
#include "ccmd4_internal.h"
#include <corecrypto/ccmd5.h>
#include "cc_internal.h"
#include <corecrypto/ccdigest_priv.h>
#include "ccdigest_internal.h"

#define F(x,y,z)  (z ^ (x & (y ^ z)))
#define G(x,y,z)  (y ^ (z & (y ^ x)))
#define H(x,y,z)  (x^y^z)
#define I(x,y,z)  (y^(x|(~z)))

#if CC_SMALL_CODE

#define FF(a,b,c,d,M,s,t) \
a = (a + F(b,c,d) + M + t); a = CC_ROL(a, s) + b;

#define GG(a,b,c,d,M,s,t) \
a = (a + G(b,c,d) + M + t); a = CC_ROL(a, s) + b;

#define HH(a,b,c,d,M,s,t) \
a = (a + H(b,c,d) + M + t); a = CC_ROL(a, s) + b;

#define II(a,b,c,d,M,s,t) \
a = (a + I(b,c,d) + M + t); a = CC_ROL(a, s) + b;

static const unsigned char Worder[64] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
    5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
    0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
};

static const unsigned char Rorder[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static const uint32_t Korder[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#else

#define FF(a,b,c,d,M,s,t) \
a = (a + F(b,c,d) + M + t); a = CC_ROLc(a, s) + b;

#define GG(a,b,c,d,M,s,t) \
a = (a + G(b,c,d) + M + t); a = CC_ROLc(a, s) + b;

#define HH(a,b,c,d,M,s,t) \
a = (a + H(b,c,d) + M + t); a = CC_ROLc(a, s) + b;

#define II(a,b,c,d,M,s,t) \
a = (a + I(b,c,d) + M + t); a = CC_ROLc(a, s) + b;


#endif


static void md5_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    uint32_t i, W[16], a, b, c, d;
#if CC_SMALL_CODE
    uint32_t t;
#endif
    uint32_t *s = ccdigest_u32(state);
    const unsigned char *buf = in;

    while(nblocks--) {

        /* copy the state into 512-bits into W[0..15] */
        for (i = 0; i < 16; i++) {
            W[i] = cc_load32_le(buf + (4*i));
        }

        /* copy state */
        a = s[0];
        b = s[1];
        c = s[2];
        d = s[3];

    #if CC_SMALL_CODE
        for (i = 0; i < 16; ++i) {
            FF(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
            t = d; d = c; c = b; b = a; a = t;
        }

        for (; i < 32; ++i) {
            GG(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
            t = d; d = c; c = b; b = a; a = t;
        }

        for (; i < 48; ++i) {
            HH(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
            t = d; d = c; c = b; b = a; a = t;
        }

        for (; i < 64; ++i) {
            II(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
            t = d; d = c; c = b; b = a; a = t;
        }

    #else
        FF(a,b,c,d,W[0],7,0xd76aa478)
        FF(d,a,b,c,W[1],12,0xe8c7b756)
        FF(c,d,a,b,W[2],17,0x242070db)
        FF(b,c,d,a,W[3],22,0xc1bdceee)
        FF(a,b,c,d,W[4],7,0xf57c0faf)
        FF(d,a,b,c,W[5],12,0x4787c62a)
        FF(c,d,a,b,W[6],17,0xa8304613)
        FF(b,c,d,a,W[7],22,0xfd469501)
        FF(a,b,c,d,W[8],7,0x698098d8)
        FF(d,a,b,c,W[9],12,0x8b44f7af)
        FF(c,d,a,b,W[10],17,0xffff5bb1)
        FF(b,c,d,a,W[11],22,0x895cd7be)
        FF(a,b,c,d,W[12],7,0x6b901122)
        FF(d,a,b,c,W[13],12,0xfd987193)
        FF(c,d,a,b,W[14],17,0xa679438e)
        FF(b,c,d,a,W[15],22,0x49b40821)
        GG(a,b,c,d,W[1],5,0xf61e2562)
        GG(d,a,b,c,W[6],9,0xc040b340)
        GG(c,d,a,b,W[11],14,0x265e5a51)
        GG(b,c,d,a,W[0],20,0xe9b6c7aa)
        GG(a,b,c,d,W[5],5,0xd62f105d)
        GG(d,a,b,c,W[10],9,0x02441453)
        GG(c,d,a,b,W[15],14,0xd8a1e681)
        GG(b,c,d,a,W[4],20,0xe7d3fbc8)
        GG(a,b,c,d,W[9],5,0x21e1cde6)
        GG(d,a,b,c,W[14],9,0xc33707d6)
        GG(c,d,a,b,W[3],14,0xf4d50d87)
        GG(b,c,d,a,W[8],20,0x455a14ed)
        GG(a,b,c,d,W[13],5,0xa9e3e905)
        GG(d,a,b,c,W[2],9,0xfcefa3f8)
        GG(c,d,a,b,W[7],14,0x676f02d9)
        GG(b,c,d,a,W[12],20,0x8d2a4c8a)
        HH(a,b,c,d,W[5],4,0xfffa3942)
        HH(d,a,b,c,W[8],11,0x8771f681)
        HH(c,d,a,b,W[11],16,0x6d9d6122)
        HH(b,c,d,a,W[14],23,0xfde5380c)
        HH(a,b,c,d,W[1],4,0xa4beea44)
        HH(d,a,b,c,W[4],11,0x4bdecfa9)
        HH(c,d,a,b,W[7],16,0xf6bb4b60)
        HH(b,c,d,a,W[10],23,0xbebfbc70)
        HH(a,b,c,d,W[13],4,0x289b7ec6)
        HH(d,a,b,c,W[0],11,0xeaa127fa)
        HH(c,d,a,b,W[3],16,0xd4ef3085)
        HH(b,c,d,a,W[6],23,0x04881d05)
        HH(a,b,c,d,W[9],4,0xd9d4d039)
        HH(d,a,b,c,W[12],11,0xe6db99e5)
        HH(c,d,a,b,W[15],16,0x1fa27cf8)
        HH(b,c,d,a,W[2],23,0xc4ac5665)
        II(a,b,c,d,W[0],6,0xf4292244)
        II(d,a,b,c,W[7],10,0x432aff97)
        II(c,d,a,b,W[14],15,0xab9423a7)
        II(b,c,d,a,W[5],21,0xfc93a039)
        II(a,b,c,d,W[12],6,0x655b59c3)
        II(d,a,b,c,W[3],10,0x8f0ccc92)
        II(c,d,a,b,W[10],15,0xffeff47d)
        II(b,c,d,a,W[1],21,0x85845dd1)
        II(a,b,c,d,W[8],6,0x6fa87e4f)
        II(d,a,b,c,W[15],10,0xfe2ce6e0)
        II(c,d,a,b,W[6],15,0xa3014314)
        II(b,c,d,a,W[13],21,0x4e0811a1)
        II(a,b,c,d,W[4],6,0xf7537e82)
        II(d,a,b,c,W[11],10,0xbd3af235)
        II(c,d,a,b,W[2],15,0x2ad7d2bb)
        II(b,c,d,a,W[9],21,0xeb86d391)
    #endif

        /* store state */
        s[0] += a;
        s[1] += b;
        s[2] += c;
        s[3] += d;

        buf+=CCMD5_BLOCK_SIZE;
    }
}

const struct ccdigest_info ccmd5_ltc_di = {
    .output_size = CCMD5_OUTPUT_SIZE,
    .state_size = CCMD5_STATE_SIZE,
    .block_size = CCMD5_BLOCK_SIZE,
    .oid_size = 10,
    .oid = CC_DIGEST_OID_MD5,
    .initial_state = ccmd4_initial_state,
    .compress = md5_compress,
    .final = ccdigest_final_64le,
};
