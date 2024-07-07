/* Copyright (c) (2010,2011,2015-2019,2021,2022) Apple Inc. All rights reserved.
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

#include <corecrypto/ccsha2.h>
#include "cc_internal.h"
#include "ccsha2_internal.h"

#if !CC_KERNEL || !CC_USE_ASM

#if CCSHA2_SHA256_USE_SHA512_K
#define K(i) ((uint32_t)(ccsha512_K[i] >> 32))
#else
#define K(i) ccsha256_K[i]
#endif

// Various logical functions
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define S(x, n) CC_RORc(x, n)
#define R(x, n) ((x) >> (n))
#define Sigma0(x) (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x) (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x) (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x) (S(x, 17) ^ S(x, 19) ^ R(x, 10))

#define set_W(i) (W[i] = cc_load32_be(buf + (4 * (i))))

// the round function
#define RND(a, b, c, d, e, f, g, h, i)              \
    t0 = h + Sigma1(e) + Ch(e, f, g) + K(i) + W[i]; \
    t1 = Sigma0(a) + Maj(a, b, c);                  \
    d += t0;                                        \
    h = t0 + t1;

// compress 512-bits
void ccsha256_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    uint32_t W[64], t0, t1;
    uint32_t S[8];
    int i;
    uint32_t *s = ccdigest_u32(state);
    const unsigned char *buf = in;

    while (nblocks--) {
        // schedule W 0..15
        for (i = 0; i < 16; i += 1) {
            set_W(i);
        }

        // schedule W 16..63
        for (; i < 64; i++) {
            W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
        }

        // copy state into S
        S[0] = s[0];
        S[1] = s[1];
        S[2] = s[2];
        S[3] = s[3];
        S[4] = s[4];
        S[5] = s[5];
        S[6] = s[6];
        S[7] = s[7];

        // Compress
#if CC_SMALL_CODE
        for (i = 0; i < 64; i += 1) {
            t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K(i) + W[i];
            t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
            S[7] = S[6];
            S[6] = S[5];
            S[5] = S[4];
            S[4] = S[3] + t0;
            S[3] = S[2];
            S[2] = S[1];
            S[1] = S[0];
            S[0] = t0 + t1;
        }
#else
        for (i = 0; i < 64; i += 8) {
            RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i + 0);
            RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1);
            RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2);
            RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3);
            RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4);
            RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5);
            RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6);
            RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7);
        }
#endif

        // feedback
        s[0] += S[0];
        s[1] += S[1];
        s[2] += S[2];
        s[3] += S[3];
        s[4] += S[4];
        s[5] += S[5];
        s[6] += S[6];
        s[7] += S[7];

        buf += CCSHA256_BLOCK_SIZE / sizeof(buf[0]);
    }
}

#endif
