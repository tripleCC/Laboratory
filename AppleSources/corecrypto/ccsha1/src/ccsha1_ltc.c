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



#include <corecrypto/ccsha1.h>
#include "ccsha1_internal.h"
#include <corecrypto/ccdigest_priv.h>
#include "ccdigest_internal.h"
#include "cc_internal.h"

#if !CC_KERNEL || !CC_USE_ASM

#define F0(x,y,z)  (z ^ (x & (y ^ z)))
#define F1(x,y,z)  (x ^ y ^ z)
#define F2(x,y,z)  ((x & y) | (z & (x | y)))
#define F3(x,y,z)  (x ^ y ^ z)


static void sha1_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    uint32_t a,b,c,d,e,W[80],i;
    uint32_t *s = ccdigest_u32(state);
    const unsigned char *buf = in;

    while (nblocks--) {


        /* copy the state into 512-bits into W[0..15] */
        for (i = 0; i < 16; i++) {
            W[i] = cc_load32_be(buf + (4*i));
        }

        /* read state */
        a = s[0];
        b = s[1];
        c = s[2];
        d = s[3];
        e = s[4];

        /* expand it */
        for (i = 16; i < 80; i++) {
            W[i] = CC_ROL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
        }

        /* compress */
        /* round one */
#define FF0(a,b,c,d,e,i) e = (CC_ROLc(a, 5) + F0(b,c,d) + e + W[i] + 0x5a827999); b = CC_ROLc(b, 30);
#define FF1(a,b,c,d,e,i) e = (CC_ROLc(a, 5) + F1(b,c,d) + e + W[i] + 0x6ed9eba1); b = CC_ROLc(b, 30);
#define FF2(a,b,c,d,e,i) e = (CC_ROLc(a, 5) + F2(b,c,d) + e + W[i] + 0x8f1bbcdc); b = CC_ROLc(b, 30);
#define FF3(a,b,c,d,e,i) e = (CC_ROLc(a, 5) + F3(b,c,d) + e + W[i] + 0xca62c1d6); b = CC_ROLc(b, 30);

#if CC_SMALL_CODE
        uint32_t t;

        for (i = 0; i < 20; ) {
            FF0(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
        }

        for (; i < 40; ) {
            FF1(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
        }

        for (; i < 60; ) {
            FF2(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
        }

        for (; i < 80; ) {
            FF3(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
        }

#else

        for (i = 0; i < 20; ) {
            FF0(a,b,c,d,e,i++);
            FF0(e,a,b,c,d,i++);
            FF0(d,e,a,b,c,i++);
            FF0(c,d,e,a,b,i++);
            FF0(b,c,d,e,a,i++);
        }

        /* round two */
        for (; i < 40; )  {
            FF1(a,b,c,d,e,i++);
            FF1(e,a,b,c,d,i++);
            FF1(d,e,a,b,c,i++);
            FF1(c,d,e,a,b,i++);
            FF1(b,c,d,e,a,i++);
        }

        /* round three */
        for (; i < 60; )  {
            FF2(a,b,c,d,e,i++);
            FF2(e,a,b,c,d,i++);
            FF2(d,e,a,b,c,i++);
            FF2(c,d,e,a,b,i++);
            FF2(b,c,d,e,a,i++);
        }

        /* round four */
        for (; i < 80; )  {
            FF3(a,b,c,d,e,i++);
            FF3(e,a,b,c,d,i++);
            FF3(d,e,a,b,c,i++);
            FF3(c,d,e,a,b,i++);
            FF3(b,c,d,e,a,i++);
        }
#endif

#undef FF0
#undef FF1
#undef FF2
#undef FF3
        /* store state */
        s[0] += a;
        s[1] += b;
        s[2] += c;
        s[3] += d;
        s[4] += e;

        buf+=CCSHA1_BLOCK_SIZE;
    }
}

const struct ccdigest_info ccsha1_ltc_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid_size = ccoid_sha1_len,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = ccsha1_initial_state,
    .compress = sha1_compress,
    .final = ccdigest_final_64be,
    .impl = CC_IMPL_SHA1_LTC,
};

#endif
