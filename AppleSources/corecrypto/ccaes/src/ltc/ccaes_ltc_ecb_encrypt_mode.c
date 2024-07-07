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

#include <corecrypto/ccaes.h>
#include "cc_internal.h"

#if !CC_KERNEL || !CC_USE_ASM || defined(__x86_64__)

#include "ccaes_ltc_common.h"
#include "ccaes_ltc_tab.h"

static void ccaes_ltc_ecb_encrypt(const ccecb_ctx *skey, const unsigned char *pt, unsigned char *ct)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3, rn, r;
    const uint32_t *rk;
    const ltc_rijndael_keysched *rijndael;

    rijndael = (const ltc_rijndael_keysched *)skey;

    rn = rijndael->enc.rn;
    rk = rijndael->enc.ks;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = cc_load32_le(pt + 0) ^ rk[0];
    s1 = cc_load32_le(pt + 4) ^ rk[1];
    s2 = cc_load32_le(pt + 8) ^ rk[2];
    s3 = cc_load32_le(pt + 12) ^ rk[3];

    /*
     * Nr - 1 full rounds:
     */
    r = (rn / 16) >> 1;
    for (;;) {
        t0 = Te0(cc_byte(s0, 0)) ^ Te1(cc_byte(s1, 1)) ^ Te2(cc_byte(s2, 2)) ^ Te3(cc_byte(s3, 3)) ^ rk[4];
        t1 = Te0(cc_byte(s1, 0)) ^ Te1(cc_byte(s2, 1)) ^ Te2(cc_byte(s3, 2)) ^ Te3(cc_byte(s0, 3)) ^ rk[5];
        t2 = Te0(cc_byte(s2, 0)) ^ Te1(cc_byte(s3, 1)) ^ Te2(cc_byte(s0, 2)) ^ Te3(cc_byte(s1, 3)) ^ rk[6];
        t3 = Te0(cc_byte(s3, 0)) ^ Te1(cc_byte(s0, 1)) ^ Te2(cc_byte(s1, 2)) ^ Te3(cc_byte(s2, 3)) ^ rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 = Te0(cc_byte(t0, 0)) ^ Te1(cc_byte(t1, 1)) ^ Te2(cc_byte(t2, 2)) ^ Te3(cc_byte(t3, 3)) ^ rk[0];
        s1 = Te0(cc_byte(t1, 0)) ^ Te1(cc_byte(t2, 1)) ^ Te2(cc_byte(t3, 2)) ^ Te3(cc_byte(t0, 3)) ^ rk[1];
        s2 = Te0(cc_byte(t2, 0)) ^ Te1(cc_byte(t3, 1)) ^ Te2(cc_byte(t0, 2)) ^ Te3(cc_byte(t1, 3)) ^ rk[2];
        s3 = Te0(cc_byte(t3, 0)) ^ Te1(cc_byte(t0, 1)) ^ Te2(cc_byte(t1, 2)) ^ Te3(cc_byte(t2, 3)) ^ rk[3];
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 = Te4_3[cc_byte(t0, 0)] ^ Te4_2[cc_byte(t1, 1)] ^ Te4_1[cc_byte(t2, 2)] ^ Te4_0[cc_byte(t3, 3)] ^ rk[0];
    cc_store32_le(s0, ct);
    s1 = Te4_3[cc_byte(t1, 0)] ^ Te4_2[cc_byte(t2, 1)] ^ Te4_1[cc_byte(t3, 2)] ^ Te4_0[cc_byte(t0, 3)] ^ rk[1];
    cc_store32_le(s1, ct + 4);
    s2 = Te4_3[cc_byte(t2, 0)] ^ Te4_2[cc_byte(t3, 1)] ^ Te4_1[cc_byte(t0, 2)] ^ Te4_0[cc_byte(t1, 3)] ^ rk[2];
    cc_store32_le(s2, ct + 8);
    s3 = Te4_3[cc_byte(t3, 0)] ^ Te4_2[cc_byte(t0, 1)] ^ Te4_1[cc_byte(t1, 2)] ^ Te4_0[cc_byte(t2, 3)] ^ rk[3];
    cc_store32_le(s3, ct + 12);
}

static int ccaes_ecb_encrypt(const ccecb_ctx *key, size_t nblocks, const void *in, void *out)
{
    if (nblocks) {
        const unsigned char *p = in;
        unsigned char *c = out;
        for (;;) {
            ccaes_ltc_ecb_encrypt(key, p, c);
            if (--nblocks) {
                p += CCAES_BLOCK_SIZE;
                c += CCAES_BLOCK_SIZE;
            } else {
                break;
            }
        }
    }

    return 0;
}

const struct ccmode_ecb ccaes_ltc_ecb_encrypt_mode = {
    .size = sizeof(ltc_rijndael_keysched),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_ecb_encrypt_init,
    .ecb = ccaes_ecb_encrypt,
    .roundkey = ccaes_ecb_encrypt_roundkey,
    .impl = CC_IMPL_AES_ECB_LTC,
};

#endif
