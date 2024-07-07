/* Copyright (c) (2010,2011,2012,2015,2016,2018,2019) Apple Inc. All rights reserved.
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


#include <corecrypto/ccrc2.h>
#include "ltc_rc2.h"

/**********************************************************************\
 * Encrypt an 8-byte block of plaintext using the given key.            *
 \**********************************************************************/
/*!
 Encrypts a block of text with LTC_RC2
 @param in The input plaintext (8 bytes)
 @param out The output ciphertext (8 bytes)
 @param skey The key as scheduled
 */

static int ltc_rc2_ecb_encrypt(const ccecb_ctx *skey, size_t nblocks, const void *in, void *out)
{
    const uint32_t *xkey;
    uint32_t x76, x54, x32, x10, i;
    const ltc_rc2_keysched *rc2;
    const unsigned char *pt=in;
    unsigned char *ct=out;

    rc2 = (const ltc_rc2_keysched *)skey;
    xkey = rc2->xkey;

    while(nblocks--) {

        x76 = ((uint32_t)pt[7] << 8) + (uint32_t)pt[6];
        x54 = ((uint32_t)pt[5] << 8) + (uint32_t)pt[4];
        x32 = ((uint32_t)pt[3] << 8) + (uint32_t)pt[2];
        x10 = ((uint32_t)pt[1] << 8) + (uint32_t)pt[0];

        for (i = 0; i < 16; i++) {
            x10 = (x10 + (x32 & ~x76) + (x54 & x76) + xkey[4*i+0]) & 0xFFFF;
            x10 = ((x10 << 1) | (x10 >> 15));

            x32 = (x32 + (x54 & ~x10) + (x76 & x10) + xkey[4*i+1]) & 0xFFFF;
            x32 = ((x32 << 2) | (x32 >> 14));

            x54 = (x54 + (x76 & ~x32) + (x10 & x32) + xkey[4*i+2]) & 0xFFFF;
            x54 = ((x54 << 3) | (x54 >> 13));

            x76 = (x76 + (x10 & ~x54) + (x32 & x54) + xkey[4*i+3]) & 0xFFFF;
            x76 = ((x76 << 5) | (x76 >> 11));

            if (i == 4 || i == 10) {
                x10 = (x10 + xkey[x76 & 63]) & 0xFFFF;
                x32 = (x32 + xkey[x10 & 63]) & 0xFFFF;
                x54 = (x54 + xkey[x32 & 63]) & 0xFFFF;
                x76 = (x76 + xkey[x54 & 63]) & 0xFFFF;
            }
        }

        ct[0] = (unsigned char)x10;
        ct[1] = (unsigned char)(x10 >> 8);
        ct[2] = (unsigned char)x32;
        ct[3] = (unsigned char)(x32 >> 8);
        ct[4] = (unsigned char)x54;
        ct[5] = (unsigned char)(x54 >> 8);
        ct[6] = (unsigned char)x76;
        ct[7] = (unsigned char)(x76 >> 8);

        pt+=CCRC2_BLOCK_SIZE;
        ct+=CCRC2_BLOCK_SIZE;
    }
    
    return 0;
}

#include <corecrypto/cc_priv.h>

const struct ccmode_ecb ccrc2_ltc_ecb_encrypt_mode = {
    .size = sizeof(ltc_rc2_keysched),
    .block_size = CCRC2_BLOCK_SIZE,
    .init = ccrc2_ltc_setup,
    .ecb = ltc_rc2_ecb_encrypt,
};
