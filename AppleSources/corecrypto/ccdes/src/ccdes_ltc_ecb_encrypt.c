/* Copyright (c) (2010,2011,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
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

#include <corecrypto/ccdes.h>
#include <corecrypto/cc_priv.h>
#include "ltc_des.h"

/*!
 Encrypts a block of text with LTC_DES
 @param in The input plaintext (8 bytes)
 @param out The output ciphertext (8 bytes)
 @param skey The key as scheduled
 @return CCERR_OK  if successful
 */
static int ltc_des_ecb_encrypt(const ccecb_ctx *skey, size_t nblocks, const void *in, void *out)
{
    uint32_t work[2];
    const ltc_des_keysched *des;
    const unsigned char *pt=in;
    unsigned char *ct=out;

    des = (const ltc_des_keysched *)skey;

    while(nblocks--) {
        work[0] = cc_load32_be(pt);
        work[1] = cc_load32_be(pt + 4);
        desfunc(work, des->ek);
        cc_store32_be(work[0], ct);
        cc_store32_be(work[1], ct + 4);
        ct += 8;
        pt += 8;
    }
    
    return CCERR_OK;
}

const struct ccmode_ecb ccdes_ltc_ecb_encrypt_mode = {
    .size = sizeof(ltc_des_keysched),
    .block_size = CCDES_BLOCK_SIZE,
    .init = ccdes_ltc_setup,
    .ecb = ltc_des_ecb_encrypt
};
