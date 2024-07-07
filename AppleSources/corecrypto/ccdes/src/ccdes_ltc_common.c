/* Copyright (c) (2010,2011,2015,2016,2019) Apple Inc. All rights reserved.
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
#include "ltc_des.h"

/*!
 Initialize the LTC_DES block cipher
 @param key The symmetric key you wish to pass
 @param keylen The key length in bytes
 @param num_rounds The number of rounds desired (0 for default)
 @param skey The key in as scheduled by this function.
 @return CRYPT_OK if successful
 */
static int ltc_des_setup(const unsigned char *key, size_t keylen, int num_rounds,
                        ccecb_ctx *skey)
{
    ltc_des_keysched *des;

    des = (ltc_des_keysched *)skey;

    if (num_rounds != 0 && num_rounds != 16) {
        return -1; /* CRYPT_INVALID_ROUNDS; */
    }

     if (keylen != 8) {
        return -1; /* CRYPT_INVALID_KEYSIZE; */
    }

    deskey(key, EN0, des->ek);
    deskey(key, DE1, des->dk);

    return 0; /* CRYPT_OK; */
}

int ccdes_ltc_setup(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                    size_t rawkey_len, const void *rawkey)
{
    return ltc_des_setup(rawkey, rawkey_len, 0, key);
}
