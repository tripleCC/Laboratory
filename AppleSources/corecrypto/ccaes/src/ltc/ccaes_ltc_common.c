/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

//  Created on 7/16/18.
//

#include "ccaes_internal.h"
#include <corecrypto/cc_error.h>
#include "cc_macros.h"

#include "ccaes_ltc_common.h"
#include "ccaes_ltc_tab.h"
#include "cc_internal.h"

static uint32_t setup_mix(uint32_t temp)
{
    return Te4_3[cc_byte(temp, 1)] ^ Te4_2[cc_byte(temp, 2)] ^ Te4_1[cc_byte(temp, 3)] ^ Te4_0[cc_byte(temp, 0)];
}

/*!
 Initialize the AES (Rijndael) block cipher
 @param key The symmetric key you wish to pass
 @param keylen The key length in bytes
 @param num_rounds The number of rounds desired (0 for default)
 @param skey The key in as scheduled by this function.
 @return CRYPT_OK if successful
 */
static int ccaes_ltc_init(const unsigned char *key, int keylen, int num_rounds, ccecb_ctx *skey)
{
    int j;
    uint32_t i, temp, *rk;
#ifndef ENCRYPT_ONLY
    uint32_t *rrk;
#endif
    ltc_rijndael_keysched *rijndael;

    rijndael = (ltc_rijndael_keysched *)skey;

    int rc = ccaes_key_length_validation((size_t)keylen);
    cc_require_or_return(rc == CCERR_OK, rc);
    keylen = (int) ccaes_key_length_to_nbytes((size_t)keylen);
    
    if (num_rounds != 0 && num_rounds != (10 + ((keylen / 8) - 2) * 2)) {
        return -1; // CRYPT_INVALID_ROUNDS;
    }

    rijndael->enc.rn = rijndael->dec.rn = (10 + (((uint32_t)keylen / 8) - 2) * 2) * 16;

    /* setup the forward key */
    i = 0;
    rk = rijndael->enc.ks;
    rk[0] = cc_load32_le(key + 0);
    rk[1] = cc_load32_le(key + 4);
    rk[2] = cc_load32_le(key + 8);
    rk[3] = cc_load32_le(key + 12);
    if (keylen == 16) {
        j = 44;
        for (;;) {
            temp = rk[3];
            rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                break;
            }
            rk += 4;
        }
    } else if (keylen == 24) {
        j = 52;
        rk[4] = cc_load32_le(key + 16);
        rk[5] = cc_load32_le(key + 20);
        for (;;) {
#ifdef _MSC_VER
            temp = rijndael->enc.ks[rk - rijndael->enc.ks + 5];
#else
            temp = rk[5];
#endif
            rk[6] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[7] = rk[1] ^ rk[6];
            rk[8] = rk[2] ^ rk[7];
            rk[9] = rk[3] ^ rk[8];
            if (++i == 8) {
                break;
            }
            rk[10] = rk[4] ^ rk[9];
            rk[11] = rk[5] ^ rk[10];
            rk += 6;
        }
    } else /* (keylen == 32) */ {
        j = 60;
        rk[4] = cc_load32_le(key + 16);
        rk[5] = cc_load32_le(key + 20);
        rk[6] = cc_load32_le(key + 24);
        rk[7] = cc_load32_le(key + 28);
        for (;;) {
#ifdef _MSC_VER
            temp = rijndael->enc.ks[rk - rijndael->enc.ks + 7];
#else
            temp = rk[7];
#endif
            rk[8] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[9] = rk[1] ^ rk[8];
            rk[10] = rk[2] ^ rk[9];
            rk[11] = rk[3] ^ rk[10];
            if (++i == 7) {
                break;
            }
            temp = rk[11];
            rk[12] = rk[4] ^ setup_mix(CC_ROLc(temp, 8));
            rk[13] = rk[5] ^ rk[12];
            rk[14] = rk[6] ^ rk[13];
            rk[15] = rk[7] ^ rk[14];
            rk += 8;
        }
    }

#ifndef ENCRYPT_ONLY
    /* setup the inverse key now */
    rk = rijndael->dec.ks;
    rrk = rijndael->enc.ks + j - 4;

    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    /* copy first */
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk = *rrk;
    rk -= 3;
    rrk -= 3;

    for (i = 1; i < rijndael->dec.rn / 16; i++) {
        rrk -= 4;
        rk += 4;

        temp = rrk[0];
        rk[0] = Tks0[cc_byte(temp, 0)] ^ Tks1[cc_byte(temp, 1)] ^ Tks2[cc_byte(temp, 2)] ^ Tks3[cc_byte(temp, 3)];
        temp = rrk[1];
        rk[1] = Tks0[cc_byte(temp, 0)] ^ Tks1[cc_byte(temp, 1)] ^ Tks2[cc_byte(temp, 2)] ^ Tks3[cc_byte(temp, 3)];
        temp = rrk[2];
        rk[2] = Tks0[cc_byte(temp, 0)] ^ Tks1[cc_byte(temp, 1)] ^ Tks2[cc_byte(temp, 2)] ^ Tks3[cc_byte(temp, 3)];
        temp = rrk[3];
        rk[3] = Tks0[cc_byte(temp, 0)] ^ Tks1[cc_byte(temp, 1)] ^ Tks2[cc_byte(temp, 2)] ^ Tks3[cc_byte(temp, 3)];
    }

    /* copy last */
    rrk -= 4;
    rk += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk = *rrk;
#endif /* ENCRYPT_ONLY */

    return 0; // CRYPT_OK;
}

int ccaes_ecb_encrypt_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key, size_t rawkey_len, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_len);
    cc_require_or_return(rc == CCERR_OK, rc);
    return ccaes_ltc_init(rawkey, (int)rawkey_len, 0, key);
}

int ccaes_ecb_decrypt_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key, size_t rawkey_len, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_len);
    cc_require_or_return(rc == CCERR_OK, rc);
    return ccaes_ltc_init(rawkey, (int)rawkey_len, 0, key);
}

void ccaes_ecb_encrypt_roundkey(const ccecb_ctx *ctx, unsigned i, void *roundkey)
{
    const ltc_rijndael_keysched *skey = (const ltc_rijndael_keysched *)ctx;
    cc_memcpy(roundkey, &skey->enc.ks[i * 4], CCAES_ROUNDKEY_SIZE);
}
