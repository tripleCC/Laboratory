/* Copyright (c) (2017-2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_drbg_trng.h"

#include "ccdrbg_internal.h"
#include <corecrypto/ccaes.h>

/*
* The result of ccdrbg_generate is:
*     drbg.init(entropy, perso)
*     drbg.reseed(entropy_reseed1 or "0...0")
*     drbg.generate()
*     drbg.reseed(entropy_reseed2 or "0...0")
*     return drbg.generate()
*
* When no entropy is provided for the reseed, or ccdrbg_trng_reseed is not called, 384 0-bits are
* used for the reseed.
*
* Any calls to ccdrbg_generate passes all the data (entropy, perso, entropy_reseed1,
* entropy_reseed2) to the IP, then the IP computes the result and it is retrieved by
* ccdrbg_generate.
*/


int fipspost_post_drbg_trng(uint32_t fips_mode)
{
const uint8_t *entropy = (const uint8_t *)
            "\x05\x6d\xcd\xe5\x4a\x18\x17\xa7\x76\x07\xf0\x1f\x2c\x37\xb0\x1f"
            "\x51\xf2\xa9\xb6\x85\xa0\x05\x50\xbc\x31\x29\x3a\x71\x3e\x08\xb3"
            "\xd2\x1b\x8e\x63\x94\x41\xc0\x4a\xf6\xb2\x14\xf8\x4c\x38\x7b\x6b";
const uint8_t *pers_str = (const uint8_t *)
            "\xcd\x53\x1a\x46\x92\x09\x66\x00\x6f\x2c\x33\xe8\x44\xb9\xc6\x39"
            "\xaf\x43\x43\xf3\x58\x25\x1d\x58\xb4\x79\x64\x53\xcd\x78\x0c\xdf"
            "\xa8\xda\x1d\xfa\xcc\x26\xeb\x3f\x64\xb0\x40\xcc\xc6\x38\x00\x2a";
const uint8_t *entropy_reseed_1 = (const uint8_t *)
            "\xbe\xda\x17\x7e\x59\xbc\xc2\x59\x63\x72\x16\x51\x9e\x9b\xc4\x6c"
            "\xcf\xd5\xab\xb2\xe3\x2b\x2e\x4f\x3e\xa8\xe3\xdf\xb5\xde\x9d\xb8"
            "\x8c\x29\x74\xc4\x1d\x01\x1f\x58\xa8\xfe\xc3\x55\x9d\x7d\xed\xb0";
const uint8_t *entropy_reseed_2 = (const uint8_t *)
            "\x72\xa2\xb8\x1e\x7d\xb6\x95\xb1\xc1\xcc\xa1\x13\xd7\x92\x92\xf8"
            "\x98\x01\x7e\x39\xe9\xdb\x34\xbc\xa3\x95\x47\xf8\xf1\x7d\x8e\x97"
            "\x29\x20\xe3\xc7\x9d\xc7\x80\x7d\xf6\xec\x5a\x7b\xe9\xf8\xc2\x8a";
const uint8_t *expected_output = (const uint8_t *)POST_FIPS_RESULT_STR(
            "\xf6\x40\x24\x2d\xdd\x34\xe9\xe1\x31\xe7\x13\x03\x7b\x18\x34\xb7");

    int32_t ret;
    uint8_t output[CCAES_BLOCK_SIZE];

    struct ccdrbg_info info;
    ccdrbg_factory_trng(&info);
    uint8_t state[ccdrbg_context_size(&info)];
    struct ccdrbg_state *drbg = (struct ccdrbg_state *)state;

    ret = ccdrbg_init(&info, drbg, CCDRBG_TRNG_VECTOR_LEN, entropy, 0, NULL,
            CCDRBG_TRNG_VECTOR_LEN, pers_str);
    if (ret != 0) {
        failf("failed ccdrbg_init: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    ret = ccdrbg_reseed(&info, drbg, CCDRBG_TRNG_VECTOR_LEN, entropy_reseed_1, 0, NULL);
    if (ret != 0) {
        failf("failed ccdrbg_reseed(1): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    ret = ccdrbg_reseed(&info, drbg, CCDRBG_TRNG_VECTOR_LEN, entropy_reseed_2, 0, NULL);
    if (ret != 0) {
        failf("failed ccdrbg_reseed(2): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    ret = ccdrbg_generate(&info, drbg, CCAES_BLOCK_SIZE, output, 0, NULL);
    if (ret != 0) {
        failf("failed ccdrbg_generate: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    return memcmp(expected_output, output, CCAES_BLOCK_SIZE) == 0 ? 0 : CCPOST_KAT_FAILURE;
}
