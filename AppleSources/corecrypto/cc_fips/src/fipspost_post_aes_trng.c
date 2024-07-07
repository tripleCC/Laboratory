/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
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
#include "fipspost_post_aes_trng.h"

#include <corecrypto/ccaes.h>

int fipspost_post_aes_trng(uint32_t fips_mode)
{
    uint8_t *key = (uint8_t *)
            "\xc4\x7b\x02\x94\xdb\xbb\xee\x0f\xec\x47\x57\xf2\x2f\xfe\xee\x35"
            "\x87\xca\x47\x30\xc3\xd3\x3b\x69\x1d\xf3\x8b\xab\x07\x6b\xc5\x58";
    uint8_t *input = (uint8_t *)
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t *expected_output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x46\xf2\xfb\x34\x2d\x6f\x0a\xb4\x77\x47\x6f\xc5\x01\x24\x2c\x5f");
    uint8_t output[CCAES_BLOCK_SIZE];

	ccecb_one_shot(&ccaes_trng_ecb_encrypt_mode, CCAES_KEY_SIZE_256, key,
            1, input, output);

    return memcmp(expected_output, output, CCAES_BLOCK_SIZE) == 0 ? 0 : CCPOST_KAT_FAILURE;
}
