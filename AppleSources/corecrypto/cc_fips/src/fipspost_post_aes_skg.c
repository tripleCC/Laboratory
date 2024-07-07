/* Copyright (c) (2017,2019,2021) Apple Inc. All rights reserved.
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
#include "fipspost_post_aes_skg.h"

#include <stdbool.h>

#include <corecrypto/ccaes.h> // for CCAES_BLOCK_SIZE

CC_WARN_RESULT
static int fipspost_post_aes_skg_oneshot(bool enc, bool cbc,
        size_t key_len, const uint8_t *key,
        size_t iv_len, const uint8_t *iv,
        size_t input_len, const uint8_t *input,
        const uint8_t *output)
{
    const void *ccmode;
    uint8_t result[CCAES_BLOCK_SIZE];

    if (input_len != CCAES_BLOCK_SIZE) {
        failf("invalid input length: %zu", input_len);
        return CCPOST_GENERIC_FAILURE;
    }

    if (iv_len != 0 && iv_len != CCAES_BLOCK_SIZE) {
        failf("invalid iv length: %zu", iv_len);
    }

    if (cbc) {
        if (enc) {
            ccmode = &ccaes_skg_cbc_encrypt_mode;
        } else {
            ccmode = &ccaes_skg_cbc_decrypt_mode;
        }
        cccbc_one_shot(ccmode, key_len, key, iv,
                input_len / cccbc_block_size(ccmode), input, result);
    } else {
        if (enc) {
            ccmode = &ccaes_skg_ecb_encrypt_mode;
        } else {
            ccmode = &ccaes_skg_ecb_decrypt_mode;
        }
        ccecb_one_shot(ccmode, key_len, key,
                input_len / ccecb_block_size(ccmode), input, result);
    }

    if (memcmp(output, result, CCAES_BLOCK_SIZE) != 0) {
        failf("result mismatch");
        return CCPOST_KAT_FAILURE;
    }

    return 0;
}

int fipspost_post_aes_skg_enc_cbc_128(uint32_t fips_mode)
{
    // AES 128 Encryption Test Data
    uint8_t *key = (uint8_t *)
            "\x34\x49\x1b\x26\x6d\x8f\xb5\x4c\x5c\xe1\xa9\xfb\xf1\x7b\x09\x8c";
    uint8_t *iv = (uint8_t *)
            "\x9b\xc2\x0b\x29\x51\xff\x72\xd3\xf2\x80\xff\x3b\xd2\xdc\x3d\xcc";
    uint8_t *input = (uint8_t *)
            "\x06\xfe\x99\x71\x63\xcb\xcb\x55\x85\x3e\x28\x57\x74\xcc\xa8\x9d";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x32\x5d\xe3\x14\xe9\x29\xed\x08\x97\x87\xd0\xa2\x05\xd1\xeb\x33");

    return fipspost_post_aes_skg_oneshot(true, true, CCAES_KEY_SIZE_128, key,
            CCAES_BLOCK_SIZE, iv, CCAES_BLOCK_SIZE, input, output);
}

int fipspost_post_aes_skg_dec_cbc_128(uint32_t fips_mode)
{
    // AES 128 Decryption Test Data
    uint8_t *key = (uint8_t *)
            "\xc6\x8e\x4e\xb2\xca\x2a\xc5\xaf\xee\xac\xad\xea\xa3\x97\x11\x94";
    uint8_t *iv = (uint8_t *)
            "\x11\xdd\x9d\xa1\xbd\x22\x3a\xcf\x68\xc5\xa1\xe1\x96\x4c\x18\x9b";
    uint8_t *input = (uint8_t *)
            "\xaa\x36\x57\x9b\x0c\x72\xc5\x28\x16\x7b\x70\x12\xd7\xfa\xf0\xde";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x9e\x66\x1d\xb3\x80\x39\x20\x9a\x72\xc7\xd2\x96\x40\x66\x88\xf2");

    return fipspost_post_aes_skg_oneshot(false, true, CCAES_KEY_SIZE_128, key,
            CCAES_BLOCK_SIZE, iv, CCAES_BLOCK_SIZE, input, output);
}

int fipspost_post_aes_skg_enc_ecb_128(uint32_t fips_mode)
{
    // AES 128 Encryption Test Data
    uint8_t *key = (uint8_t *)
            "\xe6\x80\x74\x7f\x14\xe8\xa6\xee\x00\xbb\xa6\xbd\x65\x57\xae\x51";
    uint8_t *input = (uint8_t *)
            "\x7f\xea\x96\xf9\x0f\xba\xe1\x2a\x85\x7f\x5c\x97\xe0\xcb\xa5\x79";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x3d\x30\xe6\x36\x45\x85\x46\x16\x71\xaa\x67\x10\x26\xb2\xec\xd9");

    return fipspost_post_aes_skg_oneshot(true, false, CCAES_KEY_SIZE_128, key,
            0, NULL, CCAES_BLOCK_SIZE, input, output);
}

int fipspost_post_aes_skg_dec_ecb_128(uint32_t fips_mode)
{
    // AES 128 Decryption Test Data
    uint8_t *key = (uint8_t *)
            "\xe6\x80\x74\x7f\x14\xe8\xa6\xee\x00\xbb\xa6\xbd\x65\x57\xae\x51";
    uint8_t *input = (uint8_t *)
            "\x3d\x30\xe6\x36\x45\x85\x46\x16\x71\xaa\x67\x10\x26\xb2\xec\xd9";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x7f\xea\x96\xf9\x0f\xba\xe1\x2a\x85\x7f\x5c\x97\xe0\xcb\xa5\x79");

    return fipspost_post_aes_skg_oneshot(false, false, CCAES_KEY_SIZE_128, key,
            0, NULL, CCAES_BLOCK_SIZE, input, output);
}
