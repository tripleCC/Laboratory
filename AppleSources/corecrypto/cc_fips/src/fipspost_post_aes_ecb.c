/* Copyright (c) (2017-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include "cc_debug.h"
#include <corecrypto/ccaes.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_aes_ecb.h"

static const size_t key_nbytes = 16;
static const unsigned char valid_key[] = "\xe6\x80\x74\x7f\x14\xe8\xa6\xee\x00\xbb\xa6\xbd\x65\x57\xae\x51";
static const unsigned char invalid_key[] = "\x01\xe6\x80\x74\x7f\x14\xe8\xa6\xee\x00\xbb\xa6\xbd\x65\x57\xae";

static const unsigned char plaintext_data[] = "\x7f\xea\x96\xf9\x0f\xba\xe1\x2a\x85\x7f\x5c\x97\xe0\xcb\xa5\x79";
static const unsigned char ciphertext_data[] = "\x3d\x30\xe6\x36\x45\x85\x46\x16\x71\xaa\x67\x10\x26\xb2\xec\xd9";

CC_INLINE int fipspost_post_aes_ecb_encrypt(uint32_t fips_mode)
{
    const struct ccmode_ecb *ecb_mode = ccaes_ecb_encrypt_mode();
    unsigned char output[16];

    const unsigned char *key = (const unsigned char *)valid_key;
    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        key = (const unsigned char *)invalid_key;
    }

    if (ccecb_one_shot(ecb_mode, key_nbytes, key, 1, plaintext_data, output)) {
        failf("aes_ecb_encrypt one_shot");
        return CCPOST_LIBRARY_ERROR;
    }

    if (cc_cmp_safe(sizeof(output), output, ciphertext_data)) {
        failf("aes_ecb_encrypt cmp");
        return CCPOST_KAT_FAILURE;
    }

    return CCERR_OK;
}

CC_INLINE int fipspost_post_aes_ecb_decrypt(uint32_t fips_mode)
{
    const struct ccmode_ecb *ecb_mode = ccaes_ecb_decrypt_mode();
    unsigned char output[16];

    const unsigned char *key = (const unsigned char *)valid_key;
    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        key = (const unsigned char *)invalid_key;
    }

    if (ccecb_one_shot(ecb_mode, key_nbytes, key, 1, ciphertext_data, output)) {
        failf("aes_ecb_decrypt one_shot");
        return CCPOST_LIBRARY_ERROR;
    }

    if (cc_cmp_safe(sizeof(output), output, plaintext_data)) {
        failf("aes_ecb_decrypt cmp");
        return CCPOST_KAT_FAILURE;
    }

    return CCERR_OK;
}

int fipspost_post_aes_ecb(uint32_t fips_mode)
{
    int ret_e = fipspost_post_aes_ecb_encrypt(fips_mode);
    int ret_d = fipspost_post_aes_ecb_decrypt(fips_mode);

    return ret_e | ret_d;
}
