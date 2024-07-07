/* Copyright (c) (2017-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdes.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_tdes_ecb.h"

static const size_t key_nbytes = 24;
static const unsigned char valid_key[] =
    "\x5e\xe4\xdb\x0c\xdf\xdf\x71\x9e\x40\xfc\x96\x2d\x2f\x31\xf4\x16\xd9\xaa\x0f\x22\x8d\x89\xe0\x7f";
static const unsigned char invalid_key[] =
    "\x01\x5e\xe4\xdb\x0c\xdf\xdf\x71\x9e\x40\xfc\x96\x2d\x2f\x31\xf4\x16\xd9\xaa\x0f\x22\x8d\x89\xe0";

static const unsigned char plaintext_data[] = "\x7f\xea\x96\xf9\x0f\xba\xe1\x2a";
static const unsigned char ciphertext_data[] = "\x10|\x15\xf8\xdd\xf1|\xf5";

CC_WARN_RESULT
static int fipspost_post_tdes_ecb_decrypt(uint32_t fips_mode)
{
    uint8_t output[8];
    const struct ccmode_ecb *ecb_mode = ccdes3_ecb_decrypt_mode();

    const unsigned char *key = (const unsigned char *)valid_key;
    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        key = (const unsigned char *)invalid_key;
    }

    if (ccecb_one_shot(ecb_mode, key_nbytes, key, 1, ciphertext_data, output)) {
        failf("des3_ecb_decrypt one_shot");
        return CCPOST_LIBRARY_ERROR;
    }

    if (cc_cmp_safe(sizeof(output), output, plaintext_data)) {
        failf("des3_ecb_decrypt cmp");
        return CCPOST_KAT_FAILURE;
    }

    return CCERR_OK;
}

int fipspost_post_tdes_ecb(uint32_t fips_mode)
{
    int ret_d = fipspost_post_tdes_ecb_decrypt(fips_mode);
    return ret_d;
}
