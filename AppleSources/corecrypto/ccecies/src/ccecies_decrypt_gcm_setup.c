/* Copyright (c) (2014,2015,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccecies.h>
#include "ccecies_internal.h"

int ccecies_decrypt_gcm_setup(ccecies_gcm_t ecies, /* output */
                              const struct ccdigest_info *di,
                              const struct ccmode_gcm *gcm_dec,
                              uint32_t cipher_key_size,
                              uint32_t mac_tag_size,
                              uint32_t options)
{
    CC_ENSURE_DIT_ENABLED

    ecies->di = di;
    ecies->gcm = gcm_dec;
    ecies->options = options;
    ecies->key_length = cipher_key_size;
    ecies->mac_length = mac_tag_size;
    ecies->rng = ccrng(NULL);

    if (!ecies->rng) {
        return CCERR_INTERNAL;
    }

    if (gcm_dec->encdec != CCMODE_GCM_DECRYPTOR) {
        return CCERR_CRYPTO_CONFIG;
    }

    if (cipher_key_size != CCAES_KEY_SIZE_128 &&
        cipher_key_size != CCAES_KEY_SIZE_192 &&
        cipher_key_size != CCAES_KEY_SIZE_256) {
        return CCERR_CRYPTO_CONFIG;
    }

    if (mac_tag_size < CCECIES_CIPHER_TAG_MIN_NBYTES ||
        mac_tag_size > CCECIES_CIPHER_TAG_MAX_NBYTES) {
        return CCERR_CRYPTO_CONFIG;
    }

    return CCERR_OK;
}
