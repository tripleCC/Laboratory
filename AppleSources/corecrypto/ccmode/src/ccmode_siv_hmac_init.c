/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode_siv_hmac.h>
#include "ccmode_siv_hmac_internal.h"
#include "ccmode_internal.h"
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

int ccmode_siv_hmac_init(const struct ccmode_siv_hmac *siv_hmac,
                         ccsiv_hmac_ctx *siv_hmac_ctx,
                         size_t rawkey_byte_len,
                         const uint8_t *rawkey,
                         size_t tag_length)
{
    _CCMODE_SIV_HMAC_CTX(siv_hmac_ctx)->siv_hmac = siv_hmac;
    
    // Check if the key size is valid and set key
    if ((rawkey_byte_len > CCSIV_HMAC_MAX_KEY_BYTESIZE) // Too big for structure
        || ((rawkey_byte_len != 32)                     // Not compliant with spec
            && (rawkey_byte_len != 48) && (rawkey_byte_len != 64))) {
            return CCMODE_NOT_SUPPORTED;
        }
    if (rawkey_byte_len / 2 > _CCMODE_SIV_HMAC_DIGEST(siv_hmac_ctx)->state_size) {
        return CCMODE_NOT_SUPPORTED; // Prevent instantiation where the HMAC Key is larger than its internal state
        // to prevent callers from thinking they have more security than they actually do.
    }
    // Ensure that tag is not longer than hmac output, which is the digest output
    if (tag_length > _CCMODE_SIV_HMAC_DIGEST(siv_hmac_ctx)->output_size) {
        return CCMODE_TAG_LENGTH_REQUEST_TOO_LONG;
    }
    // Ensure that tag is no shorter than an acceptible collision resistant length: 160 bits currently.
    if (tag_length < _CCMODE_SIV_HMAC_MINIMUM_ACCEPTABLE_COLLISION_RESISTANT_TAG_LENGTH) {
        return CCMODE_TAG_LENGTH_TOO_SHORT;
    }
    // Current version only supports 128 bit block-size
    if (_CCMODE_SIV_HMAC_CTR_MODE(siv_hmac_ctx)->ecb_block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }
    
    _CCMODE_SIV_HMAC_KEYSIZE(siv_hmac_ctx) = rawkey_byte_len;
    cc_memcpy(_CCMODE_SIV_HMAC_CTR_KEY(siv_hmac_ctx), rawkey, rawkey_byte_len / 2);                         // Save MAC key
    cc_memcpy(_CCMODE_SIV_HMAC_MAC_KEY(siv_hmac_ctx), rawkey + (rawkey_byte_len / 2), rawkey_byte_len / 2); // Save CTR key
    _CCMODE_SIV_HMAC_TAG_LENGTH(siv_hmac_ctx) = tag_length;
    return ccmode_siv_hmac_reset(siv_hmac_ctx);
}
