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

#include <corecrypto/ccmode_siv_hmac.h>
#include "ccmode_siv_internal.h"
#include "ccmode_siv_hmac_internal.h"
#include "ccmode_internal.h"
#include <corecrypto/cc_priv.h>

int ccmode_siv_hmac_encrypt(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out)
{
    size_t tag_length = _CCMODE_SIV_HMAC_TAG_LENGTH(ctx);
    size_t block_size = _CCMODE_SIV_HMAC_CTR_MODE(ctx)->ecb_block_size;

    // Supports only 128-bit block ciphers.
    if (block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    uint8_t V[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t Q[16];
    
    int rc;
    const struct ccmode_ctr *ctr = _CCMODE_SIV_HMAC_CTR_MODE(ctx);
    
    // Finalize S2V
    if ((rc = ccmode_siv_hmac_auth_finalize(ctx, nbytes, in, V)) != 0) {
        return rc;
    }
    
    // CTR encryption with IV V and key derived from V.
    cc_memcpy(Q, V, block_size);
    
    // Generate per message key.
    uint8_t temp_key[CCSIV_MAX_KEY_BYTESIZE];
    if ((rc = ccmode_siv_hmac_temp_key_gen(ctx, temp_key, Q)) != 0) {
        goto error_out;
    }
    
    // Modify IV for SIV
    Q[8] &= 0x7F;
    Q[12] &= 0x7F;
    
    // Ctr encryption, may be called with data of size zero
    if ((rc = ccctr_one_shot(ctr, _CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2, temp_key, Q, nbytes, in, out + tag_length)) != 0) {
        goto error_out;
    }
    cc_memcpy(out, V, tag_length);

error_out:
    if (rc) {
        cc_clear(nbytes + tag_length, out);
        cc_clear(tag_length, V);
        ccmode_siv_hmac_reset(ctx); // Zero SIV_HMAC ctx tag, and reset state.
    }
    cc_clear(_CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2, temp_key);
    return rc;
}
