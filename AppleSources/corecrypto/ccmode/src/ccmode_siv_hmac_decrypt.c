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
#include "ccmode_internal.h"

int ccmode_siv_hmac_decrypt(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out)
{
    int rc = CCERR_OK;
    size_t block_size = _CCMODE_SIV_HMAC_CTR_MODE(ctx)->ecb_block_size;
    size_t tag_length = _CCMODE_SIV_HMAC_TAG_LENGTH(ctx);

    // Supports only 128-bit block ciphers.
    if (block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    uint8_t V[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t T[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t Q[16];
    const struct ccmode_ctr *ctr = _CCMODE_SIV_HMAC_CTR_MODE(ctx);
    
    // Sanity checks
    if ((_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_INIT) && (_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_AAD) &&
        (_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_NONCE)) {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }
    if (nbytes < tag_length) {
        return CCMODE_INVALID_INPUT; // Input is too small! Invalid/missing tag
    }
    
    // CTR encryption with IV V
    cc_memcpy(V, in, tag_length);
    cc_memcpy(Q, V, block_size);
    
    // Generate per message IV.
    uint8_t temp_key[CCSIV_MAX_KEY_BYTESIZE];
    if ((rc = ccmode_siv_hmac_temp_key_gen(ctx, temp_key, Q)) != 0) {
        goto errOut;
    }
    
    // Modify IV for SIV
    // The below modification 0's out the 32 and 64 bit in the CTR.
    // The SIV rfc introduces this so increments to the ctr can be done with a machine instruction on 32
    // and 64 bit machines if you can guarantee the increment length is less than 2^31 or 2^63 blocks respectively
    Q[8] &= 0x7F;
    Q[12] &= 0x7F;
    
    // Ctr encryption, may be called with data of size zero
    rc = ccctr_one_shot(ctr, _CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2, temp_key, Q, nbytes - tag_length, in + tag_length, out);
    
    // Compute integrity tag
    rc |= ccmode_siv_hmac_auth_finalize(ctx, nbytes - tag_length, out, T);
    
    // Check integrity
    rc |= cc_cmp_safe(tag_length, T, V);
    
errOut:
    // Fail after decrypting data: erase the output
    if (rc) {
        cc_clear(nbytes - tag_length, out);
        cc_clear(tag_length, T);
        ccmode_siv_hmac_reset(ctx);  // Zero SIV_HMAC ctx tag, and reset state.
        rc = CCMODE_DECRYPTION_OR_VERIFICATION_ERR;
    }
    cc_clear(_CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2, temp_key);
    return rc;
}
