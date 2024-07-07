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

#include "cc_internal.h"
#include <corecrypto/ccmode.h>
#include "ccmode_siv_hmac_internal.h"

size_t ccsiv_hmac_context_size(const struct ccmode_siv_hmac *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->size;
}

size_t ccsiv_hmac_block_size(const struct ccmode_siv_hmac *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->block_size;
}

size_t ccsiv_hmac_ciphertext_size(ccsiv_hmac_ctx *ctx, size_t plaintext_size)
{
    CC_ENSURE_DIT_ENABLED

    return plaintext_size + _CCMODE_SIV_HMAC_TAG_LENGTH(ctx);
}

size_t ccsiv_hmac_plaintext_size(ccsiv_hmac_ctx *ctx, size_t ciphertext_size)
{
    CC_ENSURE_DIT_ENABLED

    if (ciphertext_size < _CCMODE_SIV_HMAC_TAG_LENGTH(ctx)) {
        return 0; // No attached plaintext.
    }
    return ciphertext_size - _CCMODE_SIV_HMAC_TAG_LENGTH(ctx);
}

int ccsiv_hmac_init(const struct ccmode_siv_hmac *mode,
                    ccsiv_hmac_ctx *ctx,
                    size_t key_byte_len,
                    const uint8_t *key,
                    size_t tag_size)
{
    CC_ENSURE_DIT_ENABLED

    return mode->init(mode, ctx, key_byte_len, key, tag_size);
}

int ccsiv_hmac_aad(const struct ccmode_siv_hmac *mode, ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in)
{
    CC_ENSURE_DIT_ENABLED

    return mode->auth(ctx, nbytes, in);
}

int ccsiv_hmac_set_nonce(const struct ccmode_siv_hmac *mode, ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in)
{
    CC_ENSURE_DIT_ENABLED

    return mode->set_nonce(ctx, nbytes, in);
}

int ccsiv_hmac_crypt(const struct ccmode_siv_hmac *mode, ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out)
{
    CC_ENSURE_DIT_ENABLED

    return mode->crypt(ctx, nbytes, in, out);
}

int ccsiv_hmac_reset(const struct ccmode_siv_hmac *mode, ccsiv_hmac_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    return mode->reset(ctx);
}

int ccsiv_hmac_one_shot(const struct ccmode_siv_hmac *mode,
                        size_t key_len,
                        const uint8_t *key,
                        size_t tag_length,
                        unsigned nonce_nbytes,
                        const uint8_t *nonce,
                        unsigned adata_nbytes,
                        const uint8_t *adata,
                        size_t in_nbytes,
                        const uint8_t *in,
                        uint8_t *out)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    ccsiv_hmac_ctx_decl(mode->size, ctx);
    rc = mode->init(mode, ctx, key_len, key, tag_length);
    if (rc) {
        return rc;
    }
    
    if (adata_nbytes) {
        rc = mode->auth(ctx, adata_nbytes, adata);
    }
    if (rc) {
        return rc;
    }
    
    if (nonce_nbytes) {
        rc = mode->set_nonce(ctx, nonce_nbytes, nonce);
    }
    if (rc) {
        return rc;
    }
    
    rc = mode->crypt(ctx, in_nbytes, in, out);
    if (rc) {
        return rc;
    }
    ccsiv_hmac_ctx_clear(mode->size, ctx);
    return rc;
}
