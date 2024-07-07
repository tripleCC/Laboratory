/* Copyright (c) (2022) Apple Inc. All rights reserved.
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

size_t ccsiv_context_size(const struct ccmode_siv *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->size;
}

size_t ccsiv_block_size(const struct ccmode_siv *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->block_size;
}

size_t ccsiv_ciphertext_size(const struct ccmode_siv *mode,
                             size_t plaintext_size)
{
    CC_ENSURE_DIT_ENABLED

    return plaintext_size + mode->cbc->block_size;
}

size_t ccsiv_plaintext_size(const struct ccmode_siv *mode,
                            size_t ciphertext_size)
{
    CC_ENSURE_DIT_ENABLED

    if (ciphertext_size<mode->cbc->block_size) {
        return 0; // error
    }
    return ciphertext_size - mode->cbc->block_size;
}

int ccsiv_init(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
               size_t key_byte_len, const uint8_t *key)
{
    CC_ENSURE_DIT_ENABLED

    return mode->init(mode, ctx, key_byte_len, key);
}

int ccsiv_set_nonce(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
                    size_t nbytes, const uint8_t *in)
{
    CC_ENSURE_DIT_ENABLED

    return mode->set_nonce(ctx, nbytes, in);
}

int ccsiv_aad(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
              size_t nbytes, const uint8_t *in)
{
    CC_ENSURE_DIT_ENABLED

    return mode->auth(ctx, nbytes, in);
}

int ccsiv_crypt(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
                size_t nbytes, const uint8_t *in, uint8_t *out)
{
    CC_ENSURE_DIT_ENABLED

    return mode->crypt(ctx, nbytes, in, out);
}

int ccsiv_reset(const struct ccmode_siv *mode, ccsiv_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    return mode->reset(ctx);
}

int ccsiv_one_shot(const struct ccmode_siv *mode,
                   size_t key_len, const uint8_t *key,
                   unsigned nonce_nbytes, const uint8_t* nonce,
                   unsigned adata_nbytes, const uint8_t* adata,
                   size_t in_nbytes, const uint8_t *in, uint8_t *out)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    ccsiv_ctx_decl(mode->size, ctx);
    rc=mode->init(mode, ctx, key_len, key);
    if (rc) {return rc;}
    rc=mode->set_nonce(ctx, nonce_nbytes, nonce);
    if (rc) {return rc;}
    rc=mode->auth(ctx, adata_nbytes, adata);
    if (rc) {return rc;}
    rc=mode->crypt(ctx, in_nbytes, in, out);
    if (rc) {return rc;}
    ccsiv_ctx_clear(mode->size, ctx);
    return rc;
}
