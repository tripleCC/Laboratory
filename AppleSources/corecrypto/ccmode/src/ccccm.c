/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"
#include "ccmode_internal.h"

size_t ccccm_context_size(const struct ccmode_ccm *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->size;
}

size_t ccccm_block_size(const struct ccmode_ccm *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->block_size;
}

int ccccm_init(const struct ccmode_ccm *mode,
               ccccm_ctx *ctx,
               size_t key_len,
               const void *cc_sized_by(key_len) key)
{
    CC_ENSURE_DIT_ENABLED

    return mode->init(mode, ctx, key_len, key);
}

int ccccm_set_iv(const struct ccmode_ccm *mode,
                 ccccm_ctx *ctx,
                 ccccm_nonce *nonce_ctx,
                 size_t nonce_len,
                 const void *cc_sized_by(nonce_len) nonce,
                 size_t mac_size,
                 size_t auth_len,
                 size_t data_len)
{
    CC_ENSURE_DIT_ENABLED

    return mode->set_iv(ctx, nonce_ctx, nonce_len, nonce, mac_size, auth_len, data_len);
}

int ccccm_cbcmac(const struct ccmode_ccm *mode,
                 ccccm_ctx *ctx,
                 ccccm_nonce *nonce_ctx,
                 size_t nbytes,
                 const void *cc_sized_by(nbytes) in)
{
    CC_ENSURE_DIT_ENABLED

    return mode->cbcmac(ctx, nonce_ctx, nbytes, in);
}

int ccccm_aad(const struct ccmode_ccm *mode,
              ccccm_ctx *ctx,
              ccccm_nonce *nonce_ctx,
              size_t ad_nbytes,
              const uint8_t *cc_sized_by(ad_nbytes) ad)
{
    CC_ENSURE_DIT_ENABLED

    return mode->cbcmac(ctx, nonce_ctx, ad_nbytes, ad);
}

int ccccm_update(const struct ccmode_ccm *mode,
                 ccccm_ctx *ctx,
                 ccccm_nonce *nonce_ctx,
                 size_t nbytes,
                 const void *cc_sized_by(nbytes) in,
                 void *cc_sized_by(nbytes) out)
{
    CC_ENSURE_DIT_ENABLED

    return mode->ccm(ctx, nonce_ctx, nbytes, in, out);
}

int ccccm_encrypt(const struct ccmode_ccm *mode,
                  ccccm_ctx *ctx,
                  ccccm_nonce *nonce_ctx,
                  size_t nbytes,
                  const uint8_t *cc_sized_by(nbytes) plaintext,
                  uint8_t *cc_sized_by(nbytes) encrypted_plaintext)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(mode->enc_mode == true, CCMODE_INVALID_CALL_SEQUENCE);
    return mode->ccm(ctx, nonce_ctx, nbytes, plaintext, encrypted_plaintext);
}

int ccccm_decrypt(const struct ccmode_ccm *mode,
                  ccccm_ctx *ctx,
                  ccccm_nonce *nonce_ctx,
                  size_t nbytes,
                  const uint8_t *cc_sized_by(nbytes) encrypted_plaintext,
                  uint8_t *cc_sized_by(nbytes) plaintext)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(mode->enc_mode == false, CCMODE_INVALID_CALL_SEQUENCE);
    return mode->ccm(ctx, nonce_ctx, nbytes, encrypted_plaintext, plaintext);
}

int ccccm_finalize(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, void *cc_indexable mac)
{
    CC_ENSURE_DIT_ENABLED

    return mode->finalize(ctx, nonce_ctx, mac);
}

int ccccm_finalize_and_generate_tag(const struct ccmode_ccm *mode,
                                    ccccm_ctx *ctx,
                                    ccccm_nonce *nonce_ctx,
                                    uint8_t *cc_indexable mac)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(mode->enc_mode == true, CCMODE_INVALID_CALL_SEQUENCE);
    return mode->finalize(ctx, nonce_ctx, mac);
}

int ccccm_finalize_and_verify_tag(const struct ccmode_ccm *mode,
                                  ccccm_ctx *ctx,
                                  ccccm_nonce *nonce_ctx,
                                  const uint8_t *cc_indexable mac)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t outTag[CCM_MAX_TAG_SIZE];
    cc_require_or_return(mode->enc_mode == false, CCMODE_INVALID_CALL_SEQUENCE);
    int rc = mode->finalize(ctx, nonce_ctx, outTag);
    cc_require(rc == CCERR_OK, errOut);
    rc = cc_cmp_safe(CCMODE_CCM_KEY_MAC_LEN(nonce_ctx), outTag, mac) == 0 ? CCERR_OK : CCMODE_INTEGRITY_FAILURE;

    // If authentication failed, don't return the improperly computed tag
    if (rc!= CCERR_OK) {
        cc_clear(CCMODE_CCM_KEY_MAC_LEN(nonce_ctx), outTag);
    }
errOut:
    return rc;
}

int ccccm_reset(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx)
{
    CC_ENSURE_DIT_ENABLED

    return mode->reset(ctx, nonce_ctx);
}

int ccccm_one_shot(const struct ccmode_ccm *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   size_t nonce_len,
                   const void *cc_sized_by(nonce_len) nonce,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out,
                   size_t adata_len,
                   const void *cc_sized_by(adata_len) adata,
                   size_t mac_size,
                   void *cc_sized_by(mac_size) mac)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    ccccm_ctx_decl(mode->size, ctx);
    ccccm_nonce_decl(mode->nonce_size, nonce_ctx);
    rc = mode->init(mode, ctx, key_len, key);
    if (rc == 0) {
        rc = mode->set_iv(ctx, nonce_ctx, nonce_len, nonce, mac_size, adata_len, nbytes);
    }
    if (rc == 0) {
        rc = mode->cbcmac(ctx, nonce_ctx, adata_len, adata);
    }
    if (rc == 0) {
        rc = mode->ccm(ctx, nonce_ctx, nbytes, in, out);
    }
    if (rc == 0) {
        rc = mode->finalize(ctx, nonce_ctx, mac);
    }
    ccccm_ctx_clear(mode->size, ctx);
    ccccm_nonce_clear(mode->nonce_size, nonce_ctx);

    return rc;
}

int ccccm_one_shot_encrypt(const struct ccmode_ccm *mode,
                           size_t key_nbytes,
                           const uint8_t *cc_sized_by(key_nbytes) key,
                           size_t nonce_nbytes,
                           const uint8_t *cc_sized_by(nonce_nbytes) nonce,
                           size_t nbytes,
                           const uint8_t *cc_sized_by(nbytes) plaintext,
                           uint8_t *cc_sized_by(nbytes) encrypted_plaintext,
                           size_t adata_nbytes,
                           const uint8_t *cc_sized_by(adata_nbytes) adata,
                           size_t mac_tag_nbytes,
                           uint8_t *cc_sized_by(mac_tag_nbytes) mac_tag)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    cc_require_or_return(mode->enc_mode == true, CCMODE_INVALID_CALL_SEQUENCE);
    ccccm_ctx_decl(mode->size, ctx);
    ccccm_nonce_decl(mode->nonce_size, nonce_ctx);
    rc = mode->init(mode, ctx, key_nbytes, key);
    if (rc == 0) {
        rc = mode->set_iv(ctx, nonce_ctx, nonce_nbytes, nonce, mac_tag_nbytes, adata_nbytes, nbytes);
    }
    if (rc == 0) {
        rc = mode->cbcmac(ctx, nonce_ctx, adata_nbytes, adata);
    }
    if (rc == 0) {
        rc = mode->ccm(ctx, nonce_ctx, nbytes, plaintext, encrypted_plaintext);
    }
    if (rc == 0) {
        rc = mode->finalize(ctx, nonce_ctx, mac_tag);
    }
    ccccm_ctx_clear(mode->size, ctx);
    ccccm_nonce_clear(mode->nonce_size, nonce_ctx);

    return rc;
}

int ccccm_one_shot_decrypt(const struct ccmode_ccm *mode,
                           size_t key_nbytes,
                           const uint8_t *cc_sized_by(key_nbytes) key,
                           size_t nonce_nbytes,
                           const uint8_t *cc_sized_by(nonce_nbytes) nonce,
                           size_t nbytes,
                           const uint8_t *cc_sized_by(nbytes) encrypted_plaintext,
                           uint8_t *cc_sized_by(nbytes) plaintext,
                           size_t adata_nbytes,
                           const uint8_t *cc_sized_by(adata_nbytes) adata,
                           size_t mac_tag_nbytes,
                           const uint8_t *cc_sized_by(mac_tag_nbytes) mac_tag)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    cc_require_or_return(mode->enc_mode == false, CCMODE_INVALID_CALL_SEQUENCE);
    ccccm_ctx_decl(mode->size, ctx);
    ccccm_nonce_decl(mode->nonce_size, nonce_ctx);
    rc = mode->init(mode, ctx, key_nbytes, key);
    if (rc == 0) {
        rc = mode->set_iv(ctx, nonce_ctx, nonce_nbytes, nonce, mac_tag_nbytes, adata_nbytes, nbytes);
    }
    if (rc == 0) {
        rc = mode->cbcmac(ctx, nonce_ctx, adata_nbytes, adata);
    }
    if (rc == 0) {
        rc = mode->ccm(ctx, nonce_ctx, nbytes, encrypted_plaintext, plaintext);
    }
    if (rc == 0) {
        rc = ccccm_finalize_and_verify_tag(mode, ctx, nonce_ctx, mac_tag);
    }
    ccccm_ctx_clear(mode->size, ctx);
    ccccm_nonce_clear(mode->nonce_size, nonce_ctx);

    return rc;
}
