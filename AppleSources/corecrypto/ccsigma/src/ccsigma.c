/* Copyright (c) (2020,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccmode.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccsigma_priv.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccnistkdf.h>

int ccsigma_init(const struct ccsigma_info *info,
                 struct ccsigma_ctx *ctx,
                 ccsigma_role_t role,
                 struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ctx->info = info;
    ctx->role = role;

    ccec_full_ctx_t kex_ctx = ctx->info->key_exchange.ctx(ctx);
    return ccec_generate_key_fips(info->key_exchange.curve_params, rng, kex_ctx);
}

static int ccsigma_sign_internal(void *ctx,
                                 size_t digest_nbytes,
                                 const void *digest,
                                 size_t *signature_nbytes,
                                 void *signature,
                                 struct ccrng_state *rng)
{
    struct ccsigma_ctx *sigma_ctx = ctx;
    ccec_full_ctx_t sign_ctx = sigma_ctx->info->signature.ctx(sigma_ctx);
    int err = CCERR_PARAMETER;

    cc_require(*signature_nbytes >= sigma_ctx->info->signature.signature_size, out);
    *signature_nbytes = sigma_ctx->info->signature.signature_size;

    uint8_t *r = signature;
    uint8_t *s = r + ccec_signature_r_s_size(ccec_ctx_pub(sign_ctx));

    err = ccec_sign_composite(sign_ctx, digest_nbytes, digest, r, s, rng);

 out:
    return err;
}

int ccsigma_import_signing_key(struct ccsigma_ctx *ctx,
                               size_t signing_key_size,
                               const void *signing_key)
{
    CC_ENSURE_DIT_ENABLED

    ccec_full_ctx_t sign_ctx = ctx->info->signature.ctx(ctx);
    int err = ccec_x963_import_priv(ctx->info->signature.curve_params,
                                    signing_key_size,
                                    signing_key,
                                    sign_ctx);
    cc_require(err == CCERR_OK, out);

    err = ccsigma_set_signing_function(ctx, ccsigma_sign_internal, ctx);

 out:
    return err;
}

int ccsigma_set_signing_function(struct ccsigma_ctx *ctx,
                                 ccsigma_sign_fn_t sign_fn,
                                 void *sign_ctx)
{
    CC_ENSURE_DIT_ENABLED

    ctx->sign_fn = sign_fn;
    ctx->sign_ctx = sign_ctx;

    return CCERR_OK;
}

int ccsigma_import_peer_verification_key(struct ccsigma_ctx *ctx,
                                         size_t peer_verification_key_size,
                                         const void *peer_verification_key)
{
    CC_ENSURE_DIT_ENABLED

    ccec_pub_ctx_t verify_ctx = ctx->info->signature.peer_ctx(ctx);
    return ccec_x963_import_pub(ctx->info->signature.curve_params,
                                peer_verification_key_size,
                                peer_verification_key,
                                verify_ctx);
}

int ccsigma_export_key_share(struct ccsigma_ctx *ctx,
                             size_t *key_share_size,
                             void *key_share)
{
    CC_ENSURE_DIT_ENABLED

    int err = CCERR_PARAMETER;

    size_t size = ccec_compressed_x962_export_pub_size(ctx->info->key_exchange.curve_params);
    cc_require(*key_share_size >= size, out);

    *key_share_size = size;

    ccec_full_ctx_t kex_ctx = ctx->info->key_exchange.ctx(ctx);
    err = ccec_compressed_x962_export_pub(ccec_ctx_pub(kex_ctx), key_share);

 out:
    if (err != CCERR_OK) {
        cc_clear(*key_share_size, key_share);
    }

    return err;
}

int ccsigma_import_peer_key_share(struct ccsigma_ctx *ctx,
                                  size_t peer_key_share_size,
                                  void *peer_key_share)
{
    CC_ENSURE_DIT_ENABLED

    ccec_pub_ctx_t peer_kex_ctx = ctx->info->key_exchange.peer_ctx(ctx);
    return ccec_compressed_x962_import_pub(ctx->info->key_exchange.curve_params,
                                           peer_key_share_size,
                                           peer_key_share,
                                           peer_kex_ctx);
}

static size_t ccsigma_shared_secret_size(const struct ccsigma_info *info)
{
    return ccec_cp_prime_size(info->key_exchange.curve_params);
}

static int ccsigma_session_key_lookup(struct ccsigma_ctx *ctx,
                                      size_t key_index,
                                      size_t *key_size,
                                      void **key)
{
    int err = CCERR_PARAMETER;

    cc_require(key_index < ctx->info->session_keys.count, out);

    size_t i;
    const size_t *key_info = ctx->info->session_keys.info;
    size_t offset = 0;
    for (i = 0; i < key_index; i += 1) {
        offset += key_info[i];
    }

    *key_size = key_info[i];
    *key = (uint8_t *)ctx->info->session_keys.buffer(ctx) + offset;
    err = CCERR_OK;

 out:
    return err;
}

ccsigma_role_t ccsigma_peer_role(struct ccsigma_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    if (ctx->role == CCSIGMA_ROLE_INIT) {
        return CCSIGMA_ROLE_RESP;
    } else {
        return CCSIGMA_ROLE_INIT;
    }
}

ccec_pub_ctx_t ccsigma_kex_init_ctx(struct ccsigma_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    if (ctx->role == CCSIGMA_ROLE_INIT) {
        return ccec_ctx_pub(ctx->info->key_exchange.ctx(ctx));
    } else {
        return ctx->info->key_exchange.peer_ctx(ctx);
    }
}

ccec_pub_ctx_t ccsigma_kex_resp_ctx(struct ccsigma_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    if (ctx->role == CCSIGMA_ROLE_RESP) {
        return ccec_ctx_pub(ctx->info->key_exchange.ctx(ctx));
    } else {
        return ctx->info->key_exchange.peer_ctx(ctx);
    }
}

int ccsigma_derive_session_keys(struct ccsigma_ctx *ctx,
                                size_t add_data_size,
                                const void *add_data,
                                struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    const struct ccsigma_info *info = ctx->info;
    size_t shared_secret_size = ccsigma_shared_secret_size(info);
    uint8_t shared_secret[CCSIGMA_KEX_MAX_SHARED_SECRET_SIZE];

    int err = CCERR_CRYPTO_CONFIG;
    cc_require(shared_secret_size <= sizeof(shared_secret), out);

    ccec_full_ctx_t kex_ctx = info->key_exchange.ctx(ctx);
    ccec_pub_ctx_t peer_kex_ctx = ctx->info->key_exchange.peer_ctx(ctx);

    err = ccecdh_compute_shared_secret(kex_ctx,
                                       peer_kex_ctx,
                                       &shared_secret_size,
                                       shared_secret,
                                       rng);
    cc_require(err == CCERR_OK, out);

    err = info->session_keys.derive(ctx,
                                    shared_secret_size,
                                    shared_secret,
                                    add_data_size,
                                    add_data);

 out:
    return err;
}

int ccsigma_compute_mac(struct ccsigma_ctx *ctx,
                        size_t key_index,
                        size_t data_size,
                        const void *data,
                        void *tag)
{
    CC_ENSURE_DIT_ENABLED

    size_t key_size;
    void *key;

    int err = ccsigma_session_key_lookup(ctx, key_index, &key_size, &key);
    cc_require(err == CCERR_OK, out);

    err = ctx->info->mac.compute(ctx,
                                 key_size,
                                 key,
                                 data_size,
                                 data,
                                 tag);

 out:
    return err;
}

int ccsigma_sign(struct ccsigma_ctx *ctx,
                 void *signature,
                 size_t identity_size,
                 const void *identity,
                 struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    size_t digest_size = ctx->info->signature.digest_info->output_size;
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];

    int err = CCERR_CRYPTO_CONFIG;
    cc_require(digest_size <= sizeof(digest), out);

    err = ctx->info->sigma.compute_mac_and_digest(ctx,
                                                  ctx->role,
                                                  identity_size,
                                                  identity,
                                                  digest);
    cc_require(err == CCERR_OK, out);

    ccsigma_sign_fn_t sign_fn = ctx->sign_fn;
    size_t signature_nbytes = ctx->info->signature.signature_size;
    err = sign_fn(ctx->sign_ctx,
                  digest_size,
                  digest,
                  &signature_nbytes,
                  signature,
                  rng);

 out:
    return err;
}

int ccsigma_verify(struct ccsigma_ctx *ctx,
                   const void *signature,
                   size_t peer_identity_size,
                   const void *peer_identity)
{
    CC_ENSURE_DIT_ENABLED

    size_t digest_size = ctx->info->signature.digest_info->output_size;
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];

    int err = CCERR_CRYPTO_CONFIG;
    cc_require(digest_size <= sizeof(digest), out);

    err = ctx->info->sigma.compute_mac_and_digest(ctx,
                                                  ccsigma_peer_role(ctx),
                                                  peer_identity_size,
                                                  peer_identity,
                                                  digest);
    cc_require(err == CCERR_OK, out);

    ccec_pub_ctx_t verify_ctx = ctx->info->signature.peer_ctx(ctx);

    const uint8_t *r = signature;
    const uint8_t *s = r + ccec_signature_r_s_size(verify_ctx);

    bool valid;
    err = ccec_verify_composite(verify_ctx, digest_size, digest, r, s, &valid);
    cc_require(err == CCERR_OK, out);

    if (!valid) {
        err = CCERR_INVALID_SIGNATURE;
    }

 out:
    return err;
}

int ccsigma_seal(struct ccsigma_ctx *ctx,
                 size_t key_index,
                 size_t iv_index,
                 size_t add_data_size,
                 const void *add_data,
                 size_t ptext_size,
                 const void *ptext,
                 void *ctext,
                 void *tag)
{
    CC_ENSURE_DIT_ENABLED

    int err;
    void *key;
    size_t key_size;
    void *iv;
    size_t iv_size;

    err = ccsigma_session_key_lookup(ctx, key_index, &key_size, &key);
    cc_require(err == CCERR_OK, out);

    err = ccsigma_session_key_lookup(ctx, iv_index, &iv_size, &iv);
    cc_require(err == CCERR_OK, out);

    err = ctx->info->aead.seal(ctx,
                               key_size,
                               key,
                               iv_size,
                               iv,
                               add_data_size,
                               add_data,
                               ptext_size,
                               ptext,
                               ctext,
                               tag);
    cc_require(err == CCERR_OK, out);

    ctx->info->aead.next_iv(iv_size, iv);

 out:
    return err;
}

int ccsigma_open(struct ccsigma_ctx *ctx,
                 size_t key_index,
                 size_t iv_index,
                 size_t add_data_size,
                 const void *add_data,
                 size_t ctext_size,
                 const void *ctext,
                 void *ptext,
                 const void *tag)
{
    CC_ENSURE_DIT_ENABLED

    int err;
    void *key;
    size_t key_size;
    void *iv;
    size_t iv_size;

    size_t tag_size = ctx->info->aead.tag_size;
    uint8_t tag_copy[CCSIGMA_AEAD_MAX_TAG_SIZE];

    err = CCERR_CRYPTO_CONFIG;
    cc_require(tag_size <= sizeof(tag_copy), out);

    err = ccsigma_session_key_lookup(ctx, key_index, &key_size, &key);
    cc_require(err == CCERR_OK, out);

    err = ccsigma_session_key_lookup(ctx, iv_index, &iv_size, &iv);
    cc_require(err == CCERR_OK, out);

    cc_memcpy(tag_copy, tag, tag_size);

    err = ctx->info->aead.open(ctx,
                               key_size,
                               key,
                               iv_size,
                               iv,
                               add_data_size,
                               add_data,
                               ctext_size,
                               ctext,
                               ptext,
                               tag_copy);
    cc_require(err == CCERR_OK, out);

    ctx->info->aead.next_iv(iv_size, iv);

 out:
    return err;
}

int ccsigma_clear_key(struct ccsigma_ctx *ctx, size_t key_index)
{
    CC_ENSURE_DIT_ENABLED

    size_t size;
    void *key;
    int err = ccsigma_session_key_lookup(ctx, key_index, &size, &key);
    cc_require(err == CCERR_OK, out);

    cc_clear(size, key);

 out:
    return err;
}

void ccsigma_clear(struct ccsigma_ctx *ctx)
{
    CC_ENSURE_DIT_ENABLED

    ctx->info->clear(ctx);
}
