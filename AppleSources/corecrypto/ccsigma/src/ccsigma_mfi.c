/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccsigma_mfi.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccnistkdf.h>

static ccec_full_ctx_t mfi_kex_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->key_exchange.ctx;
}

static ccec_pub_ctx_t mfi_peer_kex_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->key_exchange.peer_ctx;
}

static ccec_full_ctx_t mfi_sign_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->signature.ctx;
}

static ccec_pub_ctx_t mfi_peer_sign_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->signature.peer_ctx;
}

static void *mfi_session_keys_buffer(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->session_keys_buffer;
}

struct ccsigma_mfi_info {
    struct ccsigma_info sigma_info;
    const uint8_t *kdf_salt;
    size_t kdf_salt_size;
    const uint8_t *kdf_label;
    size_t kdf_label_size;
    const uint8_t *kdf_dst;
    size_t kdf_dst_size;
    const uint8_t *sign_dst;
    size_t sign_dst_size;
};

static int mfi_session_keys_derive(struct ccsigma_ctx *ctx,
                                   size_t shared_secret_size,
                                   const void *shared_secret,
                                   size_t transcript_size,
                                   const void *transcript)
{
    const struct ccsigma_info *info = ctx->info;
    const struct ccsigma_mfi_info *mfi_info = (const struct ccsigma_mfi_info *)info;

    size_t key_share_size = ccec_compressed_x962_export_pub_size(info->key_exchange.curve_params);
    size_t kdf_ctx_size = mfi_info->kdf_dst_size + (2 * key_share_size) + transcript_size;
    uint8_t kdf_ctx[CCSIGMA_MFI_KDF_MAX_CTX_SIZE];

    int err = CCERR_PARAMETER;
    cc_require(kdf_ctx_size <= sizeof(kdf_ctx), out);

    uint8_t kdk[16];
    err = cccmac_one_shot_generate(ccaes_cbc_encrypt_mode(),
                                   mfi_info->kdf_salt_size, mfi_info->kdf_salt,
                                   shared_secret_size, shared_secret,
                                   sizeof(kdk), kdk);
    cc_require(err == CCERR_OK, out);

    uint8_t *p = kdf_ctx;

    cc_memcpy(p, mfi_info->kdf_dst, mfi_info->kdf_dst_size);

    p += mfi_info->kdf_dst_size;

    err = ccec_compressed_x962_export_pub(ccsigma_kex_init_ctx(ctx), p);
    cc_require(err == CCERR_OK, out);

    p += key_share_size;

    err = ccec_compressed_x962_export_pub(ccsigma_kex_resp_ctx(ctx), p);
    cc_require(err == CCERR_OK, out);

    p += key_share_size;

    cc_memcpy(p, transcript, transcript_size);

    err = ccnistkdf_ctr_cmac(ccaes_cbc_encrypt_mode(),
                             32,
                             sizeof(kdk), kdk,
                             mfi_info->kdf_label_size, mfi_info->kdf_label,
                             kdf_ctx_size, kdf_ctx,
                             info->session_keys.buffer_size,
                             4,
                             info->session_keys.buffer(ctx));

 out:
    return err;
}

static int mfi_mac_compute(struct ccsigma_ctx *ctx,
                           size_t key_size,
                           const void *key,
                           size_t data_size,
                           const void *data,
                           void *mac)
{
    return cccmac_one_shot_generate(ccaes_cbc_encrypt_mode(),
                                    key_size,
                                    key,
                                    data_size,
                                    data,
                                    ctx->info->mac.tag_size,
                                    mac);
}

static int mfi_sigma_compute_mac_and_digest(struct ccsigma_ctx *ctx,
                                            ccsigma_role_t role,
                                            size_t identity_size,
                                            const void *identity,
                                            void *digest)
{
    const struct ccsigma_info *info = ctx->info;
    const struct ccsigma_mfi_info *mfi_info = (const struct ccsigma_mfi_info *)info;

    const struct ccdigest_info *digest_info = info->signature.digest_info;
    ccdigest_di_decl(digest_info, digest_ctx);

    ccdigest_init(digest_info, digest_ctx);

    ccdigest_update(digest_info, digest_ctx, mfi_info->sign_dst_size, mfi_info->sign_dst);

    size_t key_share_size = ccec_compressed_x962_export_pub_size(info->key_exchange.curve_params);
    uint8_t key_share[CCSIGMA_MFI_KEX_KEY_SHARE_SIZE];

    int err = CCERR_CRYPTO_CONFIG;
    cc_require(key_share_size <= sizeof(key_share), out);

    ccec_pub_ctx_t init_kex_ctx = ccsigma_kex_init_ctx(ctx);
    ccec_compressed_x962_export_pub(init_kex_ctx, key_share);
    ccdigest_update(digest_info, digest_ctx, key_share_size, key_share);

    ccec_pub_ctx_t resp_kex_ctx = ccsigma_kex_resp_ctx(ctx);
    ccec_compressed_x962_export_pub(resp_kex_ctx, key_share);
    ccdigest_update(digest_info, digest_ctx, key_share_size, key_share);

    uint8_t tag[CCSIGMA_MFI_MAC_TAG_SIZE];
    size_t key_index = info->sigma.mac_key_indices[role];

    err = ccsigma_compute_mac(ctx, key_index, identity_size, identity, tag);
    cc_require(err == CCERR_OK, out);

    ccdigest_update(digest_info, digest_ctx, info->mac.tag_size, tag);

    ccdigest_final(digest_info, digest_ctx, digest);

 out:
    return err;
}

static int mfi_aead_seal(struct ccsigma_ctx *ctx,
                         size_t key_size,
                         const void *key,
                         size_t iv_size,
                         const void *iv,
                         size_t add_data_size,
                         const void *add_data,
                         size_t ptext_size,
                         const void *ptext,
                         void *ctext,
                         void *tag)
{
    return ccccm_one_shot(ccaes_ccm_encrypt_mode(),
                          key_size,
                          key,
                          iv_size,
                          iv,
                          ptext_size,
                          ptext,
                          ctext,
                          add_data_size,
                          add_data,
                          ctx->info->aead.tag_size,
                          tag);
}

static int mfi_aead_open(struct ccsigma_ctx *ctx,
                         size_t key_size,
                         const void *key,
                         size_t iv_size,
                         const void *iv,
                         size_t add_data_size,
                         const void *add_data,
                         size_t ptext_size,
                         const void *ptext,
                         void *ctext,
                         void *tag)
{
    size_t tag_size = ctx->info->aead.tag_size;
    uint8_t computed_tag[CCSIGMA_MFI_AEAD_TAG_SIZE];

    int err = CCERR_CRYPTO_CONFIG;
    cc_require(tag_size <= sizeof(computed_tag), out);

    err = ccccm_one_shot(ccaes_ccm_decrypt_mode(),
                         key_size,
                         key,
                         iv_size,
                         iv,
                         ptext_size,
                         ptext,
                         ctext,
                         add_data_size,
                         add_data,
                         tag_size,
                         computed_tag);
    cc_require(err == CCERR_OK, out);

    if (cc_cmp_safe(ctx->info->aead.tag_size, tag, computed_tag)) {
        err = CCERR_INTEGRITY;
    }

 out:
    return err;
}

static void mfi_aead_next_iv(size_t iv_size, void *iv)
{
    inc_uint(iv, iv_size);
}

static void mfi_clear(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    cc_clear(sizeof(*ctx), ctx);
}

const static size_t mfi_session_keys_info[CCSIGMA_MFI_SESSION_KEYS_COUNT] = {
    16, // CCSIGMA_MFI_ER_KEY
    12, // CCSIGMA_MFI_ER_IV
    16, // CCSIGMA_MFI_TR_KEY
    16, // CCSIGMA_MFI_CR_KEY
    12, // CCSIGMA_MFI_CR_IV
    16, // CCSIGMA_MFI_SR_KEY
    12, // CCSIGMA_MFI_SR_IV
    16, // CCSIGMA_MFI_EI_KEY
    12, // CCSIGMA_MFI_EI_IV
    16, // CCSIGMA_MFI_TI_KEY
    16, // CCSIGMA_MFI_CI_KEY
    12, // CCSIGMA_MFI_CI_IV
    16, // CCSIGMA_MFI_SI_KEY
    12, // CCSIGMA_MFI_SI_IV
};

// SHA256('MFi 4.0 SIGMA-I Authentication Randomness Extraction')[:16]
static const uint8_t mfi_kdf_salt[] = {
    0xb6, 0x3f, 0xd4, 0x30, 0x48, 0x2f, 0x6d, 0x50,
    0x62, 0x41, 0x99, 0xe9, 0x88, 0x81, 0xb1, 0xf6,
};

// "MFi 4.0 SIGMA-I Authentication Key Expansion"
static const uint8_t mfi_kdf_label[] = {
    0x4d, 0x46, 0x69, 0x20, 0x34, 0x2e, 0x30, 0x20,
    0x53, 0x49, 0x47, 0x4d, 0x41, 0x2d, 0x49, 0x20,
    0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4b,
    0x65, 0x79, 0x20, 0x45, 0x78, 0x70, 0x61, 0x6e,
    0x73, 0x69, 0x6f, 0x6e,
};

static const uint8_t mfi_dst[] = { 0x1 };

const static size_t mfi_nvm_session_keys_info[CCSIGMA_MFI_SESSION_KEYS_COUNT] = {
    16, // CCSIGMA_MFI_ER_KEY
    12, // CCSIGMA_MFI_ER_IV
    16, // CCSIGMA_MFI_TR_KEY
    0,  // CCSIGMA_MFI_CR_KEY
    0,  // CCSIGMA_MFI_CR_IV
    16, // CCSIGMA_MFI_SR_KEY
    12, // CCSIGMA_MFI_SR_IV
    16, // CCSIGMA_MFI_EI_KEY
    12, // CCSIGMA_MFI_EI_IV
    16, // CCSIGMA_MFI_TI_KEY
    0,  // CCSIGMA_MFI_CI_KEY
    0,  // CCSIGMA_MFI_CI_IV
    16, // CCSIGMA_MFI_SI_KEY
    12, // CCSIGMA_MFI_SI_IV
};

// SHA256('MFi 4.0 NVM Authentication Randomness Extraction')[:16]
static const uint8_t mfi_nvm_kdf_salt[] = {
    0x04, 0x2b, 0x29, 0x81, 0xa1, 0x87, 0xcb, 0x0d,
    0x72, 0x90, 0x76, 0x1b, 0x33, 0xe5, 0x84, 0x0e,
};

// "MFi 4.0 NVM Authentication Key Expansion"
static const uint8_t mfi_nvm_kdf_label[] = {
    0x4d, 0x46, 0x69, 0x20, 0x34, 0x2e, 0x30, 0x20,
    0x4e, 0x56, 0x4d, 0x20, 0x41, 0x75, 0x74, 0x68,
    0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x45,
    0x78, 0x70, 0x61, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
};

static const uint8_t mfi_nvm_dst[] = { 0x2 };

static struct ccsigma_mfi_info mfi_info = {
    .kdf_salt = mfi_kdf_salt,
    .kdf_salt_size = sizeof(mfi_kdf_salt),
    .kdf_label = mfi_kdf_label,
    .kdf_label_size = sizeof(mfi_kdf_label),
    .kdf_dst = mfi_dst,
    .kdf_dst_size = sizeof(mfi_dst),
    .sign_dst = mfi_dst,
    .sign_dst_size = sizeof(mfi_dst),
};

static struct ccsigma_mfi_info mfi_nvm_info = {
    .kdf_salt = mfi_nvm_kdf_salt,
    .kdf_salt_size = sizeof(mfi_nvm_kdf_salt),
    .kdf_label = mfi_nvm_kdf_label,
    .kdf_label_size = sizeof(mfi_nvm_kdf_label),
    .kdf_dst = mfi_nvm_dst,
    .kdf_dst_size = sizeof(mfi_nvm_dst),
    .sign_dst = mfi_nvm_dst,
    .sign_dst_size = sizeof(mfi_nvm_dst),
};

static void mfi_info_init(struct ccsigma_info *sigma_info)
{
    ccec_const_cp_t cp = ccec_cp_256();

    cc_assert(CCSIGMA_MFI_KEX_CP_BITSIZE == ccec_cp_prime_bitlen(cp));

    sigma_info->key_exchange.curve_params = cp;
    sigma_info->key_exchange.ctx = mfi_kex_ctx;
    sigma_info->key_exchange.peer_ctx = mfi_peer_kex_ctx;

    size_t signature_size = 2 * ccec_cp_prime_size(cp);

    cc_assert(CCSIGMA_MFI_SIG_CP_SIZE == ccec_cp_prime_size(cp));
    cc_assert(CCSIGMA_MFI_SIG_CP_BITSIZE == ccec_cp_prime_bitlen(cp));
    cc_assert(CCSIGMA_MFI_SIGNATURE_SIZE == signature_size);

    sigma_info->signature.curve_params = cp;
    sigma_info->signature.digest_info = ccsha256_di();
    sigma_info->signature.signature_size = signature_size;
    sigma_info->signature.ctx = mfi_sign_ctx;
    sigma_info->signature.peer_ctx = mfi_peer_sign_ctx;

    sigma_info->session_keys.count = CCSIGMA_MFI_SESSION_KEYS_COUNT;
    sigma_info->session_keys.info = mfi_session_keys_info;
    sigma_info->session_keys.buffer_size = CCSIGMA_MFI_SESSION_KEYS_BUFFER_SIZE;
    sigma_info->session_keys.buffer = mfi_session_keys_buffer;
    sigma_info->session_keys.derive = mfi_session_keys_derive;

    sigma_info->mac.tag_size = CCSIGMA_MFI_MAC_TAG_SIZE;
    sigma_info->mac.compute = mfi_mac_compute;

    sigma_info->sigma.mac_key_indices[0] = CCSIGMA_MFI_TI_KEY;
    sigma_info->sigma.mac_key_indices[1] = CCSIGMA_MFI_TR_KEY;
    sigma_info->sigma.compute_mac_and_digest = mfi_sigma_compute_mac_and_digest;

    sigma_info->aead.tag_size = CCSIGMA_MFI_AEAD_TAG_SIZE;
    sigma_info->aead.seal = mfi_aead_seal;
    sigma_info->aead.open = mfi_aead_open;
    sigma_info->aead.next_iv = mfi_aead_next_iv;

    sigma_info->clear = mfi_clear;
}

const struct ccsigma_info *ccsigma_mfi_info(void)
{
    CC_ENSURE_DIT_ENABLED

    mfi_info_init(&mfi_info.sigma_info);

    return &mfi_info.sigma_info;
}

const struct ccsigma_info *ccsigma_mfi_nvm_info(void)
{
    CC_ENSURE_DIT_ENABLED

    mfi_info_init(&mfi_nvm_info.sigma_info);

    mfi_nvm_info.sigma_info.session_keys.info = mfi_nvm_session_keys_info;
    mfi_nvm_info.sigma_info.session_keys.buffer_size = CCSIGMA_MFI_NVM_SESSION_KEYS_BUFFER_SIZE;

    return &mfi_nvm_info.sigma_info;
}
