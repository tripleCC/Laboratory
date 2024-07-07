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

#include <corecrypto/cc.h>
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng_ecfips_test.h>
#include "testmore.h"
#include "testbyteBuffer.h"
#include <corecrypto/ccec.h>

#if (CCSIGMA == 0)
entryPoint(ccsigma_tests, "ccsigma test")
#else

#include <corecrypto/ccsigma_priv.h>
#include <corecrypto/ccsigma_mfi.h>

static void
ccsigma_round_trip(const struct ccsigma_info *info)
{
    int err;

    struct ccrng_state *rng = ccrng(NULL);

    size_t signing_key_size = ccec_x963_export_size_cp(1, info->signature.curve_params);
    size_t verification_key_size = ccec_compressed_x962_export_pub_size(info->signature.curve_params);
    size_t signature_size = info->signature.signature_size;

    struct ccsigma_mfi_ctx init_mfi_ctx;
    struct ccsigma_ctx *init_ctx = &init_mfi_ctx.sigma_ctx;

    const char *init_identity = "initiator";
    size_t init_identity_size = strlen(init_identity);

    ccec_full_ctx_decl_cp(info->signature.curve_params, init_signing_ctx);

    uint8_t init_signing_key[signing_key_size];

    uint8_t init_verification_key[verification_key_size];

    uint8_t init_signature[signature_size];

    size_t init_key_share_size = ccec_compressed_x962_export_pub_size(info->key_exchange.curve_params);
    uint8_t init_key_share[init_key_share_size];

    uint8_t init_tag[info->aead.tag_size];

    struct ccsigma_mfi_ctx resp_mfi_ctx;
    struct ccsigma_ctx *resp_ctx = &resp_mfi_ctx.sigma_ctx;

    const char *resp_identity = "responder";
    size_t resp_identity_size = strlen(resp_identity);

    ccec_full_ctx_decl_cp(info->signature.curve_params, resp_signing_ctx);

    uint8_t resp_signing_key[signing_key_size];

    uint8_t resp_verification_key[verification_key_size];

    uint8_t resp_signature[signature_size];

    size_t resp_key_share_size = ccec_compressed_x962_export_pub_size(info->key_exchange.curve_params);
    uint8_t resp_key_share[resp_key_share_size];

    uint8_t resp_tag[info->aead.tag_size];

    uint8_t bad_tag[info->aead.tag_size];
    uint8_t bad_signature[signature_size];

    err = ccsigma_init(info, init_ctx, CCSIGMA_ROLE_INIT, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_init/init", errout);

    err = ccec_generate_key_fips(info->signature.curve_params, rng, init_signing_ctx);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccec_generate_key_fips/init", errout);

    err = ccec_x963_export(1, init_signing_key, init_signing_ctx);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccec_x963_export/#1", errout);

    err = ccsigma_import_signing_key(init_ctx, signing_key_size, init_signing_key);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_import_signing_key/init", errout);

    err = ccsigma_export_key_share(init_ctx, &init_key_share_size, init_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_export_key_share/init", errout);

    err = ccsigma_init(info, resp_ctx, CCSIGMA_ROLE_RESP, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_init/resp", errout);

    err = ccec_generate_key_fips(info->signature.curve_params, rng, resp_signing_ctx);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccec_generate_key_fips/resp", errout);

    err = ccec_x963_export(1, resp_signing_key, resp_signing_ctx);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccec_x963_export/#2", errout);

    err = ccsigma_import_signing_key(resp_ctx, signing_key_size, resp_signing_key);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_import_signing_key/resp", errout);

    err = ccsigma_import_peer_key_share(resp_ctx, init_key_share_size, init_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_import_peer_key_share/resp", errout);

    err = ccsigma_derive_session_keys(resp_ctx, 0, NULL, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_derive_session_keys/resp", errout);

    err = ccsigma_sign(resp_ctx, resp_signature, resp_identity_size, resp_identity, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_sign/resp", errout);

    err = ccsigma_seal(resp_ctx, CCSIGMA_MFI_ER_KEY, CCSIGMA_MFI_ER_IV, 0, NULL, signature_size, resp_signature, resp_signature, resp_tag);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_seal/resp", errout);

    err = ccsigma_clear_key(resp_ctx, CCSIGMA_MFI_ER_KEY);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(er_key)/resp", errout);

    err = ccsigma_clear_key(resp_ctx, CCSIGMA_MFI_ER_IV);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(er_iv)/resp", errout);

    err = ccsigma_export_key_share(resp_ctx, &resp_key_share_size, resp_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_export_key_share/resp", errout);

    err = ccsigma_import_peer_key_share(init_ctx, resp_key_share_size, resp_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_import_key_share/init", errout);

    err = ccsigma_derive_session_keys(init_ctx, 0, NULL, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_derive_session_keys/init", errout);

    cc_memcpy(bad_tag, resp_tag, info->aead.tag_size);
    bad_tag[0] ^= 1;
    err = ccsigma_open(init_ctx, CCSIGMA_MFI_ER_KEY, CCSIGMA_MFI_ER_IV, 0, NULL, signature_size, resp_signature, bad_signature, bad_tag);
    is_or_goto(err, CCERR_INTEGRITY, "ccsigma_round_trip/ccsigma_open(fail)/init", errout);

    err = ccsigma_open(init_ctx, CCSIGMA_MFI_ER_KEY, CCSIGMA_MFI_ER_IV, 0, NULL, signature_size, resp_signature, resp_signature, resp_tag);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_open/init", errout);

    err = ccsigma_clear_key(init_ctx, CCSIGMA_MFI_ER_KEY);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(er_key)/init", errout);

    err = ccsigma_clear_key(init_ctx, CCSIGMA_MFI_ER_IV);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(er_iv)/init", errout);

    err = ccec_compressed_x962_export_pub(ccec_ctx_pub(resp_signing_ctx), resp_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccec_compressed_x962_export_pub/resp", errout);

    err = ccsigma_import_peer_verification_key(init_ctx, verification_key_size, resp_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_import_peer_verification_key/init", errout);

    cc_memcpy(bad_signature, resp_signature, signature_size);
    bad_signature[0] ^= 1;
    err = ccsigma_verify(init_ctx, bad_signature, resp_identity_size, resp_identity);
    is_or_goto(err, CCERR_INVALID_SIGNATURE, "ccsigma_round_trip/ccsigma_verify(fail)/init", errout);

    err = ccsigma_verify(init_ctx, resp_signature, resp_identity_size, resp_identity);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_verify/init", errout);

    err = ccsigma_sign(init_ctx, init_signature, init_identity_size, init_identity, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_sign/init", errout);

    err = ccsigma_seal(init_ctx, CCSIGMA_MFI_EI_KEY, CCSIGMA_MFI_EI_IV, 0, NULL, signature_size, init_signature, init_signature, init_tag);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_seal/init", errout);

    err = ccsigma_clear_key(init_ctx, CCSIGMA_MFI_EI_KEY);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(ei_key)/init", errout);

    err = ccsigma_clear_key(init_ctx, CCSIGMA_MFI_EI_IV);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(ei_iv)/init", errout);

    cc_memcpy(bad_tag, init_tag, info->aead.tag_size);
    bad_tag[0] ^= 1;
    err = ccsigma_open(resp_ctx, CCSIGMA_MFI_EI_KEY, CCSIGMA_MFI_EI_IV, 0, NULL, signature_size, init_signature, bad_signature, bad_tag);
    is_or_goto(err, CCERR_INTEGRITY, "ccsigma_round_trip/ccsigma_open(fail)/resp", errout);

    err = ccsigma_open(resp_ctx, CCSIGMA_MFI_EI_KEY, CCSIGMA_MFI_EI_IV, 0, NULL, signature_size, init_signature, init_signature, init_tag);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_open/resp", errout);

    err = ccsigma_clear_key(resp_ctx, CCSIGMA_MFI_EI_KEY);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(ei_key)/resp", errout);

    err = ccsigma_clear_key(resp_ctx, CCSIGMA_MFI_EI_IV);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_clear_key(ei_iv)/resp", errout);

    err = ccec_compressed_x962_export_pub(ccec_ctx_pub(init_signing_ctx), init_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccec_compressed_x962_export_pub/init", errout);

    err = ccsigma_import_peer_verification_key(resp_ctx, verification_key_size, init_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_import_peer_verification_key/resp", errout);

    cc_memcpy(bad_signature, init_signature, signature_size);
    bad_signature[0] ^= 1;
    err = ccsigma_verify(resp_ctx, bad_signature, init_identity_size, init_identity);
    is_or_goto(err, CCERR_INVALID_SIGNATURE, "ccsigma_round_trip/ccsigma_verify(fail)/resp", errout);

    err = ccsigma_verify(resp_ctx, init_signature, init_identity_size, init_identity);
    is_or_goto(err, CCERR_OK, "ccsigma_round_trip/ccsigma_verify/resp", errout);

    ccsigma_clear(init_ctx);

    ccsigma_clear(resp_ctx);

 errout:
    return;
}

enum sigma_kat_info {
    SIGMA_KAT_INFO_MFI = 0,
    SIGMA_KAT_INFO_MFI_NVM = 1,

    SIGMA_KAT_INFO_COUNT,
};

static const struct ccsigma_info *(*sigma_kat_infos[SIGMA_KAT_INFO_COUNT])(void) = {
    [SIGMA_KAT_INFO_MFI] = &ccsigma_mfi_info,
    [SIGMA_KAT_INFO_MFI_NVM] = &ccsigma_mfi_nvm_info,
};

struct sigma_kat {
    enum sigma_kat_info info;
    uint8_t init_signing_key_priv_der[128];
    uint8_t init_key_share_priv[32];
    uint8_t init_key_share[64];
    uint8_t resp_signing_key_priv_der[128];
    uint8_t resp_key_share_priv[32];
    uint8_t resp_key_share[64];
    uint8_t session_keys[200];
    uint8_t init_identity[16];
    uint8_t init_signature[64];
    uint8_t resp_identity[16];
    uint8_t resp_signature[64];
    uint8_t transcript[16];
};

static void
ccsigma_kat(struct sigma_kat *kat)
{
    int err;

    const struct ccsigma_info *info = sigma_kat_infos[kat->info]();

    struct ccrng_ecfips_test_state rng_ecfips;
    struct ccrng_state *rng = (struct ccrng_state *)&rng_ecfips;

    ccec_const_cp_t sig_params = info->signature.curve_params;

    struct ccsigma_mfi_ctx init_mfi_ctx;
    struct ccsigma_ctx *init_ctx = &init_mfi_ctx.sigma_ctx;

    ccec_full_ctx_decl_cp(sig_params, init_signing_ctx);

    size_t init_signing_key_size = ccec_x963_export_size_cp(1, info->signature.curve_params);
    uint8_t init_signing_key[init_signing_key_size];

    size_t init_verification_key_size = ccec_compressed_x962_export_pub_size(info->signature.curve_params);
    uint8_t init_verification_key[init_verification_key_size];

    size_t init_key_share_size = ccec_compressed_x962_export_pub_size(info->key_exchange.curve_params);
    uint8_t init_key_share[init_key_share_size];

    struct ccsigma_mfi_ctx resp_mfi_ctx;
    struct ccsigma_ctx *resp_ctx = &resp_mfi_ctx.sigma_ctx;

    ccec_full_ctx_decl_cp(info->signature.curve_params, resp_signing_ctx);

    size_t resp_signing_key_size = ccec_x963_export_size_cp(1, info->signature.curve_params);
    uint8_t resp_signing_key[resp_signing_key_size];

    size_t resp_verification_key_size = ccec_compressed_x962_export_pub_size(info->signature.curve_params);
    uint8_t resp_verification_key[resp_verification_key_size];

    size_t resp_key_share_size = ccec_compressed_x962_export_pub_size(info->key_exchange.curve_params);
    uint8_t resp_key_share[resp_key_share_size];

    ccrng_ecfips_test_init(&rng_ecfips,
                           sizeof(kat->init_key_share_priv),
                           kat->init_key_share_priv);
    err = ccsigma_init(info, init_ctx, CCSIGMA_ROLE_INIT, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_init/init", errout);

    err = ccsigma_export_key_share(init_ctx, &init_key_share_size, init_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_export_key_share/init", errout);

    ok_memcmp_or_goto(init_key_share, kat->init_key_share, sizeof(init_key_share), errout, "ccsigma_kat/init_key_share/init");

    ccec_der_import_priv(sig_params,
                         sizeof(kat->init_signing_key_priv_der),
                         kat->init_signing_key_priv_der,
                         init_signing_ctx);
    err = ccec_x963_export(1, init_signing_key, init_signing_ctx);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccec_x963_export/#1", errout);
    err = ccsigma_import_signing_key(init_ctx, init_signing_key_size, init_signing_key);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_import_signing_key/init", errout);

    ccrng_ecfips_test_init(&rng_ecfips,
                           sizeof(kat->resp_key_share_priv),
                           kat->resp_key_share_priv);
    err = ccsigma_init(info, resp_ctx, CCSIGMA_ROLE_RESP, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_init/resp", errout);

    err = ccsigma_export_key_share(resp_ctx, &resp_key_share_size, resp_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_export_key_share/resp", errout);

    ok_memcmp_or_goto(resp_key_share, kat->resp_key_share, sizeof(resp_key_share), errout, "ccsigma_kat/resp_key_share/resp");

    ccec_der_import_priv(sig_params,
                         sizeof(kat->resp_signing_key_priv_der),
                         kat->resp_signing_key_priv_der,
                         resp_signing_ctx);
    err = ccec_x963_export(1, resp_signing_key, resp_signing_ctx);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccec_x963_export/#2", errout);
    err = ccsigma_import_signing_key(resp_ctx, resp_signing_key_size, resp_signing_key);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_import_signing_key/resp", errout);

    err = ccsigma_import_peer_key_share(resp_ctx, init_key_share_size, init_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_import_peer_key_share/resp", errout);

    err = ccsigma_derive_session_keys(resp_ctx, sizeof(kat->transcript), kat->transcript, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_derive_session_keys/resp", errout);

    ok_memcmp_or_goto(resp_mfi_ctx.session_keys_buffer, kat->session_keys, info->session_keys.buffer_size, errout, "ccsigma_kat/session_keys/resp");

    err = ccsigma_import_peer_key_share(init_ctx, resp_key_share_size, resp_key_share);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_import_key_share/init", errout);

    err = ccsigma_derive_session_keys(init_ctx, sizeof(kat->transcript), kat->transcript, rng);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_derive_session_keys/init", errout);

    ok_memcmp_or_goto(init_mfi_ctx.session_keys_buffer, kat->session_keys, info->session_keys.buffer_size, errout, "ccsigma_kat/session_keys/init");

    err = ccec_compressed_x962_export_pub(ccec_ctx_pub(resp_signing_ctx), resp_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccec_compressed_x962_export_pub/resp", errout);

    err = ccsigma_import_peer_verification_key(init_ctx, resp_verification_key_size, resp_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_import_peer_verification_key/init", errout);

    err = ccsigma_verify(init_ctx, kat->resp_signature, sizeof(kat->resp_identity), kat->resp_identity);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_verify/init", errout);

    err = ccec_compressed_x962_export_pub(ccec_ctx_pub(init_signing_ctx), init_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccec_compressed_x962_export_pub/init", errout);

    err = ccsigma_import_peer_verification_key(resp_ctx, init_verification_key_size, init_verification_key);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_import_peer_verification_key/resp", errout);

    err = ccsigma_verify(resp_ctx, kat->init_signature, sizeof(kat->init_identity), kat->init_identity);
    is_or_goto(err, CCERR_OK, "ccsigma_kat/ccsigma_verify/resp", errout);

errout:
    return;
}

struct sigma_kat sigma_kats[] = {
#include "ccsigma_kat.inc"
};

static void
ccsigma_kats(void)
{
    for (size_t i = 0; i < CC_ARRAY_LEN(sigma_kats); i += 1) {
        struct sigma_kat *kat = &sigma_kats[i];
        ccsigma_kat(kat);
    }
}

#define ccsigma_round_trip_ntests (38)
#define ccsigma_kat_ntests (22)

int
ccsigma_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests((2 * ccsigma_round_trip_ntests) +
               ccsigma_kat_ntests * CC_ARRAY_LEN(sigma_kats));

    ccsigma_round_trip(ccsigma_mfi_info());
    ccsigma_round_trip(ccsigma_mfi_nvm_info());

    ccsigma_kats();

    return 0;
}

#endif // CCSIGMA
