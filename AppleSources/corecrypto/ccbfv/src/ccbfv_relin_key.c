/* Copyright (c) (2019,2022,2023) Apple Inc. All rights reserved.
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
#include "ccbfv_relin_key.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "ccbfv_util.h"
#include "ccbfv_serialization.h"
#include "ccpolyzp_po2cyc_serialization.h"

cc_size ccbfv_relin_key_nof_n(ccbfv_param_ctx_const_t param_ctx)
{
    cc_size rv = ccn_nof_size(sizeof_struct_ccbfv_relin_key());
    uint32_t nmoduli = ccbfv_param_ctx_key_ctx_nmoduli(param_ctx);
    uint32_t nciphers = CC_MAX_EVAL(1, nmoduli - 1);
    struct ccpolyzp_po2cyc_dims dims = { .nmoduli = nmoduli, .degree = ccbfv_param_ctx_polynomial_degree(param_ctx) };
    rv += nciphers * ccbfv_ciphertext_nof_n(&dims, ccbfv_ciphertext_fresh_npolys());
    return rv;
}

ccbfv_ciphertext_eval_t ccbfv_relin_key_ciphertext(ccbfv_relin_key_t relin_key, uint32_t cipher_idx)
{
    ccpolyzp_po2cyc_ctx_const_t relin_key_ctx = ccbfv_param_ctx_encrypt_key_context(relin_key->param_ctx);
    cc_assert(cipher_idx < relin_key_ctx->dims.nmoduli);

    cc_unit *relin_cipher = (cc_unit *)CCBFV_RELIN_KEY_CIPHERS(relin_key);
    relin_cipher += cipher_idx * ccbfv_ciphertext_nof_n(&relin_key_ctx->dims, ccbfv_ciphertext_fresh_npolys());
    return (ccbfv_ciphertext_eval_t)relin_cipher;
}

ccbfv_ciphertext_eval_const_t ccbfv_relin_key_ciphertext_const(ccbfv_relin_key_const_t relin_key, uint32_t cipher_idx)
{
    ccpolyzp_po2cyc_ctx_const_t relin_key_ctx = ccbfv_param_ctx_encrypt_key_context(relin_key->param_ctx);
    cc_assert(cipher_idx < relin_key_ctx->dims.nmoduli);

    const cc_unit *relin_cipher = (const cc_unit *)CCBFV_RELIN_KEY_CIPHERS_CONST(relin_key);
    relin_cipher += cipher_idx * ccbfv_ciphertext_nof_n(&relin_key_ctx->dims, ccbfv_ciphertext_fresh_npolys());
    return (ccbfv_ciphertext_eval_const_t)relin_cipher;
}

cc_size CCBFV_RELIN_KEY_GENERATE_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    return (CCPOLYZP_PO2CYC_WORKSPACE_N(degree, nmoduli)) + CCBFV_ENCRYPT_ZERO_SYMMETRIC_EVAL_WORKSPACE_N(degree, nmoduli);
}

int ccbfv_relin_key_generate_ws(cc_ws_t ws,
                                ccbfv_relin_key_t relin_key,
                                ccbfv_secret_key_const_t secret_key,
                                ccbfv_param_ctx_const_t param_ctx,
                                uint32_t nseeds,
                                uint8_t *cc_counted_by(nseeds) seeds,
                                struct ccrng_state *rng)
{
    ccpolyzp_po2cyc_ctx_const_t key_ctx = ccbfv_param_ctx_encrypt_key_context(param_ctx);
    uint32_t nmoduli = key_ctx->dims.nmoduli;
    cc_require_or_return(nmoduli > 1, CCERR_PARAMETER);

    uint32_t nciphers = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    cc_require_or_return(nseeds == 0 || nseeds == nciphers * ccbfv_rng_seed_sizeof(), CCERR_PARAMETER);

    relin_key->param_ctx = param_ctx;
    uint32_t degree = ccbfv_param_ctx_polynomial_degree(param_ctx);

    CC_DECL_BP_WS(ws, bp);
    int rv = CCERR_OK;

    // Create source secret key S_A = s^2
    ccpolyzp_po2cyc_eval_const_t secret_key_poly = ((ccpolyzp_po2cyc_eval_const_t)secret_key);
    ccpolyzp_po2cyc_eval_t secret_key_2 = (ccpolyzp_po2cyc_eval_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &key_ctx->dims);
    secret_key_2->context = secret_key_poly->context;
    ccpolyzp_po2cyc_eval_mul(secret_key_2, secret_key_poly, secret_key_poly);

    ccrns_modulus_const_t q_ks = ccpolyzp_po2cyc_ctx_ccrns_modulus(key_ctx, nciphers);
    for (uint32_t rns_idx = 0; rns_idx < nciphers; ++rns_idx) {
        ccrns_modulus_const_t q_i = ccpolyzp_po2cyc_ctx_ccrns_modulus(key_ctx, rns_idx);
        ccbfv_ciphertext_eval_t relin_cipher = ccbfv_relin_key_ciphertext(relin_key, rns_idx);

        // (-(a * s_B + e), a)_{[Q_i, q_ks]}
        rv = ccbfv_encrypt_zero_symmetric_eval_ws(ws,
                                                  relin_cipher,
                                                  param_ctx,
                                                  secret_key,
                                                  key_ctx->dims.nmoduli,
                                                  (ccbfv_rng_seed_t)(seeds ? seeds + ccbfv_rng_seed_sizeof() * rns_idx : NULL),
                                                  rng);
        cc_require(rv == CCERR_OK, errOut);

        // Add [q_ks * \tilde{P})_{Q_i}(s_A)_j]_{Q_i} to the first polynomial
        // [q_ks * \tilde{P})_{Q_i}(s_A)]_{q_j} = [q_ks * s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{q_j}
        //                                      = / [q_ks * s_A]_{q_i} for i == j
        //                                        \ 0                  for i != j
        // So, we only need to add q_ks * \tilde{P}_{Q_i}(s_A) to the `rns_idx`'th RNS component
        ccpolyzp_po2cyc_eval_t rlk_poly0 = ccbfv_ciphertext_eval_polynomial(relin_cipher, 0);
        const ccrns_int q_ks_mod_qi = ccpolyzp_po2cyc_scalar_mod1(q_ks->value, q_i);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            ccrns_int relin_key_coeff = ccpolyzp_po2cyc_eval_data_int(rlk_poly0, rns_idx, coeff_idx);
            // s_A mod q_i
            ccrns_int secret_key_relin_coeff = ccpolyzp_po2cyc_eval_data_int(secret_key_2, rns_idx, coeff_idx);
            // (s_A * q_ks) mod q_i
            ccrns_int prod = ccpolyzp_po2cyc_scalar_mul_mod(q_ks_mod_qi, secret_key_relin_coeff, q_i);
            ccrns_int sum = ccpolyzp_po2cyc_scalar_add_mod(prod, relin_key_coeff, q_i->value);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(rlk_poly0, rns_idx, coeff_idx), sum);
        }
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccbfv_relin_key_generate(ccbfv_relin_key_t relin_key,
                             ccbfv_secret_key_const_t secret_key,
                             ccbfv_param_ctx_const_t param_ctx,
                             uint32_t nseeds,
                             uint8_t *cc_counted_by(nseeds) seeds,
                             struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_ctx_const_t key_ctx = ccbfv_param_ctx_encrypt_key_context(param_ctx);
    CC_DECL_WORKSPACE_OR_FAIL(
        ws, CCBFV_RELIN_KEY_GENERATE_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(param_ctx), key_ctx->dims.nmoduli));
    int rv = ccbfv_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, nseeds, seeds, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_relin_key_save_ws(cc_ws_t ws, uint32_t nbytes_poly0s, uint8_t *poly0s, ccbfv_relin_key_const_t relin_key)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_ctx_const_t key_ctx = ccbfv_param_ctx_encrypt_key_context(relin_key->param_ctx);
    cc_require_or_return(key_ctx->dims.nmoduli > 1, CCERR_PARAMETER);
    uint32_t nciphers = ccbfv_param_ctx_ciphertext_ctx_nmoduli(relin_key->param_ctx);

    size_t nbytes_per_poly = ccpolyzp_po2cyc_serialize_poly_nbytes(key_ctx, 0);
    cc_require_or_return(nbytes_poly0s == nciphers * nbytes_per_poly, CCERR_PARAMETER);

    for (uint32_t cipher_idx = 0; cipher_idx < nciphers; ++cipher_idx) {
        ccbfv_ciphertext_eval_const_t ciphertext = ccbfv_relin_key_ciphertext_const(relin_key, cipher_idx);
        ccpolyzp_po2cyc_eval_const_t poly = ccbfv_ciphertext_eval_polynomial_const(ciphertext, 0);
        rv = ccpolyzp_po2cyc_serialize_poly_ws(ws, nbytes_per_poly, poly0s, 0, (ccpolyzp_po2cyc_const_t)poly);
        cc_require(rv == CCERR_OK, errOut);
        poly0s += nbytes_per_poly;
    }

errOut:
    return rv;
}

int ccbfv_relin_key_save(uint32_t nbytes_poly0s, uint8_t *poly0s, ccbfv_relin_key_const_t relin_key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCBFV_RELIN_KEY_SAVE_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(relin_key->param_ctx)));
    int rv = ccbfv_relin_key_save_ws(ws, nbytes_poly0s, poly0s, relin_key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_relin_key_load_ws(cc_ws_t ws,
                            ccbfv_relin_key_t relin_key,
                            ccbfv_param_ctx_const_t param_ctx,
                            uint32_t nbytes_poly0s,
                            const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                            uint32_t nbytes_seeds,
                            const uint8_t *cc_counted_by(nbytes_seeds) seeds)
{
    int rv = CCERR_OK;

    ccpolyzp_po2cyc_ctx_const_t key_ctx = ccbfv_param_ctx_encrypt_key_context(param_ctx);
    cc_require_or_return(key_ctx->dims.nmoduli > 1, CCERR_PARAMETER);
    uint32_t nciphers = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    size_t nbytes_per_poly = ccpolyzp_po2cyc_serialize_poly_nbytes(key_ctx, 0);
    size_t nbytes_per_seed = ccbfv_rng_seed_sizeof();
    cc_require_or_return(nbytes_poly0s == nciphers * nbytes_per_poly, CCERR_PARAMETER);
    cc_require_or_return(nbytes_seeds == nciphers * nbytes_per_seed, CCERR_PARAMETER);

    relin_key->param_ctx = param_ctx;

    for (uint32_t rns_idx = 0; rns_idx < nciphers; ++rns_idx) {
        ccbfv_ciphertext_eval_t relin_cipher = ccbfv_relin_key_ciphertext(relin_key, rns_idx);
        ccbfv_ciphertext_eval_init(relin_cipher, param_ctx, ccbfv_ciphertext_fresh_npolys(), key_ctx);
        rv =
            ccbfv_deserialize_seeded_ciphertext_eval_ws(ws, relin_cipher, nbytes_per_poly, poly0s, (ccbfv_rng_seed_const_t)seeds);
        cc_require(rv == CCERR_OK, errOut);
        poly0s += nbytes_per_poly;
        seeds += ccbfv_rng_seed_sizeof();
    }

errOut:
    return rv;
}

int ccbfv_relin_key_load(ccbfv_relin_key_t relin_key,
                         ccbfv_param_ctx_const_t param_ctx,
                         uint32_t nbytes_poly0s,
                         const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                         uint32_t nbytes_seeds,
                         const uint8_t *cc_counted_by(nbytes_seeds) seeds)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCBFV_RELIN_KEY_LOAD_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(param_ctx)));
    int rv = ccbfv_relin_key_load_ws(ws, relin_key, param_ctx, nbytes_poly0s, poly0s, nbytes_seeds, seeds);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
