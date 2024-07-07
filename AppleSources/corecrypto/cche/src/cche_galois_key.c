/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
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
#include "cche_galois_key.h"
#include "ccpolyzp_po2cyc_galois.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "cche_util.h"
#include "cche_serialization.h"
#include "ccpolyzp_po2cyc_serialization.h"

cc_size cche_galois_key_nof_n(cche_param_ctx_const_t param_ctx, uint32_t ngalois_elts)
{
    cc_size rv = ccn_nof_size(sizeof_struct_cche_galois_key());
    rv += ccn_nof_size(sizeof(uint32_t) * ngalois_elts);
    uint32_t nmoduli = cche_param_ctx_key_ctx_nmoduli(param_ctx);
    uint32_t nciphers = CC_MAX_EVAL(1, nmoduli - 1);
    struct ccpolyzp_po2cyc_dims dims = { .nmoduli = nmoduli, .degree = cche_param_ctx_polynomial_degree(param_ctx) };
    rv += ngalois_elts * nciphers * cche_ciphertext_nof_n(&dims, cche_ciphertext_fresh_npolys());
    return rv;
}

cche_ciphertext_eval_t cche_galois_key_ciphertext(cche_galois_key_t galois_key, uint32_t galois_elt_idx, uint32_t cipher_idx)
{
    cc_assert(galois_elt_idx < galois_key->ngalois_elts);
    cc_unit *galois_cipher = (cc_unit *)CCHE_GALOIS_KEY_CIPHERS(galois_key);
    ccpolyzp_po2cyc_ctx_const_t galois_key_ctx = cche_param_ctx_encrypt_key_context(galois_key->param_ctx);
    cc_assert(cipher_idx < galois_key_ctx->dims.nmoduli);
    uint32_t nciphers = CC_MAX_EVAL(1, galois_key_ctx->dims.nmoduli - 1);

    galois_cipher += galois_elt_idx * nciphers * cche_ciphertext_nof_n(&galois_key_ctx->dims, cche_ciphertext_fresh_npolys());
    galois_cipher += cipher_idx * cche_ciphertext_nof_n(&galois_key_ctx->dims, cche_ciphertext_fresh_npolys());
    return (cche_ciphertext_eval_t)galois_cipher;
}

cche_ciphertext_eval_const_t
cche_galois_key_ciphertext_const(cche_galois_key_const_t galois_key, uint32_t galois_elt_idx, uint32_t cipher_idx)
{
    cc_assert(galois_elt_idx < galois_key->ngalois_elts);
    const cc_unit *galois_cipher = (const cc_unit *)CCHE_GALOIS_KEY_CIPHERS_CONST(galois_key);
    ccpolyzp_po2cyc_ctx_const_t galois_key_ctx = cche_param_ctx_encrypt_key_context(galois_key->param_ctx);
    cc_assert(cipher_idx < galois_key_ctx->dims.nmoduli);
    uint32_t nciphers = CC_MAX_EVAL(1, galois_key_ctx->dims.nmoduli - 1);

    galois_cipher += galois_elt_idx * nciphers * cche_ciphertext_nof_n(&galois_key_ctx->dims, cche_ciphertext_fresh_npolys());
    galois_cipher += cipher_idx * cche_ciphertext_nof_n(&galois_key_ctx->dims, cche_ciphertext_fresh_npolys());
    return (cche_ciphertext_eval_const_t)galois_cipher;
}

cc_size CCHE_GALOIS_KEY_GENERATE_SINGLE_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    return (CCPOLYZP_PO2CYC_WORKSPACE_N(degree, nmoduli)) + CCHE_ENCRYPT_ZERO_SYMMETRIC_EVAL_WORKSPACE_N(degree, nmoduli);
}

/// @brief Generates a Galois key for a single Galois element
/// @param ws Workspace
/// @param galois_key Galois key to populate
/// @param galois_elt Galois element; must be odd in [3, 2N - 1]
/// @param galois_elt_idx Index of Galois element in the Galois key
/// @param secret_key Secret key to use for the Galois key generation
/// @param param_ctx Paramter context
/// @param seeds Buffer to an array of RNG seeds that will store the seed for the second polynomial of ciphertexts
/// @param rng Random number generator for the key generation
/// @return CCERR_OK if Galois key was generated successfully
CC_WARN_RESULT CC_NONNULL((1, 2, 5, 6)) static int cche_galois_key_generate_single_ws(cc_ws_t ws,
                                                                                      cche_galois_key_t galois_key,
                                                                                      uint32_t galois_elt,
                                                                                      uint32_t galois_elt_idx,
                                                                                      cche_secret_key_const_t secret_key,
                                                                                      cche_param_ctx_const_t param_ctx,
                                                                                      uint8_t *seeds,
                                                                                      struct ccrng_state *rng)
{
    ccpolyzp_po2cyc_ctx_const_t key_ctx = cche_param_ctx_encrypt_key_context(param_ctx);
    uint32_t nmoduli = key_ctx->dims.nmoduli;
    cc_require_or_return(nmoduli > 1, CCERR_PARAMETER);

    uint32_t degree = cche_param_ctx_polynomial_degree(param_ctx);
    cc_require_or_return(is_valid_galois_element_and_degree(galois_elt, degree), CCERR_PARAMETER);
    cc_require_or_return(galois_elt_idx < galois_key->ngalois_elts, CCERR_PARAMETER);

    CC_DECL_BP_WS(ws, bp);

    uint32_t *galois_key_elts = CCHE_GALOIS_KEY_GALOIS_ELTS(galois_key);
    galois_key_elts[galois_elt_idx] = galois_elt;

    // Create source secret key S_A
    ccpolyzp_po2cyc_eval_t secret_key_galois = (ccpolyzp_po2cyc_eval_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &key_ctx->dims);
    secret_key_galois->context = ((ccpolyzp_po2cyc_eval_const_t)secret_key)->context;
    int rv = ccpolyzp_po2cyc_eval_apply_galois(secret_key_galois, (ccpolyzp_po2cyc_eval_const_t)secret_key, galois_elt);
    cc_require(rv == CCERR_OK, errOut);

    uint32_t nciphers = key_ctx->dims.nmoduli - 1;
    ccrns_modulus_const_t q_ks = ccpolyzp_po2cyc_ctx_ccrns_modulus(key_ctx, nciphers);
    for (uint32_t rns_idx = 0; rns_idx < nciphers; ++rns_idx) {
        ccrns_modulus_const_t q_i = ccpolyzp_po2cyc_ctx_ccrns_modulus(key_ctx, rns_idx);
        cche_ciphertext_eval_t galois_cipher = cche_galois_key_ciphertext(galois_key, galois_elt_idx, rns_idx);

        // (-(a * s_B + e), a)_{[Q_i, q_ks]}
        rv = cche_encrypt_zero_symmetric_eval_ws(ws,
                                                 galois_cipher,
                                                 param_ctx,
                                                 secret_key,
                                                 key_ctx->dims.nmoduli,
                                                 (cche_rng_seed_t)(seeds ? seeds + cche_rng_seed_sizeof() * rns_idx : NULL),
                                                 rng);
        cc_require(rv == CCERR_OK, errOut);

        // Add [q_ks * \tilde{P})_{Q_i}(s_A)_j]_{Q_i} to the first polynomial
        // [q_ks * \tilde{P})_{Q_i}(s_A)]_{q_j} = [q_ks * s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{q_j}
        //                                      = / [q_ks * s_A]_{q_i} for i == j
        //                                        \ 0                  for i != j
        // So, we only need to add q_ks * \tilde{P}_{Q_i}(s_A) to the `rns_idx`'th RNS component
        ccpolyzp_po2cyc_eval_t gk_poly0 = cche_ciphertext_eval_polynomial(galois_cipher, 0);
        const ccrns_int q_ks_mod_qi = ccpolyzp_po2cyc_scalar_mod1(q_ks->value, q_i);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            ccrns_int galois_key_coeff = ccpolyzp_po2cyc_eval_data_int(gk_poly0, rns_idx, coeff_idx);
            // s_A mod q_i
            ccrns_int secret_key_galois_coeff = ccpolyzp_po2cyc_eval_data_int(secret_key_galois, rns_idx, coeff_idx);
            // (s_A * q_ks) mod q_i
            ccrns_int prod = ccpolyzp_po2cyc_scalar_mul_mod(q_ks_mod_qi, secret_key_galois_coeff, q_i);
            ccrns_int sum = ccpolyzp_po2cyc_scalar_add_mod(prod, galois_key_coeff, q_i->value);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(gk_poly0, rns_idx, coeff_idx), sum);
        }
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

cc_size CCHE_GALOIS_KEY_GENERATE_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    return CCHE_GALOIS_KEY_GENERATE_SINGLE_WORKSPACE_N(degree, nmoduli);
}

int cche_galois_key_generate_ws(cc_ws_t ws,
                                cche_galois_key_t galois_key,
                                uint32_t ngalois_elts,
                                const uint32_t *galois_elts,
                                cche_secret_key_const_t secret_key,
                                cche_param_ctx_const_t param_ctx,
                                uint32_t nseeds,
                                uint8_t *cc_counted_by(nseeds) seeds,
                                struct ccrng_state *rng)
{
    cc_require_or_return(ngalois_elts > 0, CCERR_PARAMETER);
    int rv = CCERR_OK;

    uint32_t nciphers = cche_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    cc_require_or_return(nseeds == 0 || nseeds == nciphers * ngalois_elts * cche_rng_seed_sizeof(), CCERR_PARAMETER);

    galois_key->param_ctx = param_ctx;
    galois_key->ngalois_elts = ngalois_elts;

    // check for uniqueness of Galois elements
    for (uint32_t galois_elt_idx = 0; galois_elt_idx < ngalois_elts; ++galois_elt_idx) {
        for (uint32_t i = 0; i < galois_elt_idx; ++i) {
            if (galois_elts[i] == galois_elts[galois_elt_idx]) {
                return CCERR_PARAMETER;
            }
        }
    }

    for (uint32_t galois_elt_idx = 0; galois_elt_idx < ngalois_elts; ++galois_elt_idx) {
        uint8_t *single_seeds = seeds ? seeds + galois_elt_idx * nciphers * cche_rng_seed_sizeof() : NULL;
        rv = cche_galois_key_generate_single_ws(
            ws, galois_key, galois_elts[galois_elt_idx], galois_elt_idx, secret_key, param_ctx, single_seeds, rng);
        cc_require(rv == CCERR_OK, errOut);
    }

errOut:
    return rv;
}

int cche_galois_key_generate(cche_galois_key_t galois_key,
                             uint32_t ngalois_elts,
                             const uint32_t *cc_counted_by(ngalois_elts) galois_elts,
                             cche_secret_key_const_t secret_key,
                             cche_param_ctx_const_t param_ctx,
                             uint32_t nseeds,
                             uint8_t *cc_counted_by(nseeds) seeds,
                             struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    uint32_t nmoduli = cche_param_ctx_key_ctx_nmoduli(param_ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_GALOIS_KEY_GENERATE_WORKSPACE_N(cche_param_ctx_polynomial_degree(param_ctx), nmoduli));
    int rv = cche_galois_key_generate_ws(ws, galois_key, ngalois_elts, galois_elts, secret_key, param_ctx, nseeds, seeds, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cche_galois_key_save_ws(cc_ws_t ws, uint32_t nbytes_poly0s, uint8_t *poly0s, cche_galois_key_const_t galois_key)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_ctx_const_t key_ctx = cche_param_ctx_encrypt_key_context(galois_key->param_ctx);
    uint32_t ngalois_elts = galois_key->ngalois_elts;
    uint32_t nciphers = key_ctx->dims.nmoduli - 1;
    size_t nbytes_per_poly = ccpolyzp_po2cyc_serialize_poly_nbytes(key_ctx, 0);
    cc_require_or_return(nbytes_poly0s == ngalois_elts * nciphers * nbytes_per_poly, CCERR_PARAMETER);

    for (uint32_t galois_elt_idx = 0; galois_elt_idx < ngalois_elts; ++galois_elt_idx) {
        for (uint32_t cipher_idx = 0; cipher_idx < nciphers; ++cipher_idx) {
            cche_ciphertext_eval_const_t ciphertext = cche_galois_key_ciphertext_const(galois_key, galois_elt_idx, cipher_idx);
            ccpolyzp_po2cyc_eval_const_t poly = cche_ciphertext_eval_polynomial_const(ciphertext, 0);
            rv = ccpolyzp_po2cyc_serialize_poly_ws(ws, nbytes_per_poly, poly0s, 0, (ccpolyzp_po2cyc_const_t)poly);
            cc_require(rv == CCERR_OK, errOut);
            poly0s += nbytes_per_poly;
        }
    }

errOut:
    return rv;
}

int cche_galois_key_save(uint32_t nbytes_poly0s, uint8_t *poly0s, cche_galois_key_const_t galois_key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_GALOIS_KEY_SAVE_WORKSPACE_N(cche_param_ctx_polynomial_degree(galois_key->param_ctx)));
    int rv = cche_galois_key_save_ws(ws, nbytes_poly0s, poly0s, galois_key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

/// @brief Loads a Galois key from a single keyswitching key
/// @param ws Workspace
/// @param galois_key Galois key to populate
/// @param galois_elt Galois element; must be odd in [3, 2N - 1]
/// @param galois_elt_idx Index of Galois element in the Galois key
/// @param param_ctx Parameter context
/// @param poly0s Buffer to an array of serialized polynomials that make up the first polynomial of the ciphertexts
/// @param seeds Buffer to an array of RNG seeds that store the seeds for the second polynomial of ciphertexts
/// @return CCERR_OK if Galois key was generated successfully
CC_WARN_RESULT CC_NONNULL((1, 2, 5, 6)) static int cche_galois_key_load_single_ws(cc_ws_t ws,
                                                                                  cche_galois_key_t galois_key,
                                                                                  uint32_t galois_elt,
                                                                                  uint32_t galois_elt_idx,
                                                                                  cche_param_ctx_const_t param_ctx,
                                                                                  const uint8_t *poly0s,
                                                                                  const uint8_t *seeds)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_ctx_const_t key_ctx = cche_param_ctx_encrypt_key_context(param_ctx);
    cc_require_or_return(key_ctx->dims.nmoduli > 1, CCERR_PARAMETER);

    uint32_t degree = cche_param_ctx_polynomial_degree(param_ctx);
    cc_require_or_return(is_valid_galois_element_and_degree(galois_elt, degree), CCERR_PARAMETER);
    cc_require_or_return(galois_elt_idx < galois_key->ngalois_elts, CCERR_PARAMETER);

    const size_t nbytes_per_poly = ccpolyzp_po2cyc_serialize_poly_nbytes(key_ctx, 0);

    uint32_t *galois_key_elts = CCHE_GALOIS_KEY_GALOIS_ELTS(galois_key);
    galois_key_elts[galois_elt_idx] = galois_elt;

    uint32_t nciphers = key_ctx->dims.nmoduli - 1;
    for (uint32_t rns_idx = 0; rns_idx < nciphers; ++rns_idx) {
        cche_ciphertext_eval_t galois_cipher = cche_galois_key_ciphertext(galois_key, galois_elt_idx, rns_idx);
        cche_ciphertext_eval_init(galois_cipher, param_ctx, cche_ciphertext_fresh_npolys(), key_ctx);
        rv = cche_deserialize_seeded_ciphertext_eval_ws(ws, galois_cipher, nbytes_per_poly, poly0s, (cche_rng_seed_const_t)seeds);
        cc_require(rv == CCERR_OK, errOut);
        poly0s += nbytes_per_poly;
        seeds += cche_rng_seed_sizeof();
    }

errOut:
    return rv;
}

int cche_galois_key_load_ws(cc_ws_t ws,
                            cche_galois_key_t galois_key,
                            uint32_t ngalois_elts,
                            const uint32_t *galois_elts,
                            cche_param_ctx_const_t param_ctx,
                            uint32_t nbytes_poly0s,
                            const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                            uint32_t nbytes_seeds,
                            const uint8_t *cc_counted_by(nbytes_seeds) seeds)
{
    cc_require_or_return(ngalois_elts > 0, CCERR_PARAMETER);
    int rv = CCERR_OK;

    ccpolyzp_po2cyc_ctx_const_t key_ctx = cche_param_ctx_encrypt_key_context(param_ctx);
    uint32_t nciphers = key_ctx->dims.nmoduli - 1;
    size_t nbytes_per_poly = ccpolyzp_po2cyc_serialize_poly_nbytes(key_ctx, 0);
    size_t nbytes_per_seed = cche_rng_seed_sizeof();
    cc_require_or_return(nbytes_poly0s == nciphers * ngalois_elts * nbytes_per_poly, CCERR_PARAMETER);
    cc_require_or_return(nbytes_seeds == nciphers * ngalois_elts * nbytes_per_seed, CCERR_PARAMETER);

    galois_key->param_ctx = param_ctx;
    galois_key->ngalois_elts = ngalois_elts;

    // check for uniqueness of Galois elements
    for (uint32_t galois_elt_idx = 0; galois_elt_idx < ngalois_elts; ++galois_elt_idx) {
        for (uint32_t i = 0; i < galois_elt_idx; ++i) {
            if (galois_elts[i] == galois_elts[galois_elt_idx]) {
                return CCERR_PARAMETER;
            }
        }
    }

    for (uint32_t galois_elt_idx = 0; galois_elt_idx < ngalois_elts; ++galois_elt_idx) {
        const uint8_t *single_poly0s = poly0s + galois_elt_idx * nciphers * nbytes_per_poly;
        const uint8_t *single_seeds = seeds + galois_elt_idx * nciphers * nbytes_per_seed;
        rv = cche_galois_key_load_single_ws(
            ws, galois_key, galois_elts[galois_elt_idx], galois_elt_idx, param_ctx, single_poly0s, single_seeds);
        cc_require(rv == CCERR_OK, errOut);
    }

errOut:
    return rv;
}

int cche_galois_key_load(cche_galois_key_t galois_key,
                         uint32_t ngalois_elts,
                         const uint32_t *galois_elts,
                         cche_param_ctx_const_t param_ctx,
                         uint32_t nbytes_poly0s,
                         const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                         uint32_t nbytes_seeds,
                         const uint8_t *cc_counted_by(nbytes_seeds) seeds)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_GALOIS_KEY_LOAD_WORKSPACE_N(cche_param_ctx_polynomial_degree(param_ctx)));
    int rv =
        cche_galois_key_load_ws(ws, galois_key, ngalois_elts, galois_elts, param_ctx, nbytes_poly0s, poly0s, nbytes_seeds, seeds);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

/// @brief Returns the Galois element at a given index
/// @param galois_key Galois key
/// @param galois_elt_idx Index of the Galois element to retrieve; must be in [0, galois_key->ngalois_elements - 1]
static CC_WARN_RESULT CC_NONNULL((1)) uint32_t
    cche_galois_key_galois_element(cche_galois_key_const_t galois_key, uint32_t galois_elt_idx)
{
    cc_assert(galois_elt_idx < galois_key->ngalois_elts);
    const uint32_t *galois_elts = CCHE_GALOIS_KEY_GALOIS_ELTS_CONST(galois_key);
    return galois_elts[galois_elt_idx];
}

bool cche_galois_key_find_galois_elt(uint32_t *galois_elt_idx, uint32_t galois_elt, cche_galois_key_const_t galois_key)
{
    for (uint32_t i = 0; i < galois_key->ngalois_elts; ++i) {
        if (cche_galois_key_galois_element(galois_key, i) == galois_elt) {
            if (galois_elt_idx) {
                *galois_elt_idx = i;
            }
            return true;
        }
    }
    return false;
}

cc_size CCHE_CIPHERTEXT_APPLY_GALOIS_WORKSPACE_N(cc_size degree, cc_size nctext_moduli)
{
    return CCHE_CIPHERTEXT_GALOIS_KEY_SWITCH_WORKSPACE_N(degree, nctext_moduli + 1);
}

int cche_ciphertext_apply_galois_ws(cc_ws_t ws,
                                    cche_ciphertext_coeff_t r,
                                    cche_ciphertext_coeff_const_t ctext,
                                    uint32_t galois_elt,
                                    cche_galois_key_const_t galois_key)
{
    int rv = CCERR_OK;
    cc_require_or_return(cche_galois_key_find_galois_elt(NULL, galois_elt, galois_key), CCERR_PARAMETER);
    cc_require_or_return(r != ctext, CCERR_PARAMETER);

    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        ccpolyzp_po2cyc_coeff_const_t ctext_poly = cche_ciphertext_coeff_polynomial_const(ctext, poly_idx);
        ccpolyzp_po2cyc_coeff_t r_poly = cche_ciphertext_coeff_polynomial(r, poly_idx);
        rv = ccpolyzp_po2cyc_coeff_apply_galois(r_poly, ctext_poly, galois_elt);
        cc_require(rv == CCERR_OK, errOut);
    }
    rv = cche_ciphertext_galois_key_switch_ws(ws, r, galois_elt, galois_key);

errOut:
    return rv;
}

int cche_ciphertext_apply_galois(cche_ciphertext_coeff_t r,
                                 cche_ciphertext_coeff_const_t ctext,
                                 uint32_t galois_elt,
                                 cche_galois_key_const_t galois_key)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_ctx_const_t key_ctx = cche_param_ctx_encrypt_key_context(galois_key->param_ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_CIPHERTEXT_APPLY_GALOIS_WORKSPACE_N(key_ctx->dims.degree, key_ctx->dims.nmoduli));
    int rv = cche_ciphertext_apply_galois_ws(ws, r, ctext, galois_elt, galois_key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

cc_size CCHE_CIPHERTEXT_GALOIS_KEY_SWITCH_WORKSPACE_N(cc_size degree, cc_size ngalois_key_moduli)
{
    uint32_t npolys = cche_ciphertext_fresh_npolys();
    struct ccpolyzp_po2cyc_dims galois_key_dims = { .nmoduli = (uint32_t)ngalois_key_moduli, .degree = (uint32_t)degree };
    struct ccpolyzp_po2cyc_dims buffer_dims = { .nmoduli = 1, .degree = (uint32_t)degree };
    return (cche_ciphertext_nof_n(&galois_key_dims, npolys)) + (2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * degree * npolys) +
           (ccpolyzp_po2cyc_nof_n(&buffer_dims)) + (ccpolyzp_po2cyc_ctx_nof_n((uint32_t)degree)) +
           CCHE_CIPHERTEXT_MOD_SWITCH_DOWN_WORKSPACE_N(degree, ngalois_key_moduli);
}

int cche_ciphertext_galois_key_switch_ws(cc_ws_t ws,
                                         cche_ciphertext_coeff_t r,
                                         uint32_t galois_elt,
                                         cche_galois_key_const_t galois_key)
{
    uint32_t galois_elt_idx;
    cc_require_or_return(cche_galois_key_find_galois_elt(&galois_elt_idx, galois_elt, galois_key), CCERR_PARAMETER);
    cc_require_or_return(r->npolys == cche_ciphertext_fresh_npolys(), CCERR_PARAMETER);
    int rv = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

    ccpolyzp_po2cyc_ctx_const_t galois_key_ctx = cche_param_ctx_encrypt_key_context(galois_key->param_ctx);
    uint32_t galois_key_nmoduli = galois_key_ctx->dims.nmoduli;
    uint32_t ctext_nmoduli = cche_ciphertext_coeff_ctx(r)->dims.nmoduli;

    /// Compute r[0] += r[1] * galois_cipher[0], r[1] *= galois_cipher[1])
    /// We first compute the products in a 128-bit accumulator, delaying modular reduction for improved performance.
    // Then, we perform the addition.
    cche_ciphertext_eval_t ctext_galois_prod = CCHE_CIPHERTEXT_EVAL_ALLOC_WS(ws, galois_key_ctx, cche_ciphertext_fresh_npolys());
    cche_ciphertext_eval_init(ctext_galois_prod, galois_key->param_ctx, cche_ciphertext_fresh_npolys(), galois_key_ctx);

    uint32_t degree = galois_key_ctx->dims.degree;
    ccpolyzp_po2cyc_coeff_t ct_galois = cche_ciphertext_coeff_polynomial(r, 1);

    // Allocate memory for a lazy 128-bit accumulator
    uint32_t ctext_npolys = r->npolys;
    cc_unit *poly_lazy_128 = CC_ALLOC_WS(ws, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * degree * ctext_npolys);

    struct ccpolyzp_po2cyc_dims buffer_dims = { .nmoduli = 1, .degree = degree };
    ccpolyzp_po2cyc_t buffer = CCPOLYZP_PO2CYC_ALLOC_WS(ws, &buffer_dims);
    ccpolyzp_po2cyc_ctx_t buffer_ctx = CCPOLYZP_PO2CYC_CTX_ALLOC_WS(ws, degree);

    for (uint32_t rns_idx = 0; rns_idx < galois_key_nmoduli; ++rns_idx) {
        uint32_t galois_key_idx = (rns_idx == galois_key_nmoduli - 1) ? galois_key_ctx->dims.nmoduli - 1 : rns_idx;
        ccrns_modulus_const_t key_modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(galois_key_ctx, rns_idx);

        // Set buffer context to a single modulus: key_modulus
        ccpolyzp_po2cyc_ctx_copy(buffer_ctx, ccpolyzp_po2cyc_ctx_idx_const(galois_key_ctx, rns_idx));
        buffer_ctx->dims.nmoduli = 1;
        buffer_ctx->next = NULL;
        ccpolyzp_po2cyc_init_zero(buffer, buffer_ctx);

        ccn_clear(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * degree * ctext_npolys, poly_lazy_128);

        // Iterate over RNS components of target and key-switching key (i.e., P_{Q_i}(s_A))
        for (uint32_t j = 0; j < ctext_nmoduli; ++j) {
            ccrns_modulus_const_t q_key_j = ccpolyzp_po2cyc_ctx_ccrns_modulus(galois_key_ctx, j);
            cche_ciphertext_eval_const_t galois_cipher = cche_galois_key_ciphertext_const(galois_key, 0, j);
            // Extend the digits of r from base Q_i to base [Q_i, q_ks]
            if (q_key_j->value <= key_modulus->value) {
                // We can't use ccpolyzp_po2cyc_eval_copy, since buffer and ct_galois have differing context dimensions
                const cc_unit *ct_galois_data = CCPOLYZP_PO2CYC_DATA_CONST(ct_galois, j, 0);
                cc_unit *buffer_data = CCPOLYZP_PO2CYC_DATA(buffer, 0, 0);
                cc_memcpy(buffer_data, ct_galois_data, ccn_sizeof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * degree));
            } else {
                for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
                    ccrns_int ctext_galois_coeff = ccpolyzp_po2cyc_coeff_data_int(ct_galois, j, coeff_idx);
                    ccrns_int buffer_coeff = ccpolyzp_po2cyc_scalar_mod1(ctext_galois_coeff, key_modulus);
                    ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(buffer, 0, coeff_idx), buffer_coeff);
                }
            }
            // Put the digits of r in NTT form
            cc_require(rv = ccpolyzp_po2cyc_fwd_ntt((ccpolyzp_po2cyc_coeff_t)buffer) == CCERR_OK, errOut);

            // Perform the product with the key-switching key, delaying modular reduction during accumulation
            for (uint32_t k = 0; k < ctext_npolys; ++k) {
                ccpolyzp_po2cyc_eval_const_t gk_poly = cche_ciphertext_eval_polynomial_const(galois_cipher, k);

                for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
                    const cc_unit *gk_data = CCPOLYZP_PO2CYC_DATA_CONST(gk_poly, galois_key_idx, coeff_idx);
                    const cc_unit *buffer_data = CCPOLYZP_PO2CYC_DATA_CONST(buffer, 0, coeff_idx);

                    cc_unit *lazy_128_rns = &poly_lazy_128[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * (k * degree + coeff_idx)];
                    cc_unit prod[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] = { 0 };
                    ccn_mul(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, prod, gk_data, buffer_data);

                    cc_unit carry = ccn_add_ws(ws, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, lazy_128_rns, lazy_128_rns, prod);
                    cc_require_or_return(carry == 0, CCERR_INTERNAL);
                }
            }
        }
        // Reduce the 128-bit product mod q_ks
        for (uint32_t k = 0; k < ctext_npolys; ++k) {
            ccpolyzp_po2cyc_eval_t poly_prod = cche_ciphertext_eval_polynomial(ctext_galois_prod, k);
            for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
                cc_unit *poly_lazy_coeff = &poly_lazy_128[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * (k * degree + coeff_idx)];
                ccrns_int prod_rns_coeff = ccpolyzp_po2cyc_scalar_mod2(poly_lazy_coeff, key_modulus);
                cc_unit *ct_galois_prod_coeff = CCPOLYZP_PO2CYC_DATA(poly_prod, rns_idx, coeff_idx);
                ccpolyzp_po2cyc_rns_int_to_units(ct_galois_prod_coeff, prod_rns_coeff);
            }
        }
    }
    // Compute the inverse NTT in base [Q, q_ks]
    cc_require((rv = cche_ciphertext_inv_ntt(ctext_galois_prod)) == CCERR_OK, errOut);
    cche_ciphertext_coeff_t ctext_galois_prod_coeff = (cche_ciphertext_coeff_t)ctext_galois_prod;
    // Multiply the result by q_{ks}^{-1} mod Q, while switching to base Q
    cc_require((rv = cche_ciphertext_mod_switch_down_ws(ws, ctext_galois_prod_coeff)) == CCERR_OK, errOut);

    // r[0] += ct_galois_prod[0]
    ccpolyzp_po2cyc_coeff_t r_poly_0 = cche_ciphertext_coeff_polynomial(r, 0);
    ccpolyzp_po2cyc_coeff_const_t ctext_galois_prod_poly_0 = cche_ciphertext_coeff_polynomial_const(ctext_galois_prod_coeff, 0);
    ccpolyzp_po2cyc_coeff_add(r_poly_0, r_poly_0, ctext_galois_prod_poly_0);

    // r[1] = ct_galois_prod[1]
    ccpolyzp_po2cyc_coeff_t r_poly_1 = cche_ciphertext_coeff_polynomial(r, 1);
    ccpolyzp_po2cyc_coeff_const_t ctext_galois_prod_poly_1 = cche_ciphertext_coeff_polynomial_const(ctext_galois_prod_coeff, 1);
    ccpolyzp_po2cyc_coeff_copy(r_poly_1, ctext_galois_prod_poly_1);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/// @brief Computes the Galois element given a signed step
/// @param galois_elt Will store the Galois element for the step
/// @param step Number of steps to shift left. A negative step indicates a right shift
/// @param degree Polynomial modulus degree
/// @return CCERR_OK if Galois element is computed successfully
/// @details Not constant time
static int cche_galois_elt_from_step(uint32_t *galois_elt, int32_t step, uint32_t degree)
{
    cc_require_or_return(ccpolyzp_po2cyc_is_power_of_two_uint32(degree), CCERR_PARAMETER);
    uint32_t abs_step = (step < 0) ? (uint32_t)(-step) : (uint32_t)step;
    cc_require_or_return(abs_step < (degree >> 1), CCERR_PARAMETER);

    uint64_t twice_degree = 2 * degree;
    abs_step &= (twice_degree - 1);

    uint32_t power = step < 0 ? ((degree >> 1) - abs_step) : abs_step;
    // g^power % 2N
    uint64_t galois_elt_u64 = 1;
    for (uint32_t i = 0; i < power; ++i) {
        bool overflow = cc_mul_overflow(galois_elt_u64, (uint64_t)cche_encoding_generator_column, &galois_elt_u64);
        cc_require_or_return(!overflow, CCERR_INTERNAL);
        galois_elt_u64 &= twice_degree - 1;
    }
    *galois_elt = (uint32_t)galois_elt_u64;

    return CCERR_OK;
}

int cche_ciphertext_galois_elt_rotate_rows_left(uint32_t *galois_elt, uint32_t step, uint32_t degree)
{
    CC_ENSURE_DIT_ENABLED

    return cche_galois_elt_from_step(galois_elt, (int32_t)step, degree);
}

int cche_ciphertext_galois_elt_rotate_rows_right(uint32_t *galois_elt, uint32_t step, uint32_t degree)
{
    CC_ENSURE_DIT_ENABLED

    return cche_galois_elt_from_step(galois_elt, -(int32_t)step, degree);
}

int cche_ciphertext_galois_elt_swap_columns(uint32_t *galois_elt, uint32_t degree)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(ccpolyzp_po2cyc_is_power_of_two_uint32(degree), CCERR_PARAMETER);
    *galois_elt = cche_encoding_generator_row(degree);
    return CCERR_OK;
}

cc_size CCHE_CIPHERTEXT_ROTATE_ROWS_LEFT_WORKSPACE_N(cc_size degree, cc_size nctext_moduli)
{
    return CCHE_CIPHERTEXT_APPLY_GALOIS_WORKSPACE_N(degree, nctext_moduli);
}

int cche_ciphertext_rotate_rows_left_ws(cc_ws_t ws,
                                        cche_ciphertext_coeff_t r,
                                        cche_ciphertext_coeff_const_t ctext,
                                        uint32_t step,
                                        cche_galois_key_const_t galois_key)
{
    uint32_t degree = cche_param_ctx_polynomial_degree(galois_key->param_ctx);
    cc_require_or_return(step > 0 && step < degree, CCERR_PARAMETER);
    int rv = CCERR_OK;
    uint32_t galois_elt;
    cc_require((rv = cche_ciphertext_galois_elt_rotate_rows_left(&galois_elt, step, degree)) == CCERR_OK, errOut);
    cc_require((rv = cche_ciphertext_apply_galois_ws(ws, r, ctext, galois_elt, galois_key)) == CCERR_OK, errOut);

errOut:
    return rv;
}

cc_size CCHE_CIPHERTEXT_ROTATE_ROWS_RIGHT_WORKSPACE_N(cc_size degree, cc_size nctext_moduli)
{
    return CCHE_CIPHERTEXT_ROTATE_ROWS_LEFT_WORKSPACE_N(degree, nctext_moduli);
}

int cche_ciphertext_rotate_rows_right_ws(cc_ws_t ws,
                                         cche_ciphertext_coeff_t r,
                                         cche_ciphertext_coeff_const_t ctext,
                                         uint32_t step,
                                         cche_galois_key_const_t galois_key)
{
    uint32_t degree = cche_param_ctx_polynomial_degree(galois_key->param_ctx);
    cc_require_or_return(step > 0 && step < degree, CCERR_PARAMETER);
    return cche_ciphertext_rotate_rows_left_ws(ws, r, ctext, (degree >> 1) - step, galois_key);
}

cc_size CCHE_CIPHERTEXT_SWAP_COLUMNS_WORKSPACE_N(cc_size degree, cc_size nctext_moduli)
{
    return CCHE_CIPHERTEXT_APPLY_GALOIS_WORKSPACE_N(degree, nctext_moduli);
}

int cche_ciphertext_swap_columns_ws(cc_ws_t ws,
                                    cche_ciphertext_coeff_t r,
                                    cche_ciphertext_coeff_const_t ctext,
                                    cche_galois_key_const_t galois_key)
{
    int rv = CCERR_OK;

    uint32_t degree = cche_param_ctx_polynomial_degree(galois_key->param_ctx);
    uint32_t galois_elt;
    cc_require((rv = cche_ciphertext_galois_elt_swap_columns(&galois_elt, degree)) == CCERR_OK, errOut);
    cc_require((rv = cche_ciphertext_apply_galois_ws(ws, r, ctext, galois_elt, galois_key)) == CCERR_OK, errOut);

errOut:
    return rv;
}
