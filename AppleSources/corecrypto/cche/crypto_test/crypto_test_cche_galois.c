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

#include "testmore.h"
#include "cche_debug.h"
#include "cche_internal.h"
#include "cche_galois_key.h"
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_galois.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "crypto_test_cche.h"
#include <corecrypto/ccrng.h>
#include "ccpolyzp_po2cyc_serialization.h"

// Override CC_DECL_WORKSPACE_TEST(ws) and increase the test workspace size to 2 MB
#undef CC_DECL_WORKSPACE_TEST
#define CC_DECL_WORKSPACE_TEST(ws)                                    \
    int ws##_rv;                                                      \
    CC_DECL_WORKSPACE_RV(ws, ccn_nof_size(2 * 1024 * 1024), ws##_rv); \
    cc_try_abort_if(ws##_rv != CCERR_OK, "alloc ws");

static const uint32_t degree = 16;
static const ccrns_int plaintext_modulus = 40961;

static void test_cche_galois_key_error(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    CC_DECL_BP_WS(ws, bp);
    // 2 moduli
    {
        cche_encrypt_params_const_t encrypt_parms_2 = get_test_encrypt_params(he_scheme, 2);
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_parms_2);
        is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_parms_2), CCERR_OK, "BFV/BGV param ctx init (2 moduli)");

        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

        uint32_t galois_elts[] = { 3 };
        cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));

        // ok
        {
            is(cche_galois_key_generate_ws(
                   ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng),
               CCERR_OK,
               "Galois key generation");
        }
        // invalid number of galois element
        {
            is(cche_galois_key_generate_ws(ws, galois_key, 0, galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng),
               CCERR_PARAMETER,
               "Galois key 0 Galois elements");
        }
        // invalid Galois element - even
        {
            uint32_t invalid_galois_elts[] = { 4 };
            is(cche_galois_key_generate_ws(ws,
                                           galois_key,
                                           CC_ARRAY_LEN(invalid_galois_elts),
                                           invalid_galois_elts,
                                           secret_key,
                                           param_ctx,
                                           0,
                                           NULL,
                                           global_test_rng),
               CCERR_PARAMETER,
               "Galois key invalid Galois element even");
        }
        // invalid Galois element 1
        {
            uint32_t invalid_galois_elts[] = { 1 };
            is(cche_galois_key_generate_ws(ws,
                                           galois_key,
                                           CC_ARRAY_LEN(invalid_galois_elts),
                                           invalid_galois_elts,
                                           secret_key,
                                           param_ctx,
                                           0,
                                           NULL,
                                           global_test_rng),
               CCERR_PARAMETER,
               "Galois key invalid Galois element 1");
        }
        // repeated Galois element
        {
            uint32_t repeated_galois_elts[] = { 3, 3 };
            is(cche_galois_key_generate_ws(ws,
                                           galois_key,
                                           CC_ARRAY_LEN(repeated_galois_elts),
                                           repeated_galois_elts,
                                           secret_key,
                                           param_ctx,
                                           0,
                                           NULL,
                                           global_test_rng),
               CCERR_PARAMETER,
               "Galois key repeated Galois element");
        }
        // invalid number of seeds
        {
            is(cche_galois_key_generate_ws(
                   ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 2, NULL, global_test_rng),
               CCERR_PARAMETER,
               "Galois key invalid number of seeds");
        }
        // wrong secret key context
        {
            cche_encrypt_params_const_t encrypt_params_3 = get_test_encrypt_params(CCHE_SCHEME_BFV, 3);
            cche_param_ctx_t param_ctx_diff = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_3);
            is(cche_param_ctx_init_ws(ws, param_ctx_diff, encrypt_params_3), CCERR_OK, "BFV/BGV param ctx init");

            cche_secret_key_t secret_key_diff = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx_diff);
            is(cche_secret_key_generate_ws(ws, secret_key_diff, param_ctx_diff, global_test_rng),
               CCERR_OK,
               "Secret key generation");

            is(cche_galois_key_generate_ws(
                   ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key_diff, param_ctx, 0, NULL, global_test_rng),
               CCERR_PARAMETER,
               "Galois key invalid secret key");
        }
        CC_FREE_BP_WS(ws, bp);
    }
    // 1 modulus
    {
        cche_encrypt_params_const_t encrypt_params_1 = get_test_encrypt_params(CCHE_SCHEME_BFV, 1);
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_1);
        is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params_1), CCERR_OK, "BFV/BGV param ctx init (1 modulus)");

        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

        uint32_t galois_elts[] = { 3 };
        cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));
        is(cche_galois_key_generate_ws(
               ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng),
           CCERR_PARAMETER,
           "Galois key 1 modulus");
        CC_FREE_BP_WS(ws, bp);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_galois_key_generate(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    CC_DECL_BP_WS(ws, bp);

    // 2 moduli
    {
        cche_encrypt_params_const_t encrypt_params_2 = get_test_encrypt_params(he_scheme, 2);
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_2);
        is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params_2), CCERR_OK, "BFV/BGV param ctx init (2 moduli)");

        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

        uint32_t galois_elts[] = { 3 };
        cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));

        is(cche_galois_key_generate_ws(
               ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng),
           CCERR_OK,
           "Galois key generation");
        is(cche_galois_key_find_galois_elt(NULL, 3, galois_key), true, "Galois key has element 3");
        is(cche_galois_key_find_galois_elt(NULL, 5, galois_key), false, "Galois key doesn't have element 5");
        CC_FREE_BP_WS(ws, bp);
    }
    // 3 moduli
    {
        cche_encrypt_params_const_t encrypt_params_3 = get_test_encrypt_params(he_scheme, 3);
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_3);
        is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params_3), CCERR_OK, "BFV/BGV param ctx init (3 moduli)");

        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

        uint32_t galois_elts[] = { 3, 5 };
        cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));

        is(cche_galois_key_generate_ws(
               ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng),
           CCERR_OK,
           "Galois key generation");
        is(cche_galois_key_find_galois_elt(NULL, 3, galois_key), true, "Galois key has element 3");
        is(cche_galois_key_find_galois_elt(NULL, 5, galois_key), true, "Galois key has element 5");
        is(cche_galois_key_find_galois_elt(NULL, 7, galois_key), false, "Galois key doesn't have element 7");
        CC_FREE_BP_WS(ws, bp);
    }
    // 4 moduli
    {
        cche_encrypt_params_const_t encrypt_params_4 = get_test_encrypt_params(he_scheme, 4);
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_4);
        is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params_4), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");

        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

        uint32_t galois_elts[] = { 3, 5, 7, 11 };
        cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));

        is(cche_galois_key_generate_ws(
               ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng),
           CCERR_OK,
           "Galois key generation");
        is(cche_galois_key_find_galois_elt(NULL, 3, galois_key), true, "Galois key has element 3");
        is(cche_galois_key_find_galois_elt(NULL, 5, galois_key), true, "Galois key has element 5");
        is(cche_galois_key_find_galois_elt(NULL, 7, galois_key), true, "Galois key has element 7");
        is(cche_galois_key_find_galois_elt(NULL, 9, galois_key), false, "Galois key doesn't have element 9");
        is(cche_galois_key_find_galois_elt(NULL, 11, galois_key), true, "Galois key has element 11");
        CC_FREE_BP_WS(ws, bp);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_galois_key_generate_deserialize(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    CC_DECL_BP_WS(ws, bp);

    // 4 moduli
    {
        cche_encrypt_params_const_t encrypt_params_4 = get_test_encrypt_params(he_scheme, 4);
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_4);
        is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params_4), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");

        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

        uint32_t galois_elts[] = { 3, 5, 7, 11 };
        uint32_t ngalois_elts = CC_ARRAY_LEN(galois_elts);
        cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, ngalois_elts);

        const uint32_t nbytes_per_poly = (uint32_t)cche_param_ctx_key_ctx_poly_nbytes(param_ctx);
        const uint32_t nciphers_per_element = cche_param_ctx_key_ctx_nmoduli(param_ctx) - 1;
        const uint32_t nciphers = nciphers_per_element * ngalois_elts;
        const uint32_t nbytes_poly0s = nbytes_per_poly * nciphers;
        const uint32_t nbytes_seeds = (uint32_t)cche_rng_seed_sizeof() * nciphers;

        uint8_t *poly0s = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes_poly0s));
        uint8_t *seeds = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes_seeds));

        is(cche_galois_key_generate_ws(ws,
                                       galois_key,
                                       CC_ARRAY_LEN(galois_elts),
                                       galois_elts,
                                       secret_key,
                                       param_ctx,
                                       nbytes_seeds,
                                       seeds,
                                       global_test_rng),
           CCERR_OK,
           "Galois key generation");

        is(cche_galois_key_save_ws(ws, nbytes_poly0s, poly0s, galois_key), CCERR_OK, "Galois key save");

        cche_galois_key_t galois_key_loaded = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, ngalois_elts);
        is(cche_galois_key_load_ws(
               ws, galois_key_loaded, ngalois_elts, galois_elts, param_ctx, nbytes_poly0s, poly0s, nbytes_seeds, seeds),
           CCERR_OK,
           "Galois key load");

        is(cche_galois_key_find_galois_elt(NULL, 3, galois_key_loaded), true, "Galois key has element 3");
        is(cche_galois_key_find_galois_elt(NULL, 5, galois_key_loaded), true, "Galois key has element 5");
        is(cche_galois_key_find_galois_elt(NULL, 7, galois_key_loaded), true, "Galois key has element 7");
        is(cche_galois_key_find_galois_elt(NULL, 9, galois_key_loaded), false, "Galois key doesn't have element 9");
        is(cche_galois_key_find_galois_elt(NULL, 11, galois_key_loaded), true, "Galois key has element 11");

        for (uint32_t galois_elt_idx = 0; galois_elt_idx < ngalois_elts; ++galois_elt_idx) {
            for (uint32_t cipher_idx = 0; cipher_idx < nciphers_per_element; ++cipher_idx) {
                cche_ciphertext_eval_const_t galois_cipher =
                    cche_galois_key_ciphertext_const(galois_key, galois_elt_idx, cipher_idx);
                cche_ciphertext_eval_const_t galois_cipher_loaded =
                    cche_galois_key_ciphertext_const(galois_key_loaded, galois_elt_idx, cipher_idx);
                is(cche_ciphertext_eval_eq(galois_cipher, galois_cipher_loaded), true, "Galois key cipher");
            }
        }

        CC_FREE_BP_WS(ws, bp);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_apply_galois_error(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    uint32_t galois_elts[] = { 3 };

    cche_encrypt_params_const_t encrypt_params_2 = get_test_encrypt_params(he_scheme, 2);
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_2);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params_2), CCERR_OK, "BFV/BGV param ctx init (2 moduli)");
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));
    int rv = cche_galois_key_generate_ws(
        ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng);
    is(rv, CCERR_OK, "Galois key generation");

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = (cche_plaintext_t)CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);

    uint64_t zeros[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        zeros[i] = 0;
    }
    is(cche_encode_simd_uint64(ptext, param_ctx, degree, zeros), CCERR_OK, "cche_encode_simd_uint64 != CCERR_OK");

    // ctext = Enc(ptext, sk)
    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    uint32_t ctext_nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;
    rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, ctext_nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV/BGV encrypt symmetric no seed");

    cche_ciphertext_coeff_t ctext_galois =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_coeff_copy(ctext_galois, ctext);

    // ok
    {
        is(cche_ciphertext_apply_galois_ws(ws, ctext_galois, ctext, galois_elts[0], galois_key),
           CCERR_OK,
           "BFV/BGV apply galois");
    }
    // Galois element not in Galois key
    {
        is(cche_ciphertext_apply_galois_ws(ws, ctext_galois, ctext, 5, galois_key),
           CCERR_PARAMETER,
           "BFV/BGV apply galois missing element");
    }
    // in-place
    {
        is(cche_ciphertext_apply_galois_ws(ws, ctext_galois, ctext_galois, galois_elts[0], galois_key),
           CCERR_PARAMETER,
           "BFV/BGV apply galois in-place");
    }

    CC_FREE_WORKSPACE(ws);
}

/// @brief Generates a random Galois element
/// @param degree The polynmomial degree, N
/// @return A random Galois element, which is odd in [3, 2N - 1]
static uint32_t random_galois_element(uint32_t degree)
{
    uint64_t galois_elt_u64;
    is(ccrng_uniform(global_test_rng, (uint64_t)degree - 1, &galois_elt_u64), CCERR_OK, "ccrng_uniform != CCERR_OK");
    uint32_t galois_elt = 2 * (uint32_t)galois_elt_u64 + 3; // in [3, 2N - 1]
    return galois_elt;
}

/// @brief Runs a single test of encryption, apply_galois, and decryption
/// @param ws Workspace
/// @param encrypt_params The encryption parameters for the test
/// @param galois_elt The Galois element
/// @param coeffs_in The input plaintext coefficients
/// @param coeffs_out The expected output plaintext coefficients
static void test_cche_encrypt_galois_decrypt_helper_single_ws(cc_ws_t ws,
                                                              cche_encrypt_params_const_t encrypt_params,
                                                              uint32_t galois_elt,
                                                              const ccrns_int *cc_counted_by(encrypt_params->degree) coeffs_in,
                                                              const ccrns_int *cc_counted_by(encrypt_params->degree) coeffs_out)
{
    CC_DECL_BP_WS(ws, bp);

    uint32_t galois_elts[] = { galois_elt };

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 modulus)");
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));
    int rv = cche_galois_key_generate_ws(
        ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng);
    is(rv, CCERR_OK, "Galois key generation");

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);

    uint64_t zeros[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        zeros[i] = 0;
    }
    is(cche_encode_simd_uint64(ptext, param_ctx, degree, zeros), CCERR_OK, "cche_encode_simd_uint64 != CCERR_OK");
    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        *CCPOLYZP_PO2CYC_DATA(cche_plaintext_polynomial(ptext), 0, coeff_idx) = coeffs_in[coeff_idx];
    }

    // ctext = Enc(ptext, sk)
    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    uint32_t ctext_nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;
    rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, ctext_nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV/BGV encrypt symmetric no seed");

    cche_ciphertext_coeff_t ctext_galois =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_coeff_copy(ctext_galois, ctext);
    is(cche_ciphertext_apply_galois_ws(ws, ctext_galois, ctext, galois_elts[0], galois_key), CCERR_OK, "BFV/BGV apply galois");
    is(cche_decrypt_ws(ws, ptext, param_ctx, ctext_galois, secret_key), CCERR_OK, "BFV/BGV decrypt");

    ccrns_int ptext_coeffs[degree];
    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        ptext_coeffs[coeff_idx] = ccpolyzp_po2cyc_coeff_data_int(cche_plaintext_polynomial(ptext), 0, coeff_idx);
    }

    is(array_eq_uint64(degree, ptext_coeffs, coeffs_out), true, "BFV/BGV galois plaintext coeffs not equal");

    CC_FREE_BP_WS(ws, bp);
}

static void test_cche_encrypt_galois_decrypt_params(cche_scheme_t he_scheme,
                                                    uint32_t galois_elt,
                                                    const ccrns_int *cc_counted_by(degree) coeffs_in,
                                                    const ccrns_int *cc_counted_by(degree) coeffs_out)
{
    CC_DECL_WORKSPACE_TEST(ws);

    for (uint32_t nmoduli = 2; nmoduli <= 5; ++nmoduli) {
        cche_encrypt_params_const_t params = get_test_encrypt_params(he_scheme, nmoduli);
        test_cche_encrypt_galois_decrypt_helper_single_ws(ws, params, galois_elt, coeffs_in, coeffs_out);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encrypt_apply_galois_1_decrypt(cche_scheme_t he_scheme)
{
    // f(x) = 1 -> f(x^{galois_elt}) = 1
    ccrns_int coeffs[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        coeffs[i] = 0;
    }
    coeffs[0] = 1;

    for (uint32_t trial = 0; trial < 10; ++trial) {
        uint32_t galois_elt = random_galois_element(degree);
        test_cche_encrypt_galois_decrypt_params(he_scheme, galois_elt, coeffs, coeffs);
    }
}

static void test_cche_encrypt_apply_galois_x_decrypt(cche_scheme_t he_scheme)
{
    // f(x) = x -> f(x^{galois_elt}) = x^{galois_elt}
    ccrns_int coeffs_in[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        coeffs_in[i] = 0;
    }
    coeffs_in[1] = 1;

    for (uint32_t trial = 0; trial < 10; ++trial) {
        uint32_t galois_elt = random_galois_element(degree);
        static const ccrns_int plaintext_modulus = 40961;
        ccrns_int coeffs_out[degree];
        for (uint32_t i = 0; i < degree; ++i) {
            coeffs_out[i] = 0;
        }
        coeffs_out[galois_elt % degree] = (galois_elt < degree) ? 1 : (plaintext_modulus - 1);

        test_cche_encrypt_galois_decrypt_params(he_scheme, galois_elt, coeffs_in, coeffs_out);
    }
}

static void test_cche_encrypt_apply_galois_x_squared_decrypt(cche_scheme_t he_scheme)
{
    // f(x) = 1 + 2x^2
    ccrns_int coeffs_in[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        coeffs_in[i] = 0;
    }
    coeffs_in[0] = 1;
    coeffs_in[2] = 2;

    // f(x^3) = 1 + 2x^6
    {
        uint32_t galois_elt = 3;
        ccrns_int coeffs_out[degree];
        for (uint32_t i = 0; i < degree; ++i) {
            coeffs_out[i] = 0;
        }
        coeffs_out[0] = 1;
        coeffs_out[6] = 2;
        test_cche_encrypt_galois_decrypt_params(he_scheme, galois_elt, coeffs_in, coeffs_out);
    }
    // f(x^5) = 1 + 2x^10
    {
        uint32_t galois_elt = 5;
        ccrns_int coeffs_out[degree];
        for (uint32_t i = 0; i < degree; ++i) {
            coeffs_out[i] = 0;
        }
        coeffs_out[0] = 1;
        coeffs_out[10] = 2;
        test_cche_encrypt_galois_decrypt_params(he_scheme, galois_elt, coeffs_in, coeffs_out);
    }
    // f(x^(N - 1)) = 1 + 2x^(2N - 2) = 1 + 1 - 2x^(N - 2)
    {
        uint32_t galois_elt = degree - 1;
        ccrns_int coeffs_out[degree];
        for (uint32_t i = 0; i < degree; ++i) {
            coeffs_out[i] = 0;
        }
        coeffs_out[0] = 1;
        coeffs_out[degree - 2] = plaintext_modulus - 2;
        test_cche_encrypt_galois_decrypt_params(he_scheme, galois_elt, coeffs_in, coeffs_out);
    }
}

/// @brief Performs a round-trip test for Galois transformation
/// @details Let ^(i) denote the operation f(x) -> f(x^i).
/// Let c = Enc(plaintext, sk) be the encryption of a plaintext under the secret key sk.
/// This test checks Dec(c^(i), sk) == plaintext^(i)
static void test_cche_apply_galois_roundtrip_helper_single(cche_encrypt_params_const_t encrypt_params, uint32_t galois_elt)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init");

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    ccrns_int coeffs_in[degree];
    random_int_array(degree, coeffs_in, plaintext_modulus);
    is(cche_encode_simd_uint64(ptext, param_ctx, degree, coeffs_in), CCERR_OK, "cche_encode_simd_uint64 != CCERR_OK");
    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        coeffs_in[coeff_idx] = ccpolyzp_po2cyc_coeff_data_int(cche_plaintext_polynomial(ptext), 0, coeff_idx);
    }

    cche_plaintext_t ptext_galois = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    cche_plaintext_copy(ptext_galois, ptext);

    int rv = ccpolyzp_po2cyc_coeff_apply_galois(
        cche_plaintext_polynomial(ptext_galois), cche_plaintext_polynomial_const(ptext), galois_elt);
    is(rv, CCERR_OK, "Error applying Galois");

    ccrns_int coeffs_out[degree];
    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        coeffs_out[coeff_idx] = ccpolyzp_po2cyc_coeff_data_int(cche_plaintext_polynomial(ptext_galois), 0, coeff_idx);
    }

    test_cche_encrypt_galois_decrypt_helper_single_ws(ws, encrypt_params, galois_elt, coeffs_in, coeffs_out);

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_apply_galois_roundtrip(cche_scheme_t he_scheme)
{
    for (uint32_t nmoduli = 2; nmoduli <= 5; ++nmoduli) {
        cche_encrypt_params_const_t params = get_test_encrypt_params(he_scheme, nmoduli);
        for (uint32_t trial = 0; trial < 10; ++trial) {
            uint32_t galois_elt = random_galois_element(degree);
            test_cche_apply_galois_roundtrip_helper_single(params, galois_elt);
        }
    }
}

enum cche_rotate_op {
    CCHE_ROTATE_ROWS_LEFT = 0,
    CCHE_ROTATE_ROWS_RIGHT = 1,
    CCHE_SWAP_COLUMNS = 2,
};

/// @brief Runs a single test of encryption, one of {swap_columns, rotate_rows_left, rotate_rows_right}, and decryption
/// @param ws Workspace
/// @param encrypt_params The encryption parameters for the test
/// @param rotate_op The Galois rotation operation to perform
/// @param step The number of steps to rotate by
/// @param coeffs_in The input plaintext coefficients
/// @param coeffs_out The expected output plaintext coefficients
static void test_cche_encrypt_rotate_decrypt_helper_single_ws(cc_ws_t ws,
                                                              cche_encrypt_params_const_t encrypt_params,
                                                              enum cche_rotate_op rotate_op,
                                                              uint32_t *step,
                                                              const ccrns_int *cc_counted_by(encrypt_params->degree) coeffs_in,
                                                              const ccrns_int *cc_counted_by(encrypt_params->degree) coeffs_out,
                                                              const char *test_name)
{
    CC_DECL_BP_WS(ws, bp);

    uint32_t degree = encrypt_params->poly_modulus_degree;
    uint32_t galois_elt;
    switch (rotate_op) {
    case CCHE_ROTATE_ROWS_LEFT:
        is(cche_ciphertext_galois_elt_rotate_rows_left(&galois_elt, *step, degree), CCERR_OK, "BFV/BGV rotate left");
        break;

    case CCHE_ROTATE_ROWS_RIGHT:
        is(cche_ciphertext_galois_elt_rotate_rows_right(&galois_elt, *step, degree), CCERR_OK, "BFV/BGV rotate right");
        break;

    case CCHE_SWAP_COLUMNS:
        is(cche_ciphertext_galois_elt_swap_columns(&galois_elt, degree), CCERR_OK, "BFV/BGV swap column");
        break;
    }
    uint32_t galois_elts[] = { galois_elt };

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 modulus)");
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));
    int rv = cche_galois_key_generate_ws(
        ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng);
    is(rv, CCERR_OK, "Galois key generation");

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    is(cche_encode_simd_uint64(ptext, param_ctx, degree, coeffs_in), CCERR_OK, "cche_encode_simd_uint64 != CCERR_OK");
    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    uint32_t ctext_nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;
    rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, ctext_nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV/BGV encrypt symmetric no seed");

    cche_ciphertext_coeff_t ctext_galois =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_coeff_copy(ctext_galois, ctext);

    switch (rotate_op) {
    case CCHE_ROTATE_ROWS_LEFT:
        is(cche_ciphertext_rotate_rows_left_ws(ws, ctext_galois, ctext, *step, galois_key), CCERR_OK, "BFV/BGV rotate left");
        break;

    case CCHE_ROTATE_ROWS_RIGHT:
        is(cche_ciphertext_rotate_rows_right_ws(ws, ctext_galois, ctext, *step, galois_key), CCERR_OK, "BFV/BGV rotate right");
        break;

    case CCHE_SWAP_COLUMNS:
        is(cche_ciphertext_swap_columns_ws(ws, ctext_galois, ctext, galois_key), CCERR_OK, "BFV/BGV swap column");
        break;
    }
    is(cche_decrypt_ws(ws, ptext, param_ctx, ctext_galois, secret_key), CCERR_OK, "BFV/BGV decrypt");
    ccrns_int ptext_coeffs[degree];
    is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, ptext_coeffs, ptext),
       CCERR_OK,
       "cche_decode_simd_uint64_ws != CCERR_OK");

    is(array_eq_uint64(degree, ptext_coeffs, coeffs_out), true, "%s BFV/BGV galois plaintext coeffs not equal", test_name);

    CC_FREE_BP_WS(ws, bp);
}

static void test_cche_rotate_error(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cche_encrypt_params_const_t encrypt_params = get_test_encrypt_params(he_scheme, 2);
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init (2 moduli)");
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    uint32_t degree = encrypt_params->poly_modulus_degree;
    uint32_t galois_elt_left;
    is(cche_ciphertext_galois_elt_rotate_rows_left(&galois_elt_left, 1, degree), CCERR_OK, "BFV/BGV rotate left");

    uint32_t galois_elt_right;
    is(cche_ciphertext_galois_elt_rotate_rows_right(&galois_elt_right, 1, degree), CCERR_OK, "BFV/BGV rotate right");

    uint32_t galois_elt_cols;
    is(cche_ciphertext_galois_elt_swap_columns(&galois_elt_cols, degree), CCERR_OK, "BFV/BGV swap column");

    uint32_t galois_elts[] = { galois_elt_left, galois_elt_right, galois_elt_cols };
    cche_galois_key_t galois_key = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts));
    int rv = cche_galois_key_generate_ws(
        ws, galois_key, CC_ARRAY_LEN(galois_elts), galois_elts, secret_key, param_ctx, 0, NULL, global_test_rng);
    is(rv, CCERR_OK, "Galois key generation");

    uint32_t galois_elt_diff = 7;
    is((galois_elt_diff != galois_elt_left) && (galois_elt_diff != galois_elt_right) && (galois_elt_diff != galois_elt_cols),
       true,
       "Galois element diff");
    uint32_t galois_elts_diff[] = { galois_elt_diff };
    cche_galois_key_t galois_key_diff = CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, CC_ARRAY_LEN(galois_elts_diff));
    rv = cche_galois_key_generate_ws(
        ws, galois_key_diff, CC_ARRAY_LEN(galois_elts_diff), galois_elts_diff, secret_key, param_ctx, 0, NULL, global_test_rng);
    is(rv, CCERR_OK, "Galois key generation");

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    uint64_t zeros[16] = { 0 };
    is(cche_encode_simd_uint64(ptext, param_ctx, degree, zeros), CCERR_OK, "cche_encode_simd_uint64 != CCERR_OK");
    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    uint32_t ctext_nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;
    rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, ctext_nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV/BGV encrypt symmetric no seed");

    cche_ciphertext_coeff_t ctext_galois =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_coeff_copy(ctext_galois, ctext);

    is(cche_ciphertext_rotate_rows_left_ws(ws, ctext_galois, ctext, 1, galois_key), CCERR_OK, "BFV/BGV rotate left ok");
    is(cche_ciphertext_rotate_rows_left_ws(ws, ctext_galois, ctext, 0, galois_key),
       CCERR_PARAMETER,
       "BFV/BGV rotate left step 0");
    is(cche_ciphertext_rotate_rows_left_ws(ws, ctext_galois, ctext, degree, galois_key),
       CCERR_PARAMETER,
       "BFV/BGV rotate left step too large");
    is(cche_ciphertext_rotate_rows_left_ws(ws, ctext, ctext, degree, galois_key),
       CCERR_PARAMETER,
       "BFV/BGV rotate left in-place");
    is(cche_ciphertext_rotate_rows_left_ws(ws, ctext, ctext, degree, galois_key_diff),
       CCERR_PARAMETER,
       "BFV/BGV rotate left invalid Galois key");

    is(cche_ciphertext_rotate_rows_right_ws(ws, ctext_galois, ctext, 1, galois_key), CCERR_OK, "BFV/BGV rotate right ok");
    is(cche_ciphertext_rotate_rows_right_ws(ws, ctext_galois, ctext, 0, galois_key),
       CCERR_PARAMETER,
       "BFV/BGV rotate right step 0");
    is(cche_ciphertext_rotate_rows_right_ws(ws, ctext_galois, ctext, degree, galois_key),
       CCERR_PARAMETER,
       "BFV/BGV rotate right step too large");
    is(cche_ciphertext_rotate_rows_right_ws(ws, ctext, ctext, degree, galois_key),
       CCERR_PARAMETER,
       "BFV/BGV rotate right in-place");
    is(cche_ciphertext_rotate_rows_left_ws(ws, ctext, ctext, degree, galois_key_diff),
       CCERR_PARAMETER,
       "BFV/BGV rotate right invalid Galois key");

    is(cche_ciphertext_swap_columns_ws(ws, ctext_galois, ctext, galois_key), CCERR_OK, "BFV/BGV swap columns ok");
    is(cche_ciphertext_swap_columns_ws(ws, ctext, ctext, galois_key), CCERR_PARAMETER, "BFV/BGV swap columns in-place");
    is(cche_ciphertext_swap_columns_ws(ws, ctext, ctext, galois_key_diff),
       CCERR_PARAMETER,
       "BFV/BGV swap columns invalid Galois key");

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encrypt_rotate_decrypt_helper_params(cche_scheme_t he_scheme,
                                                           enum cche_rotate_op rotate_op,
                                                           uint32_t *step,
                                                           const ccrns_int *cc_counted_by(degree) coeffs_in,
                                                           const ccrns_int *cc_counted_by(degree) coeffs_out,
                                                           const char *test_name)

{
    CC_DECL_WORKSPACE_TEST(ws);

    for (uint32_t nmoduli = 2; nmoduli <= 5; ++nmoduli) {
        test_cche_encrypt_rotate_decrypt_helper_single_ws(
            ws, get_test_encrypt_params(he_scheme, nmoduli), rotate_op, step, coeffs_in, coeffs_out, test_name);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_ciphertext_rotate_rows_left(cche_scheme_t he_scheme)
{
    ccrns_int coeffs_in[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    // rotate left 1
    {
        uint32_t step = 1;
        ccrns_int coeffs_out[16] = { 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_LEFT, &step, coeffs_in, coeffs_out, "rotate left 1");
    }
    // rotate left 2
    {
        uint32_t step = 2;
        ccrns_int coeffs_out[16] = { 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_LEFT, &step, coeffs_in, coeffs_out, "rotate left 2");
    }
    // rotate left 3
    {
        uint32_t step = 3;
        ccrns_int coeffs_out[16] = { 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_LEFT, &step, coeffs_in, coeffs_out, "rotate left 3");
    }
    // rotate left 4
    {
        uint32_t step = 4;
        ccrns_int coeffs_out[16] = { 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_LEFT, &step, coeffs_in, coeffs_out, "rotate left 4");
    }
    // rotate left 5
    {
        uint32_t step = 5;
        ccrns_int coeffs_out[16] = { 5, 6, 7, 0, 1, 2, 3, 4, 13, 14, 15, 8, 9, 10, 11, 12 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_LEFT, &step, coeffs_in, coeffs_out, "rotate left 5");
    }
    // rotate left 6
    {
        uint32_t step = 6;
        ccrns_int coeffs_out[16] = { 6, 7, 0, 1, 2, 3, 4, 5, 14, 15, 8, 9, 10, 11, 12, 13 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_LEFT, &step, coeffs_in, coeffs_out, "rotate left 6");
    }
    // rotate left 7
    {
        uint32_t step = 7;
        ccrns_int coeffs_out[16] = {
            7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14,
        };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_LEFT, &step, coeffs_in, coeffs_out, "rotate left 7");
    }
}

static void test_cche_ciphertext_rotate_rows_right(cche_scheme_t he_scheme)
{
    ccrns_int coeffs_in[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    // rotate right 7
    {
        uint32_t step = 7;
        ccrns_int coeffs_out[16] = { 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_RIGHT, &step, coeffs_in, coeffs_out, "rotate right 7");
    }
    // rotate right 6
    {
        uint32_t step = 6;
        ccrns_int coeffs_out[16] = { 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_RIGHT, &step, coeffs_in, coeffs_out, "rotate right 6");
    }
    // rotate right 5
    {
        uint32_t step = 5;
        ccrns_int coeffs_out[16] = { 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_RIGHT, &step, coeffs_in, coeffs_out, "rotate right 5");
    }
    // rotate right 4
    {
        uint32_t step = 4;
        ccrns_int coeffs_out[16] = { 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_RIGHT, &step, coeffs_in, coeffs_out, "rotate right 4");
    }
    // rotate right 3
    {
        uint32_t step = 3;
        ccrns_int coeffs_out[16] = { 5, 6, 7, 0, 1, 2, 3, 4, 13, 14, 15, 8, 9, 10, 11, 12 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_RIGHT, &step, coeffs_in, coeffs_out, "rotate right 3");
    }
    // rotate right 2
    {
        uint32_t step = 2;
        ccrns_int coeffs_out[16] = { 6, 7, 0, 1, 2, 3, 4, 5, 14, 15, 8, 9, 10, 11, 12, 13 };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_RIGHT, &step, coeffs_in, coeffs_out, "rotate right 2");
    }
    // rotate right 1
    {
        uint32_t step = 1;
        ccrns_int coeffs_out[16] = {
            7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14,
        };
        test_cche_encrypt_rotate_decrypt_helper_params(
            he_scheme, CCHE_ROTATE_ROWS_RIGHT, &step, coeffs_in, coeffs_out, "rotate right 1");
    }
}

static void test_cche_ciphertext_swap_columns(cche_scheme_t he_scheme)
{
    ccrns_int coeffs_in[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    ccrns_int coeffs_out[16] = { 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 };
    test_cche_encrypt_rotate_decrypt_helper_params(he_scheme, CCHE_SWAP_COLUMNS, NULL, coeffs_in, coeffs_out, "swap columns");
}

void test_cche_galois(cche_scheme_t he_scheme)
{
    // galois key
    test_cche_galois_key_error(he_scheme);
    test_cche_galois_key_generate(he_scheme);
    test_cche_galois_key_generate_deserialize(he_scheme);

    // apply galois
    test_cche_apply_galois_error(he_scheme);
    test_cche_encrypt_apply_galois_1_decrypt(he_scheme);
    test_cche_encrypt_apply_galois_x_decrypt(he_scheme);
    test_cche_encrypt_apply_galois_x_squared_decrypt(he_scheme);
    test_cche_apply_galois_roundtrip(he_scheme);

    test_cche_ciphertext_rotate_rows_left(he_scheme);
    test_cche_ciphertext_rotate_rows_right(he_scheme);
    test_cche_ciphertext_swap_columns(he_scheme);
    test_cche_rotate_error(he_scheme);
}
