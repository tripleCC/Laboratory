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
#include "cche_relin_key.h"
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "crypto_test_cche.h"
#include <corecrypto/ccrng.h>
#include "ccpolyzp_po2cyc_serialization.h"

static void test_cche_relin_key_error_single(cche_encrypt_params_const_t encrypt_params)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init");

    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    cche_relin_key_t relin_key = CCHE_RELIN_KEY_ALLOC_WS(ws, param_ctx);

    // ok
    {
        is(cche_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, 0, NULL, global_test_rng),
           CCERR_OK,
           "Relin key generation");
    }
    // invalid number of seeds
    {
        is(cche_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, 2, NULL, global_test_rng),
           CCERR_PARAMETER,
           "Relin key invalid number of seeds");
    }
    // secret key param context mismatch
    {
        cche_scheme_t nmoduli_diff = encrypt_params->nmoduli == 2 ? 3 : 2;
        cche_encrypt_params_const_t encrypt_params_diff = get_test_encrypt_params(encrypt_params->he_scheme, nmoduli_diff);
        cche_param_ctx_t param_ctx_diff = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params_diff);
        is(cche_param_ctx_init_ws(ws, param_ctx_diff, encrypt_params_diff), CCERR_OK, "BFV/BGV param ctx init");
        is(cche_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx_diff, 0, NULL, global_test_rng),
           CCERR_PARAMETER,
           "Relin key invalid param context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_relin_key_error(cche_scheme_t he_scheme)
{
    for (uint32_t nmoduli = 2; nmoduli <= 5; ++nmoduli) {
        test_cche_relin_key_error_single(get_test_encrypt_params(he_scheme, nmoduli));
    }
}

static void test_cche_relin_key_generate_single(cche_encrypt_params_const_t encrypt_params)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init");

    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    cche_relin_key_t relin_key = CCHE_RELIN_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, 0, NULL, global_test_rng),
       CCERR_OK,
       "Relin key generation");

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_relin_key_generate(cche_scheme_t he_scheme)
{
    for (uint32_t nmoduli = 2; nmoduli <= 5; ++nmoduli) {
        test_cche_relin_key_generate_single(get_test_encrypt_params(he_scheme, nmoduli));
    }
}

static void test_cche_relin_key_generate_deserialize_single(cche_encrypt_params_const_t encrypt_params)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init");

    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    cche_relin_key_t relin_key = CCHE_RELIN_KEY_ALLOC_WS(ws, param_ctx);

    const uint32_t nbytes_per_poly = (uint32_t)cche_param_ctx_key_ctx_poly_nbytes(param_ctx);
    const uint32_t nciphers = cche_param_ctx_key_ctx_nmoduli(param_ctx) - 1;
    const uint32_t nbytes_poly0s = nbytes_per_poly * nciphers;
    const uint32_t nbytes_seeds = (uint32_t)cche_rng_seed_sizeof() * nciphers;

    uint8_t *poly0s = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes_poly0s));
    uint8_t *seeds = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes_seeds));

    is(cche_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, nbytes_seeds, seeds, global_test_rng),
       CCERR_OK,
       "Relin key generation");

    is(cche_relin_key_save_ws(ws, nbytes_poly0s, poly0s, relin_key), CCERR_OK, "Relin key save");

    cche_relin_key_t relin_key_loaded = CCHE_RELIN_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_relin_key_load_ws(ws, relin_key_loaded, param_ctx, nbytes_poly0s, poly0s, nbytes_seeds, seeds),
       CCERR_OK,
       "Relin key load");

    for (uint32_t cipher_idx = 0; cipher_idx < nciphers; ++cipher_idx) {
        cche_ciphertext_eval_const_t relin_cipher = cche_relin_key_ciphertext_const(relin_key, cipher_idx);
        cche_ciphertext_eval_const_t relin_cipher_loaded = cche_relin_key_ciphertext_const(relin_key_loaded, cipher_idx);
        is(cche_ciphertext_eval_eq(relin_cipher, relin_cipher_loaded), true, "Relin key cipher");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_relin_key_generate_deserialize(cche_scheme_t he_scheme)
{
    for (uint32_t nmoduli = 2; nmoduli <= 5; ++nmoduli) {
        test_cche_relin_key_generate_deserialize_single(get_test_encrypt_params(he_scheme, nmoduli));
    }
}

void test_cche_relin(cche_scheme_t he_scheme)
{
    // relineariztion key
    test_cche_relin_key_error(he_scheme);
    test_cche_relin_key_generate(he_scheme);
    test_cche_relin_key_generate_deserialize(he_scheme);
}
