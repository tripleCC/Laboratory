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
#include "ccbfv_debug.h"
#include "ccbfv_internal.h"
#include "ccbfv_relin_key.h"
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "crypto_test_ccbfv.h"
#include <corecrypto/ccrng.h>
#include "ccpolyzp_po2cyc_serialization.h"

static const uint32_t degree = 16;
static const ccrns_int plaintext_modulus = 40961;

static const struct ccbfv_encrypt_params encrypt_params_2 = { .poly_modulus_degree = degree,
                                                              .plaintext_modulus = plaintext_modulus,
                                                              .nskip_lsbs = { 0, 0 },
                                                              .nmoduli = 2,
                                                              .moduli = { 536903681ULL, 576460752303439873ULL } };

static const struct ccbfv_encrypt_params encrypt_params_3 = { .poly_modulus_degree = degree,
                                                              .plaintext_modulus = plaintext_modulus,
                                                              .nskip_lsbs = { 0, 0 },
                                                              .nmoduli = 3,
                                                              .moduli = { 536903681ULL, 68719403009ULL, 576460752303439873ULL } };

static const struct ccbfv_encrypt_params encrypt_params_4 = {
    .poly_modulus_degree = degree,
    .plaintext_modulus = plaintext_modulus,
    .nskip_lsbs = { 0, 0 },
    .nmoduli = 4,
    .moduli = { 536903681ULL, 68719403009ULL, 1073692673ULL, 576460752303439873ULL }
};

static const struct ccbfv_encrypt_params encrypt_params_5 = {
    .poly_modulus_degree = degree,
    .plaintext_modulus = plaintext_modulus,
    .nskip_lsbs = { 0, 0 },
    .nmoduli = 5,
    .moduli = { 536903681ULL, 68719403009ULL, 1073692673ULL, 137438822401ULL, 576460752303439873ULL }
};

static void test_ccbfv_relin_key_error_single(ccbfv_encrypt_params_const_t encrypt_params)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV param ctx init");

    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    ccbfv_relin_key_t relin_key = CCBFV_RELIN_KEY_ALLOC_WS(ws, param_ctx);

    // ok
    {
        is(ccbfv_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, 0, NULL, global_test_rng),
           CCERR_OK,
           "Relin key generation");
    }
    // invalid number of seeds
    {
        is(ccbfv_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, 2, NULL, global_test_rng),
           CCERR_PARAMETER,
           "Relin key invalid number of seeds");
    }
    // secret key param context mismatch
    {
        ccbfv_encrypt_params_const_t encrypt_params_diff =
            (encrypt_params == &encrypt_params_2 ? &encrypt_params_3 : &encrypt_params_2);
        ccbfv_param_ctx_t param_ctx_diff = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params_diff);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx_diff, encrypt_params_diff), CCERR_OK, "BFV param ctx init");

        is(ccbfv_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx_diff, 0, NULL, global_test_rng),
           CCERR_PARAMETER,
           "Relin key invalid param context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_relin_key_error(void)
{
    test_ccbfv_relin_key_error_single(&encrypt_params_2);
    test_ccbfv_relin_key_error_single(&encrypt_params_3);
    test_ccbfv_relin_key_error_single(&encrypt_params_4);
    test_ccbfv_relin_key_error_single(&encrypt_params_5);
}

static void test_ccbfv_relin_key_generate_single(ccbfv_encrypt_params_const_t encrypt_params)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV param ctx init");

    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    ccbfv_relin_key_t relin_key = CCBFV_RELIN_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, 0, NULL, global_test_rng),
       CCERR_OK,
       "Relin key generation");

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_relin_key_generate(void)
{
    test_ccbfv_relin_key_generate_single(&encrypt_params_2);
    test_ccbfv_relin_key_generate_single(&encrypt_params_3);
    test_ccbfv_relin_key_generate_single(&encrypt_params_4);
    test_ccbfv_relin_key_generate_single(&encrypt_params_5);
}

static void test_ccbfv_relin_key_generate_deserialize_single(ccbfv_encrypt_params_const_t encrypt_params)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV param ctx init");

    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    ccbfv_relin_key_t relin_key = CCBFV_RELIN_KEY_ALLOC_WS(ws, param_ctx);

    const uint32_t nbytes_per_poly = (uint32_t)ccbfv_param_ctx_key_ctx_poly_nbytes(param_ctx);
    const uint32_t nciphers = ccbfv_param_ctx_key_ctx_nmoduli(param_ctx) - 1;
    const uint32_t nbytes_poly0s = nbytes_per_poly * nciphers;
    const uint32_t nbytes_seeds = (uint32_t)ccbfv_rng_seed_sizeof() * nciphers;

    uint8_t *poly0s = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes_poly0s));
    uint8_t *seeds = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes_seeds));

    is(ccbfv_relin_key_generate_ws(ws, relin_key, secret_key, param_ctx, nbytes_seeds, seeds, global_test_rng),
       CCERR_OK,
       "Relin key generation");

    is(ccbfv_relin_key_save_ws(ws, nbytes_poly0s, poly0s, relin_key), CCERR_OK, "Relin key save");

    ccbfv_relin_key_t relin_key_loaded = CCBFV_RELIN_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_relin_key_load_ws(ws, relin_key_loaded, param_ctx, nbytes_poly0s, poly0s, nbytes_seeds, seeds),
       CCERR_OK,
       "Relin key load");

    for (uint32_t cipher_idx = 0; cipher_idx < nciphers; ++cipher_idx) {
        ccbfv_ciphertext_eval_const_t relin_cipher = ccbfv_relin_key_ciphertext_const(relin_key, cipher_idx);
        ccbfv_ciphertext_eval_const_t relin_cipher_loaded = ccbfv_relin_key_ciphertext_const(relin_key_loaded, cipher_idx);
        is(ccbfv_ciphertext_eval_eq(relin_cipher, relin_cipher_loaded), true, "Relin key cipher");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_relin_key_generate_deserialize(void)
{
    test_ccbfv_relin_key_generate_deserialize_single(&encrypt_params_2);
    test_ccbfv_relin_key_generate_deserialize_single(&encrypt_params_3);
    test_ccbfv_relin_key_generate_deserialize_single(&encrypt_params_4);
    test_ccbfv_relin_key_generate_deserialize_single(&encrypt_params_5);
}

void test_ccbfv_relin(void)
{
    // relineariztion key
    test_ccbfv_relin_key_error();
    test_ccbfv_relin_key_generate();
    test_ccbfv_relin_key_generate_deserialize();
}
