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
#include "cche_priv.h"
#include "cche_serialization.h"
#include "cche_util.h"
#include "crypto_test_cche.h"
#include "ccpolyzp_po2cyc_serialization.h"
#include <math.h>

static void test_cche_ciphertext_coeff_serialization(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // three ciphertext moduli
    {
        static const struct cche_encrypt_params encrypt_params = { .he_scheme = CCHE_SCHEME_BFV,
                                                                   .poly_modulus_degree = 1024,
                                                                   .plaintext_modulus = 18433,
                                                                   .nskip_lsbs = { 0, 0 },
                                                                   .nmoduli = 4,
                                                                   .moduli = { 40961, 59393, 61441, 65537 } };
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");

        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);

        uint64_t nextra_polys;
        ccrng_uniform(global_test_rng, 3, &nextra_polys);
        // a ciphertext always has at least `cche_ciphertext_fresh_npolys()` polynomials
        uint32_t npolys = (uint32_t)nextra_polys + cche_ciphertext_fresh_npolys();

        cche_ciphertext_coeff_t ciphertext = CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, npolys);
        cche_ciphertext_coeff_init(ciphertext, param_ctx, npolys, cipher_ctx);

        int rv = CCERR_OK;
        for (uint32_t poly_idx = 0; poly_idx < npolys; ++poly_idx) {
            // this can only add to the error, but it will never clear bits.
            ccpolyzp_po2cyc_t poly = (ccpolyzp_po2cyc_t)cche_ciphertext_coeff_polynomial(ciphertext, poly_idx);
            rv |= ccpolyzp_po2cyc_random_uniform_ws(ws, poly, global_test_rng);
        }
        is(rv, CCERR_OK, "ccpolyzp_po2cyc_random_uniform failed!");

        size_t nbytes = cche_serialize_ciphertext_coeff_nbytes(ciphertext, NULL);
        uint8_t *bytes = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes));

        is(cche_serialize_ciphertext_coeff_ws(ws, nbytes, bytes, ciphertext, NULL), CCERR_OK, "cche_serialize_ciphertext_ws");
        cche_ciphertext_coeff_t ciphertext_deserialized = CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, npolys);
        cche_ciphertext_coeff_init(ciphertext_deserialized, param_ctx, npolys, cipher_ctx);
        is(cche_deserialize_ciphertext_coeff_ws(ws, ciphertext_deserialized, nbytes, bytes, NULL),
           CCERR_OK,
           "cche_deserialize_ciphertext_ws");

        is(cche_ciphertext_coeff_eq(ciphertext_deserialized, ciphertext), true, "cipher_deserialized != cipher");
    }

    CC_FREE_WORKSPACE(ws);
}

static void run_cche_ciphertext_coeff_serialization_skip_lsbs_error_test(cc_ws_t ws, cche_encrypt_params_const_t encrypt_params)
{
    CC_DECL_BP_WS(ws, bp);

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "BFV/BGV param ctx init");

    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);

    uint32_t npolys = cche_ciphertext_fresh_npolys();
    cche_ciphertext_coeff_t ctext = CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, npolys);

    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, cche_param_ctx_plaintext_context(param_ctx));
    cche_plaintext_init(ptext, param_ctx);
    is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)cche_plaintext_polynomial(ptext), global_test_rng),
       CCERR_OK,
       "ccpolyzp_po2cyc_random_uniform");

    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "cche_secret_key_generate_ws");

    is(encrypt_params->nmoduli, 1, "cche_ciphertext_coeff_serialization_skip_lsbs nmoduli != 1");
    int rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, encrypt_params->nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "cche_encrypt_symmetric_ws");

    size_t nbytes = cche_serialize_ciphertext_coeff_nbytes(ctext, encrypt_params->nskip_lsbs);
    uint8_t *bytes = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes));

    // ok
    is(cche_serialize_ciphertext_coeff_ws(ws, nbytes, bytes, ctext, encrypt_params->nskip_lsbs),
       CCERR_OK,
       "cche_serialize_ciphertext_coeff");
    // skip_lsbs[0] too large
    {
        uint32_t skip_lsbs_err[CCHE_CIPHERTEXT_FRESH_NPOLYS];
        skip_lsbs_err[0] = encrypt_params->nskip_lsbs[0] + 1;
        skip_lsbs_err[1] = 0;
        is(cche_serialize_ciphertext_coeff_ws(ws, nbytes, bytes, ctext, skip_lsbs_err),
           CCERR_PARAMETER,
           "cche_serialize_ciphertext_coeff skip_lsbs[0] too large");
    }
    // skip_lsbs[1] too large
    {
        uint32_t skip_lsbs_err[CCHE_CIPHERTEXT_FRESH_NPOLYS];
        skip_lsbs_err[0] = 0;
        skip_lsbs_err[1] = encrypt_params->nskip_lsbs[1] + 1;
        is(cche_serialize_ciphertext_coeff_ws(ws, nbytes, bytes, ctext, skip_lsbs_err),
           CCERR_PARAMETER,
           "cche_serialize_ciphertext_coeff skip_lsbs[1] too large");
    }

    CC_FREE_BP_WS(ws, bp);
}

static void test_cche_ciphertext_coeff_serialization_skip_lsbs_error(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct cche_encrypt_params encrypt_params_odd = {
        .he_scheme = CCHE_SCHEME_BFV,
        .poly_modulus_degree = 1024,
        .plaintext_modulus = (1 << 14) + 2049,
        .nmoduli = 1,
        .nskip_lsbs = { 1, 1 },
        .moduli = { 576460752303439873ULL },
    };
    static const struct cche_encrypt_params encrypt_params_even = { .he_scheme = CCHE_SCHEME_BFV,
                                                                    .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = (1 << 15) + 8193,
                                                                    .nmoduli = 1,
                                                                    .nskip_lsbs = { 1, 1 },
                                                                    .moduli = { 576460752303439873ULL } };

    run_cche_ciphertext_coeff_serialization_skip_lsbs_error_test(ws, &encrypt_params_odd);
    run_cche_ciphertext_coeff_serialization_skip_lsbs_error_test(ws, &encrypt_params_even);

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_ciphertext_eval_serialization(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // three ciphertext moduli
    {
        static const struct cche_encrypt_params encrypt_params = { .he_scheme = CCHE_SCHEME_BFV,
                                                                   .poly_modulus_degree = 1024,
                                                                   .plaintext_modulus = 18433,
                                                                   .nskip_lsbs = { 0, 0 },
                                                                   .nmoduli = 4,
                                                                   .moduli = { 40961, 59393, 61441, 65537 } };
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");

        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);

        uint64_t nextra_polys;
        ccrng_uniform(global_test_rng, 3, &nextra_polys);
        // a ciphertext always has at least `cche_ciphertext_fresh_npolys()` polynomials
        uint32_t npolys = (uint32_t)nextra_polys + cche_ciphertext_fresh_npolys();

        cche_ciphertext_eval_t ciphertext = CCHE_CIPHERTEXT_EVAL_ALLOC_WS(ws, cipher_ctx, npolys);
        cche_ciphertext_eval_init(ciphertext, param_ctx, npolys, cipher_ctx);

        int rv = CCERR_OK;
        for (uint32_t poly_idx = 0; poly_idx < npolys; ++poly_idx) {
            // this can only add to the error, but it will never clear bits.
            ccpolyzp_po2cyc_t poly = (ccpolyzp_po2cyc_t)cche_ciphertext_eval_polynomial(ciphertext, poly_idx);
            rv |= ccpolyzp_po2cyc_random_uniform_ws(ws, poly, global_test_rng);
        }
        is(rv, CCERR_OK, "ccpolyzp_po2cyc_random_uniform failed!");

        size_t nbytes = cche_serialize_ciphertext_eval_nbytes(ciphertext);
        uint8_t *bytes = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes));

        is(cche_serialize_ciphertext_eval_ws(ws, nbytes, bytes, ciphertext), CCERR_OK, "cche_serialize_ciphertext_ws");

        cche_ciphertext_eval_t ciphertext_deserialized = CCHE_CIPHERTEXT_EVAL_ALLOC_WS(ws, cipher_ctx, npolys);
        cche_ciphertext_eval_init(ciphertext_deserialized, param_ctx, npolys, cipher_ctx);
        is(cche_deserialize_ciphertext_eval_ws(ws, ciphertext_deserialized, nbytes, bytes),
           CCERR_OK,
           "cche_deserialize_ciphertext_ws");

        is(cche_ciphertext_eval_eq(ciphertext_deserialized, ciphertext), true, "cipher_deserialized != cipher");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_seeded_ciphertext_coeff_deserialization(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // three ciphertext moduli
    {
        static const struct cche_encrypt_params encrypt_params = { .he_scheme = CCHE_SCHEME_BFV,
                                                                   .poly_modulus_degree = 1024,
                                                                   .plaintext_modulus = 18433,
                                                                   .nskip_lsbs = { 0, 0 },
                                                                   .nmoduli = 4,
                                                                   .moduli = { 40961, 59393, 61441, 65537 } };
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");

        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);

        cche_ciphertext_coeff_t ciphertext = CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_coeff_init(ciphertext, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);

        cche_plaintext_t plaintext = CCHE_PLAINTEXT_ALLOC_WS(ws, cche_param_ctx_plaintext_context(param_ctx));
        cche_plaintext_init(plaintext, param_ctx);
        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)cche_plaintext_polynomial(plaintext), global_test_rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform");
        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "cche_secret_key_generate_ws");
        struct ccpolyzp_po2cyc_block_rng_seed seed;
        uint32_t nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;
        int rv = cche_encrypt_symmetric_ws(
            ws, ciphertext, plaintext, param_ctx, secret_key, nmoduli, (cche_rng_seed_t)&seed, global_test_rng);
        is(rv, CCERR_OK, "cche_encrypt_symmetric_ws");
        size_t nbytes = cche_serialize_seeded_ciphertext_coeff_nbytes(ciphertext);
        uint8_t *bytes = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes));

        ccpolyzp_po2cyc_t c0 = (ccpolyzp_po2cyc_t)cche_ciphertext_coeff_polynomial(ciphertext, 0);
        is(ccpolyzp_po2cyc_serialize_poly_ws(ws, nbytes, bytes, 0, c0), CCERR_OK, "ccpolyzp_po2cyc_serialize_poly_ws");
        cche_ciphertext_coeff_t ciphertext_deserialized =
            CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_coeff_init(ciphertext_deserialized, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);
        is(cche_deserialize_seeded_ciphertext_coeff_ws(ws, ciphertext_deserialized, nbytes, bytes, (cche_rng_seed_const_t)&seed),
           CCERR_OK,
           "cche_deserialize_seeded_ciphertext_ws");

        is(cche_ciphertext_coeff_eq(ciphertext_deserialized, ciphertext), true, "cipher_deserialized != cipher");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_seeded_ciphertext_eval_deserialization(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // three ciphertext moduli
    {
        static const struct cche_encrypt_params encrypt_params = { .he_scheme = CCHE_SCHEME_BFV,
                                                                   .poly_modulus_degree = 1024,
                                                                   .plaintext_modulus = 18433,
                                                                   .nskip_lsbs = { 0, 0 },
                                                                   .nmoduli = 4,
                                                                   .moduli = { 40961, 59393, 61441, 65537 } };
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");

        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);

        cche_ciphertext_coeff_t ciphertext = CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_coeff_init(ciphertext, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);

        cche_plaintext_t plaintext = CCHE_PLAINTEXT_ALLOC_WS(ws, cche_param_ctx_plaintext_context(param_ctx));
        cche_plaintext_init(plaintext, param_ctx);
        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)cche_plaintext_polynomial(plaintext), global_test_rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform");
        cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "cche_secret_key_generate_ws");
        struct ccpolyzp_po2cyc_block_rng_seed seed;
        uint32_t nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;
        int rv = cche_encrypt_symmetric_ws(
            ws, ciphertext, plaintext, param_ctx, secret_key, nmoduli, (cche_rng_seed_t)&seed, global_test_rng);
        is(rv, CCERR_OK, "cche_encrypt_symmetric_ws");

        cche_ciphertext_eval_t ciphertext_eval = (cche_ciphertext_eval_t)ciphertext;
        is(cche_ciphertext_fwd_ntt(ciphertext), CCERR_OK, "cche_ciphertext_fwd_ntt");

        size_t nbytes = cche_serialize_seeded_ciphertext_eval_nbytes(ciphertext_eval);
        uint8_t *bytes = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(nbytes));

        ccpolyzp_po2cyc_t c0 = (ccpolyzp_po2cyc_t)cche_ciphertext_eval_polynomial(ciphertext_eval, 0);
        is(ccpolyzp_po2cyc_serialize_poly_ws(ws, nbytes, bytes, 0, c0), CCERR_OK, "ccpolyzp_po2cyc_serialize_poly_ws");
        cche_ciphertext_eval_t ciphertext_deserialized =
            CCHE_CIPHERTEXT_EVAL_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_eval_init(ciphertext_deserialized, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);
        is(cche_deserialize_seeded_ciphertext_eval_ws(ws, ciphertext_deserialized, nbytes, bytes, (cche_rng_seed_const_t)&seed),
           CCERR_OK,
           "cche_deserialize_seeded_ciphertext_ws");

        is(cche_ciphertext_eval_eq(ciphertext_deserialized, ciphertext_eval), true, "cipher_deserialized != cipher");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_seeded_ciphertext_deserialization_kat(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // KAT 1
    {
        static const struct cche_encrypt_params encrypt_params = {
            .he_scheme = CCHE_SCHEME_BFV,
            .poly_modulus_degree = 8,
            .plaintext_modulus = 1073741857,
            .nskip_lsbs = { 0, 0 },
            .nmoduli = 3,
            .moduli = { 576460752303423649, 576460752303423761, 576460752303424529 }
        };
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "cche_param_ctx_init_ws");

        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);
        cche_ciphertext_coeff_t ciphertext = CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_coeff_init(ciphertext, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);

        ccrns_int coeffs_poly0[] = { 486027288685612137, 379799672635331981, 496351256626511075, 545803186795645958,
                                     354130367810753666, 277463028519235170, 384164341235181910, 17973204458589032,
                                     317645431490145139, 114722576589921491, 52115753025339089,  160458968408557596,
                                     17705528305394200,  522865738325937075, 335309626950870374, 422316575403374146 };

        ccrns_int coeffs_poly1[] = { 495274057633651151, 463312084685310040, 500256102513973387, 228333762508966966,
                                     6759589350600693,   558385135458612359, 556978015524569516, 541032588719460783,
                                     492599778753990141, 180436667893749491, 16659686139202483,  394688772888184600,
                                     187527770739019837, 501070475881211655, 57651262466467135,  152799710480979732 };

        ccpolyzp_po2cyc_t c0 = (ccpolyzp_po2cyc_t)cche_ciphertext_coeff_polynomial(ciphertext, 0);
        ccpolyzp_po2cyc_t c1 = (ccpolyzp_po2cyc_t)cche_ciphertext_coeff_polynomial(ciphertext, 1);
        is(ccpolyzp_po2cyc_init(c0, cipher_ctx, coeffs_poly0), CCERR_OK, "ccpolyzp_po2cyc_init 0");
        is(ccpolyzp_po2cyc_init(c1, cipher_ctx, coeffs_poly1), CCERR_OK, "ccpolyzp_po2cyc_init 1");

        uint8_t bytes[] = { 107, 235, 115, 231, 84,  8,   198, 149, 69,  81,  202, 61,  61,  21,  141, 110, 54,  77,  104, 240,
                            171, 206, 55,  147, 21,  27,  74,  59,  12,  6,   78,  161, 251, 23,  152, 157, 72,  35,  217, 191,
                            39,  133, 49,  110, 98,  85,  77,  54,  237, 107, 30,  149, 96,  63,  218, 136, 195, 58,  203, 104,
                            70,  136, 13,  100, 71,  238, 183, 49,  151, 147, 147, 89,  92,  28,  211, 11,  146, 112, 5,   36,
                            111, 237, 18,  58,  16,  148, 229, 4,   136, 28,  3,   238, 113, 88,  211, 66,  33,  135, 65,  151,
                            158, 102, 35,  203, 179, 74,  116, 37,  68,  66,  206, 86,  101, 220, 94,  176, 19,  173, 118, 66 };

        const uint8_t seed[] = { 44,  48,  218, 224, 145, 242, 157, 85,  62, 17,  192, 215, 117, 163, 74,  138,
                                 124, 109, 208, 62,  88,  70,  57,  161, 63, 218, 38,  184, 36,  28,  219, 50 };
        size_t nbytes = CC_ARRAY_LEN(bytes);

        cche_ciphertext_coeff_t ciphertext_deserialized =
            CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_coeff_init(ciphertext_deserialized, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);
        is(cche_deserialize_seeded_ciphertext_coeff_ws(ws, ciphertext_deserialized, nbytes, bytes, (cche_rng_seed_const_t)seed),
           CCERR_OK,
           "cche_deserialize_seeded_ciphertext_ws");

        is(ciphertext_deserialized->npolys, cche_ciphertext_fresh_npolys(), "npolys != cche_ciphertext_fresh_npolys()");
        is(ccpolyzp_po2cyc_coeff_eq(cche_ciphertext_coeff_polynomial_const(ciphertext, 0),
                                    cche_ciphertext_coeff_polynomial_const(ciphertext_deserialized, 0)),
           true,
           "poly0 mismatch");
        is(ccpolyzp_po2cyc_coeff_eq(cche_ciphertext_coeff_polynomial_const(ciphertext, 1),
                                    cche_ciphertext_coeff_polynomial_const(ciphertext_deserialized, 1)),
           true,
           "poly1 mismatch");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_ciphertext_deserialization_kat(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // KAT 1
    {
        static const struct cche_encrypt_params encrypt_params = {
            .he_scheme = CCHE_SCHEME_BFV,
            .poly_modulus_degree = 8,
            .plaintext_modulus = 1073741857,
            .nskip_lsbs = { 0, 0 },
            .nmoduli = 3,
            .moduli = { 576460752303423649, 576460752303423761, 576460752303424529 }
        };
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "cche_param_ctx_init_ws");

        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);
        cche_ciphertext_coeff_t ciphertext = CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_coeff_init(ciphertext, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);

        ccrns_int coeffs_poly0[] = { 506572976189548416, 6810829041538809,   387418585136907383, 144209398645233045,
                                     520705471514074689, 405151811082711573, 370443362884667790, 312477065737610999,
                                     308839659969100266, 565592621836213654, 555174819518653203, 96124592031499695,
                                     282147245020405950, 119602708837761044, 243427510914132905, 353082845921311741 };

        ccrns_int coeffs_poly1[] = { 423731123867117203, 549698005081430797, 565381787961670161, 510850687837404620,
                                     493350363775192808, 305245627840013077, 250754484794994666, 548764706059921587,
                                     115256084083351453, 66689185792340407,  313353859277255252, 14565120689654837,
                                     130067678765259566, 400040930542423793, 336510631726471368, 167955008187735847 };

        ccpolyzp_po2cyc_t c0 = (ccpolyzp_po2cyc_t)cche_ciphertext_coeff_polynomial(ciphertext, 0);
        ccpolyzp_po2cyc_t c1 = (ccpolyzp_po2cyc_t)cche_ciphertext_coeff_polynomial(ciphertext, 1);
        is(ccpolyzp_po2cyc_init(c0, cipher_ctx, coeffs_poly0), CCERR_OK, "ccpolyzp_po2cyc_init 0");
        is(ccpolyzp_po2cyc_init(c1, cipher_ctx, coeffs_poly1), CCERR_OK, "ccpolyzp_po2cyc_init 1");

        uint8_t bytes[] = { 2,   0,   112, 123, 87,  1,   169, 114, 120, 0,   24,  50,  105, 181, 165, 150, 249, 86,  6,
                            50,  104, 167, 132, 71,  114, 0,   85,  175, 27,  133, 149, 149, 115, 158, 173, 225, 99,  45,
                            228, 21,  159, 99,  108, 243, 176, 242, 21,  82,  65,  68,  105, 226, 68,  152, 228, 86,  36,
                            60,  87,  191, 38,  247, 68,  147, 128, 141, 16,  43,  158, 167, 217, 99,  126, 48,  33,  29,
                            150, 123, 70,  8,   233, 26,  106, 49,  49,  85,  128, 206, 162, 55,  133, 175, 62,  166, 54,
                            202, 156, 190, 11,  225, 168, 234, 7,   174, 115, 0,   20,  54,  13,  64,  128, 201, 130, 186,
                            148, 230, 102, 250, 71,  108, 123, 253, 94,  22,  83,  100, 230, 6,   105, 55,  160, 235, 108,
                            86,  158, 155, 13,  125, 138, 59,  217, 158, 227, 161, 23,  22,  231, 254, 117, 207, 253, 204,
                            109, 139, 184, 171, 234, 20,  238, 132, 60,  115, 72,  0,   165, 35,  21,  55,  173, 190, 1,
                            128, 170, 254, 167, 157, 154, 151, 185, 249, 40,  179, 25,  151, 140, 195, 223, 217, 249, 208,
                            236, 237, 118, 13,  131, 49,  183, 69,  148, 26,  203, 243, 127, 37,  64,  51,  190, 230, 108,
                            209, 76,  53,  28,  225, 125, 213, 217, 1,   178, 229, 141, 59,  27,  88,  153, 14,  241, 74,
                            184, 106, 47,  179, 45,  140, 130, 84,  178, 48,  169, 71,  31,  39 };

        size_t nbytes = CC_ARRAY_LEN(bytes);

        cche_ciphertext_coeff_t ciphertext_deserialized =
            CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cipher_ctx, cche_ciphertext_fresh_npolys());
        cche_ciphertext_coeff_init(ciphertext_deserialized, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);
        is(cche_deserialize_ciphertext_coeff_ws(ws, ciphertext_deserialized, nbytes, bytes, NULL),
           CCERR_OK,
           "cche_deserialize_ciphertext_coeff_ws");

        is(ciphertext_deserialized->npolys, cche_ciphertext_fresh_npolys(), "npolys != cche_ciphertext_fresh_npolys()");
        is(ccpolyzp_po2cyc_coeff_eq(cche_ciphertext_coeff_polynomial_const(ciphertext, 0),
                                    cche_ciphertext_coeff_polynomial_const(ciphertext_deserialized, 0)),
           true,
           "poly0 mismatch");
        is(ccpolyzp_po2cyc_coeff_eq(cche_ciphertext_coeff_polynomial_const(ciphertext, 1),
                                    cche_ciphertext_coeff_polynomial_const(ciphertext_deserialized, 1)),
           true,
           "poly1 mismatch");
    }

    CC_FREE_WORKSPACE(ws);
}

void test_cche_serialization(void)
{
    test_cche_ciphertext_coeff_serialization();
    test_cche_ciphertext_coeff_serialization_skip_lsbs_error();
    test_cche_seeded_ciphertext_coeff_deserialization();
    test_cche_ciphertext_eval_serialization();
    test_cche_seeded_ciphertext_eval_deserialization();
    test_cche_seeded_ciphertext_deserialization_kat();
    test_cche_ciphertext_deserialization_kat();
}
