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
#include "crypto_test_ccbfv.h"
#include "ccbfv_debug.h"
#include "ccbfv_internal.h"
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_debug.h"
#include <corecrypto/ccrng.h>
#include "ccbfv_util.h"

#undef CC_DECL_WORKSPACE_TEST
#define CC_DECL_WORKSPACE_TEST(ws)                                    \
    int ws##_rv;                                                      \
    CC_DECL_WORKSPACE_RV(ws, ccn_nof_size(2 * 1024 * 1024), ws##_rv); \
    cc_try_abort_if(ws##_rv != CCERR_OK, "alloc ws");

static void verify_poly_ctx(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t nmoduli, const ccrns_int *cc_counted_by(nmoduli) moduli)
{
    is(ctx->dims.nmoduli, nmoduli, "verify_poly_ctx nmoduli");
    for (uint32_t i = 0; i < nmoduli; ++i) {
        cczp_const_t cczp_modulus = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx, i);
        ccrns_int modulus = ccpolyzp_po2cyc_modulus_to_rns_int(cczp_modulus);
        is(modulus, moduli[i], "verify_poly_ctx moduli");
    }
}

static void test_ccbfv_encrypt_params_eq(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params_1a = { .poly_modulus_degree = 1024,
                                                                   .plaintext_modulus = 11,
                                                                   .nskip_lsbs = { 1, 1 },
                                                                   .nmoduli = 2,
                                                                   .moduli = { 536903681ULL, 576460752303439873ULL } };
    // Same parameters
    {
        struct ccbfv_encrypt_params *encrypt_params_1b =
            (struct ccbfv_encrypt_params *)CC_ALLOC_WS(ws, ccbfv_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        ccbfv_encrypt_params_copy(encrypt_params_1b, &encrypt_params_1a);
        is(ccbfv_encrypt_params_eq(&encrypt_params_1a, &encrypt_params_1a), true, "ccbfv_encrypt_params_eq same pointer");
        is(ccbfv_encrypt_params_eq(&encrypt_params_1a, encrypt_params_1b), true, "ccbfv_encrypt_params_eq same object");
    }
    // Different moduli
    {
        struct ccbfv_encrypt_params *encrypt_params_2 =
            (struct ccbfv_encrypt_params *)CC_ALLOC_WS(ws, ccbfv_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        ccbfv_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->moduli[1] = 68719403009ULL;
        is(ccbfv_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2),
           false,
           "ccbfv_encrypt_params_eq ciphertext moduli not eq");
    }
    // Different plaintext modulus
    {
        struct ccbfv_encrypt_params *encrypt_params_2 =
            (struct ccbfv_encrypt_params *)CC_ALLOC_WS(ws, ccbfv_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        ccbfv_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->plaintext_modulus = 13;
        is(ccbfv_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2),
           false,
           "ccbfv_encrypt_params_eq plaintext modulus not eq");
    }
    // Different polynomial modulus degree
    {
        struct ccbfv_encrypt_params *encrypt_params_2 =
            (struct ccbfv_encrypt_params *)CC_ALLOC_WS(ws, ccbfv_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        ccbfv_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->poly_modulus_degree = 2048;
        is(ccbfv_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2), false, "ccbfv_encrypt_params_eq degree not eq");
    }
    // Different nskip_lsbs
    {
        struct ccbfv_encrypt_params *encrypt_params_2 =
            (struct ccbfv_encrypt_params *)CC_ALLOC_WS(ws, ccbfv_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        ccbfv_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->nskip_lsbs[0] = encrypt_params_1a.nskip_lsbs[0] + 1;
        is(ccbfv_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2), false, "ccbfv_encrypt_params_eq nskip_lsbs not eq");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_param_ctx_init(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // one ciphertext modulus
    {
        static const struct ccbfv_encrypt_params encrypt_params = {
            .poly_modulus_degree = 4096, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
        };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (1 modulus)");
        static const ccrns_int plaintext_moduli[] = { 40961 };
        verify_poly_ctx(ccbfv_param_ctx_plaintext_context(param_ctx), 1, plaintext_moduli);
        static const ccrns_int key_moduli[] = { 65537 };
        verify_poly_ctx(ccbfv_param_ctx_encrypt_key_context(param_ctx), 1, key_moduli);
        static const ccrns_int coefficient_moduli[] = { 65537 };
        verify_poly_ctx(ccbfv_param_ctx_ciphertext_context(param_ctx), 1, coefficient_moduli);
        is(ccbfv_param_ctx_encrypt_key_context(param_ctx)->next, NULL, "BFV param ctx init (1 modulus), key_ctx->next = NULL");
        is(ccbfv_param_ctx_encrypt_key_context(param_ctx),
           ccbfv_param_ctx_ciphertext_context(param_ctx),
           "BFV param ctx init (1 moduli), key_ctx = ciphertext_ctx");
    }

    // three ciphertext moduli
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (4 moduli)");
        static const ccrns_int plaintext_moduli[] = { 40961 };
        verify_poly_ctx(ccbfv_param_ctx_plaintext_context(param_ctx), 1, plaintext_moduli);
        static const ccrns_int key_moduli[] = { 65537, 114689, 147457, 163841 };
        verify_poly_ctx(ccbfv_param_ctx_encrypt_key_context(param_ctx), 4, key_moduli);
        static const ccrns_int coefficient_moduli[] = { 65537, 114689, 147457 };
        verify_poly_ctx(ccbfv_param_ctx_ciphertext_context(param_ctx), 3, coefficient_moduli);
        is(ccbfv_param_ctx_encrypt_key_context(param_ctx)->next,
           ccbfv_param_ctx_ciphertext_context(param_ctx),
           "BFV param ctx init (4 moduli), key_ctx->next = ciphertext_ctx");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_param_ctx_init_errors(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    CC_DECL_BP_WS(ws, bp);
    // ok
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 18433,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 40961, 59393, 61441, 65537 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "test_ccbfv_param_ctx_init_errors ok");
        CC_FREE_BP_WS(ws, bp);
    }
    // polynomial degree is not power of two
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 1023,
                                                                    .plaintext_modulus = 18433,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 40961, 59393, 61441, 65537 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "polynomial degree is not power of two");
        CC_FREE_BP_WS(ws, bp);
    }
    // coefficient moduli contains repeated element
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 18433,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 5,
                                                                    .moduli = { 40961, 59393, 61441, 65537, 65537 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "polynomial degree is not power of two");
        CC_FREE_BP_WS(ws, bp);
    }
    // plaintext modulus is the same as one of the coefficient moduli
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 40961, 59393, 61441, 65537 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
           CCERR_PARAMETER,
           "plaintext modulus is the same as one of the coefficient moduli");
        CC_FREE_BP_WS(ws, bp);
    }
    // plaintext modulus is not prime
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 1234,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 40961, 59393, 61441, 65537 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "plaintext modulus is not prime");
        CC_FREE_BP_WS(ws, bp);
    }
    // one of the coefficient modulus is not NTT-friendly
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 18433,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 5,
                                                                    .moduli = { 40867, 40961, 59393, 61441, 65537 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
           CCERR_PARAMETER,
           "one of the coefficient modulus is not NTT-friendly");
        CC_FREE_BP_WS(ws, bp);
    }
    // plaintext modulus is larger than one of the coefficient modulus
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 133121,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 40961, 59393, 61441, 65537 } };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
           CCERR_PARAMETER,
           "plaintext modulus is larger than one of the coefficient modulus");
        CC_FREE_BP_WS(ws, bp);
    }
    // nskip_bits too large
    {
        static const struct ccbfv_encrypt_params encrypt_params = {
            .poly_modulus_degree = 1024,
            .plaintext_modulus = 18433,
            .nskip_lsbs = { 100, 0 },
            .nmoduli = 4,
            .moduli = { 40961, 59393, 61441, 65537 },
        };
        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "nskip_lsbs too large");
        CC_FREE_BP_WS(ws, bp);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_param_ctx_eq(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params_1 = { .poly_modulus_degree = 1024,
                                                                  .plaintext_modulus = 11,
                                                                  .nskip_lsbs = { 0, 0 },
                                                                  .nmoduli = 2,
                                                                  .moduli = { 536903681ULL, 576460752303439873ULL } };
    ccbfv_param_ctx_t param_ctx_1 = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_1);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx_1, &encrypt_params_1), CCERR_OK, "BFV param ctx init");

    // Same context
    {
        ccbfv_param_ctx_t param_ctx_2 = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_1);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_1), CCERR_OK, "BFV param ctx init");
        is(ccbfv_param_ctx_eq(param_ctx_1, param_ctx_1), true, "ccbfv_param_ctx_eq same pointer");
        is(ccbfv_param_ctx_eq(param_ctx_1, param_ctx_2), true, "ccbfv_param_ctx_eq same object");
    }
    // Different moduli
    {
        static const struct ccbfv_encrypt_params encrypt_params_2 = { .poly_modulus_degree = 1024,
                                                                      .plaintext_modulus = 11,
                                                                      .nskip_lsbs = { 0, 0 },
                                                                      .nmoduli = 2,
                                                                      .moduli = { 536903681ULL, 68719403009ULL } };
        ccbfv_param_ctx_t param_ctx_2 = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_2);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_2), CCERR_OK, "BFV param ctx init");
        is(ccbfv_param_ctx_eq(param_ctx_1, param_ctx_2), false, "ccbfv_param_ctx_eq different ciphertext moduli");
    }
    // Different plaintext modulus
    {
        static const struct ccbfv_encrypt_params encrypt_params_2 = { .poly_modulus_degree = 1024,
                                                                      .plaintext_modulus = 13,
                                                                      .nskip_lsbs = { 0, 0 },
                                                                      .nmoduli = 2,
                                                                      .moduli = { 536903681ULL, 68719403009ULL } };
        ccbfv_param_ctx_t param_ctx_2 = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_2);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_2), CCERR_OK, "BFV param ctx init");
        is(ccbfv_param_ctx_eq(param_ctx_1, param_ctx_2), false, "ccbfv_param_ctx_eq different plaintext modulus");
    }
    // Different poly modulus degree
    {
        static const struct ccbfv_encrypt_params encrypt_params_2 = { .poly_modulus_degree = 2048,
                                                                      .plaintext_modulus = 13,
                                                                      .nskip_lsbs = { 0, 0 },
                                                                      .nmoduli = 2,
                                                                      .moduli = { 536903681ULL, 68719403009ULL } };
        ccbfv_param_ctx_t param_ctx_2 = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_2);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_2), CCERR_OK, "BFV param ctx init");
        is(ccbfv_param_ctx_eq(param_ctx_1, param_ctx_2), false, "ccbfv_param_ctx_eq different plaintext modulus");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encode_decode_errors(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                .plaintext_modulus = 40961,
                                                                .nskip_lsbs = { 0, 0 },
                                                                .nmoduli = 4,
                                                                .moduli = { 65537, 114689, 147457, 163841 } };
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (3 moduli)");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);

    // too many values - encode poly uint64
    {
        uint64_t values[4097] = { 0 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_poly_uint64(ptext, param_ctx, 4097, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_poly_uint64_errors too many values");
    }
    // too many values - encode uint64
    {
        uint64_t values[4097] = { 0 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_uint64(ptext, param_ctx, 4097, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_uint64_errors too many values");
    }
    // too many values - encode int64
    {
        int64_t values[4097] = { 0 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_int64(ptext, param_ctx, 4097, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_int64_errors too many values");
    }
    // too many values - decode poly uint64
    {
        uint64_t values[4096] = { 0 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_poly_uint64(ptext, param_ctx, 4096, values), CCERR_OK, "ccbfv_encode_poly_uint64 != CCERR_OK");
        is(ccbfv_decode_poly_uint64(4097, values, ptext),
           CCERR_PARAMETER,
           "test_ccbfv_decode_poly_uint64_errors too many values");
    }
    // too many values - decode uint64
    {
        uint64_t values[4096] = { 0 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_uint64(ptext, param_ctx, 4096, values), CCERR_OK, "ccbfv_encode_simd_uint64 != CCERR_OK");
        is(ccbfv_decode_simd_uint64_ws(ws, 4097, values, ptext),
           CCERR_PARAMETER,
           "test_ccbfv_decode_uint64_errors too many values");
    }
    // too many values - decode int64
    {
        int64_t values[4096] = { 0 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_int64(ptext, param_ctx, 4096, values), CCERR_OK, "ccbfv_encode_simd_int64 != CCERR_OK");
        is(ccbfv_decode_simd_int64_ws(ws, 4097, values, ptext),
           CCERR_PARAMETER,
           "test_ccbfv_decode_int64_errors too many values");
    }
    // encode single too large value - uint64 poly
    {
        uint64_t values[] = { 40961 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_poly_uint64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_poly_uint64_errors single too large value");
    }
    // encode single too large value - uint64
    {
        uint64_t values[] = { 40961 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_uint64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_uint64_errors single too large value");
    }
    // encode multiple too large values - uint64 poly
    {
        uint64_t values[] = { 0, 40962, 40961 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_poly_uint64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_uint64_poly_errors multiple too large value");
    }
    // encode multiple too large values - uint64
    {
        uint64_t values[] = { 0, 40962, 40961 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_uint64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_uint64_errors multiple too large value");
    }
    // encode single too large values - int64 exceeds positive bound
    {
        int64_t values[] = { 20481 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_int64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_int64_errors single too large value postive ");
    }
    // encode multiple too large values - int64 exceeds positive bound
    {
        int64_t values[] = { 0, 20481, 20482 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_int64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_int64_errors multiple too large values positive");
    }
    // encode single too large value - int64 exceeds negative bound
    {
        int64_t values[] = { -20481 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_int64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_int64_errors single too large value negative ");
    }
    // encode multiple too large values - int64 exceeds negative bound
    {
        int64_t values[] = { 0, 0, -20481 };
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_int64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_ccbfv_encode_simd_int64_errors multiple too large values negative ");
    }
    // plaintext from wrong context - decode uint64 poly
    {
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        ccpolyzp_po2cyc_coeff_t ptext_poly = ccbfv_plaintext_polynomial(ptext);

        uint64_t values[] = { 0 };
        is(ccbfv_encode_poly_uint64(ptext, param_ctx, 1, values), CCERR_OK, "ccbfv_encode_poly_uint64 != CCERR_OK");

        ptext_poly->context = ccbfv_param_ctx_encrypt_key_context(param_ctx);
        is(ccbfv_decode_poly_uint64(1, values, ptext), CCERR_PARAMETER, "test_ccbfv_decode_poly_uint64_errors wrong context");
    }
    // plaintext from wrong context - decode uint64
    {
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        ccpolyzp_po2cyc_coeff_t ptext_poly = ccbfv_plaintext_polynomial(ptext);

        uint64_t values[] = { 0 };
        is(ccbfv_encode_simd_uint64(ptext, param_ctx, 1, values), CCERR_OK, "ccbfv_encode_simd_uint64 != CCERR_OK");

        ptext_poly->context = ccbfv_param_ctx_encrypt_key_context(param_ctx);
        is(ccbfv_decode_simd_uint64_ws(ws, 1, values, ptext), CCERR_PARAMETER, "test_ccbfv_decode_uint64_errors wrong context");
    }
    // plaintext from wrong context - decode int64
    {
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        ccpolyzp_po2cyc_coeff_t ptext_poly = ccbfv_plaintext_polynomial(ptext);

        int64_t values[] = { 0 };
        is(ccbfv_encode_simd_int64(ptext, param_ctx, 1, values), CCERR_OK, "ccbfv_encode_simd_int64 != CCERR_OK");

        ptext_poly->context = ccbfv_param_ctx_encrypt_key_context(param_ctx);
        is(ccbfv_decode_simd_int64_ws(ws, 1, values, ptext), CCERR_PARAMETER, "test_ccbfv_decode_int64_errors wrong context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encode_decode_poly_uint64(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = {
        .poly_modulus_degree = 4096, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
    };
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "ccbfv_param_ctx_init_ws != CCERR_OK");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);

    // N values roundtrip
    {
        uint64_t values[4096] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_poly_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "ccbfv_encode_poly_uint64 != CCERR_OK");
        bool encode_values_match = true;
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccpolyzp_po2cyc_coeff_const_t poly = ccbfv_plaintext_polynomial_const(ptext);
            ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, 0, i);
            encode_values_match &= (coeff == values[i]);
        }
        is(encode_values_match, true, "ccbfv_encode_poly_uint64 N values mismatch");

        uint64_t values_decoded[4096] = { 0 };
        is(ccbfv_decode_poly_uint64(4096, values_decoded, ptext), CCERR_OK, "ccbfv_decode_poly_uint64 != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_ccbfv_encode_decode_simd_uint64 N roundtrip");
    }
    // < N values roundtrip
    {
        uint64_t values[123] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_poly_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "ccbfv_encode_poly_uint64 != CCERR_OK");
        bool encode_values_match = true;
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccpolyzp_po2cyc_coeff_const_t poly = ccbfv_plaintext_polynomial_const(ptext);
            ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, 0, i);
            encode_values_match &= (coeff == values[i]);
        }
        for (uint32_t i = CC_ARRAY_LEN(values); i < encrypt_params.poly_modulus_degree; ++i) {
            ccpolyzp_po2cyc_coeff_const_t poly = ccbfv_plaintext_polynomial_const(ptext);
            ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, 0, i);
            encode_values_match &= (coeff == 0);
        }
        is(encode_values_match, true, "ccbfv_encode_poly_uint64 <N values mismatch");

        uint64_t values_decoded[123] = { 0 };
        is(ccbfv_decode_poly_uint64(123, values_decoded, ptext), CCERR_OK, "ccbfv_decode_poly_uint64 != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_ccbfv_encode_decode_poly_uint64 <N roundtrip");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encode_decode_simd_uint64(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = {
        .poly_modulus_degree = 4096, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
    };
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "ccbfv_param_ctx_init_ws != CCERR_OK");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);

    // N values roundtrip
    {
        uint64_t values[4096] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "ccbfv_encode_simd_uint64 != CCERR_OK");

        uint64_t values_decoded[4096] = { 0 };
        is(ccbfv_decode_simd_uint64_ws(ws, 4096, values_decoded, ptext), CCERR_OK, "ccbfv_decode_simd_uint64_ws != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_ccbfv_encode_decode_simd_uint64 N roundtrip");
    }
    // < N values roundtrip
    {
        uint64_t values[123] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(ccbfv_encode_simd_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "ccbfv_encode_simd_uint64 != CCERR_OK");

        uint64_t values_decoded[123] = { 0 };
        is(ccbfv_decode_simd_uint64_ws(ws, 123, values_decoded, ptext), CCERR_OK, "ccbfv_decode_simd_uint64_ws != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_ccbfv_encode_decode_simd_uint64 <N roundtrip");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encode_decode_simd_int64(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = {
        .poly_modulus_degree = 128, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
    };
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (3 moduli)");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);

    // N values roundtrip
    {
        int64_t values[128] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            values[i] = uniform_int64(40961);
        }
        values[0] = -20480;
        values[1] = 20479;

        is(ccbfv_encode_simd_int64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "ccbfv_encode_simd_int64 != CCERR_OK");

        int64_t values_decoded[128] = { 0 };
        is(ccbfv_decode_simd_int64_ws(ws, 128, values_decoded, ptext), CCERR_OK, "ccbfv_decode_simd_int64_ws != CCERR_OK");

        is(array_eq_int64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_ccbfv_encode_decode_simd_int64 N roundtrip");
    }
    // < N values roundtrip
    {
        int64_t values[123] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            values[i] = uniform_int64(40961);
        }
        values[0] = -20480;
        values[1] = 20479;
        is(ccbfv_encode_simd_int64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "ccbfv_encode_simd_int64 != CCERR_OK");

        int64_t values_decoded[123] = { 0 };
        is(ccbfv_decode_simd_int64_ws(ws, 123, values_decoded, ptext), CCERR_OK, "ccbfv_decode_simd_int64_ws != CCERR_OK");

        is(array_eq_int64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_ccbfv_encode_decode_simd_int64 <N roundtrip");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encrypt_error(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                .plaintext_modulus = 40961,
                                                                .nskip_lsbs = { 0, 0 },
                                                                .nmoduli = 4,
                                                                .moduli = { 65537, 114689, 147457, 163841 } };
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init");
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    static const struct ccbfv_encrypt_params encrypt_params_diff = { .poly_modulus_degree = 1024,
                                                                     .plaintext_modulus = 40961,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 4,
                                                                     .moduli = { 65537, 114689, 147457, 163841 } };
    ccbfv_param_ctx_t param_ctx_diff = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_diff);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx_diff, &encrypt_params_diff), CCERR_OK, "BFV param ctx init");

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    ccbfv_secret_key_t secret_key_diff = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx_diff);
    is(ccbfv_secret_key_generate_ws(ws, secret_key_diff, param_ctx_diff, global_test_rng), CCERR_OK, "Secret key generation");

    // ok
    {
        int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "BFV encrypt");
    }
    // secret key / parameter context mismatch
    {
        int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key_diff, nmoduli, NULL, global_test_rng);
        is(rv, CCERR_PARAMETER, "BFV encrypt different contexts");
    }
    // nmoduli too small
    {
        int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, 0, NULL, global_test_rng);
        is(rv, CCERR_PARAMETER, "BFV encrypt 0 moduli");
    }
    // nmoduli too large
    {
        int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli + 2, NULL, global_test_rng);
        is(rv, CCERR_PARAMETER, "BFV encrypt too many moduli");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_decrypt_error(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                .plaintext_modulus = 40961,
                                                                .nskip_lsbs = { 0, 0 },
                                                                .nmoduli = 4,
                                                                .moduli = { 65537, 114689, 147457, 163841 } };
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (4 moduli)");
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    static const struct ccbfv_encrypt_params encrypt_params_diff = { .poly_modulus_degree = 1024,
                                                                     .plaintext_modulus = 40961,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 4,
                                                                     .moduli = { 65537, 114689, 147457, 163841 } };
    ccbfv_param_ctx_t param_ctx_diff = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_diff);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx_diff, &encrypt_params_diff), CCERR_OK, "BFV param ctx init (4 moduli)");
    ccbfv_secret_key_t secret_key_diff = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx_diff);
    is(ccbfv_secret_key_generate_ws(ws, secret_key_diff, param_ctx_diff, global_test_rng), CCERR_OK, "Secret key generation");

    int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV encrypt");

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    is(ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key), CCERR_OK, "BFV decrypt");

    // secret key wrong parameter context
    {
        is(ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key_diff),
           CCERR_PARAMETER,
           "BFV decrypt secret key wrong context");
    }
    // ciphertext wrong parameter context
    {
        is(ccbfv_decrypt_ws(ws, ptext, param_ctx_diff, ctext, secret_key_diff),
           CCERR_PARAMETER,
           "BFV decrypt ctext wrong context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encrypt_zero_seed(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                .plaintext_modulus = 40961,
                                                                .nskip_lsbs = { 0, 0 },
                                                                .nmoduli = 4,
                                                                .moduli = { 65537, 114689, 147457, 163841 } };
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (4 moduli)");
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");
    int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV encrypt zero symmetric no seed");
    struct ccpolyzp_po2cyc_block_rng_seed seed = { .data = { 1 } };
    rv = ccbfv_encrypt_zero_symmetric_coeff_ws(
        ws, ctext, param_ctx, secret_key, nmoduli, (ccbfv_rng_seed_t)&seed, global_test_rng);
    is(rv, CCERR_OK, "BFV encrypt zero symmetric with seed");

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encrypt_decrypt_zero(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    CC_DECL_BP_WS(ws, bp);

    // 1 modulus
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 1,
                                                                    .moduli = { 18014398509309953ULL } };

        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (1 modulus)");
        uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

        ccbfv_ciphertext_coeff_t ctext =
            CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
        ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");
        int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "BFV encrypt zero symmetric no seed");

        ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);

        rv = ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
        is(rv, CCERR_OK, "BFV decrypt zero symmetric no seed");
        uint64_t values_decoded[4096] = { 0 };
        for (uint32_t i = 0; i < 4096; ++i) {
            values_decoded[i] = 1;
        }
        is(ccbfv_decode_simd_uint64_ws(ws, 4096, values_decoded, ptext), CCERR_OK, "ccbfv_decode_simd_uint64_ws != CCERR_OK");
        uint64_t zero_data[4096] = { 0 };
        is(array_eq_uint64(4096, values_decoded, zero_data), true, "BFV encrypt decrypt zero (1 modulus)");

        CC_FREE_BP_WS(ws, bp);
    }
    // 4 moduli
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };

        ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV param ctx init (4 moduli)");
        uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

        ccbfv_ciphertext_coeff_t ctext =
            CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
        ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
        is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");
        int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "BFV encrypt zero symmetric no seed");

        ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
        ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);

        rv = ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
        is(rv, CCERR_OK, "BFV decrypt zero symmetric no seed");
        uint64_t values_decoded[4096] = { 0 };
        for (uint32_t i = 0; i < 4096; ++i) {
            values_decoded[i] = 1;
        }
        is(ccbfv_decode_simd_uint64_ws(ws, 4096, values_decoded, ptext), CCERR_OK, "ccbfv_decode_simd_uint64_ws != CCERR_OK");
        uint64_t zero_data[4096] = { 0 };
        is(array_eq_uint64(4096, values_decoded, zero_data), true, "BFV encrypt decrypt zero (4 moduli)");

        CC_FREE_BP_WS(ws, bp);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encrypt_decrypt_nonzero_helper(cc_ws_t ws,
                                                      uint32_t degree,
                                                      uint32_t plaintext_modulus,
                                                      ccbfv_encrypt_params_const_t encrypt_params,
                                                      bool sk_from_seed)
{
    CC_DECL_BP_WS(ws, bp);
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, encrypt_params),
       CCERR_OK,
       "BFV param ctx init (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    if (!sk_from_seed) {
        is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
           CCERR_OK,
           "Secret key generation (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
    } else {
        struct ccpolyzp_po2cyc_block_rng_seed seed = { .data = { 1 } };
        is(ccbfv_secret_key_generate_from_seed_ws(ws, secret_key, param_ctx, (ccbfv_rng_seed_t)&seed),
           CCERR_OK,
           "Secret key generation with seed (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
    }

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    uint64_t values[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        ccrng_uniform(global_test_rng, plaintext_modulus, values + i);
    }
    is(ccbfv_encode_simd_uint64(ptext, param_ctx, degree, values),
       CCERR_OK,
       "ccbfv_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    int rv = ccbfv_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV encrypt symmetric no seed (%" PRIu32 " moduli)", encrypt_params->nmoduli);

    rv = ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
    is(rv, CCERR_OK, "BFV decrypt symmetric no seed (%" PRIu32 " moduli)", encrypt_params->nmoduli);
    uint64_t values_decoded[degree];
    is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext),
       CCERR_OK,
       "ccbfv_decode_simd_uint64_ws != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    is(array_eq_uint64(degree, values_decoded, values),
       true,
       "BFV encrypt decrypt (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    CC_FREE_BP_WS(ws, bp);
}

static void test_ccbfv_encrypt_decrypt_nonzero(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    // 1 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 1,
                                                                    .moduli = { 18014398509309953ULL } };

        test_ccbfv_encrypt_decrypt_nonzero_helper(ws, degree, plaintext_modulus, &encrypt_params, false);
    }
    // 4 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };

        test_ccbfv_encrypt_decrypt_nonzero_helper(ws, degree, plaintext_modulus, &encrypt_params, false);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_encrypt_decrypt_sk_from_seed(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    // 1 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 1,
                                                                    .moduli = { 18014398509309953ULL } };

        test_ccbfv_encrypt_decrypt_nonzero_helper(ws, degree, plaintext_modulus, &encrypt_params, true);
    }
    // 4 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };

        test_ccbfv_encrypt_decrypt_nonzero_helper(ws, degree, plaintext_modulus, &encrypt_params, true);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_cipher_plain_add_helper(cc_ws_t ws,
                                               uint32_t degree,
                                               uint32_t plaintext_modulus,
                                               ccbfv_encrypt_params_const_t encrypt_params)
{
    CC_DECL_BP_WS(ws, bp);
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, encrypt_params),
       CCERR_OK,
       "BFV param ctx init (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
       CCERR_OK,
       "Secret key generation (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    uint64_t values1[degree];
    uint64_t values2[degree];
    uint64_t sum[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        ccrng_uniform(global_test_rng, plaintext_modulus, values1 + i);
        ccrng_uniform(global_test_rng, plaintext_modulus, values2 + i);
        sum[i] = (values1[i] + values2[i]) % plaintext_modulus;
    }

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t ptext1 = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    ccbfv_plaintext_t ptext2 = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    is(ccbfv_encode_simd_uint64(ptext1, param_ctx, degree, values1),
       CCERR_OK,
       "ccbfv_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    is(ccbfv_encode_simd_uint64(ptext2, param_ctx, degree, values2),
       CCERR_OK,
       "ccbfv_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    int rv = ccbfv_encrypt_symmetric_ws(ws, ctext, ptext1, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "cipher_plain_add: encrypt (%" PRIu32 " moduli)", encrypt_params->nmoduli);

    // out-of-place
    {
        ccbfv_ciphertext_coeff_t ctext_sum =
            CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context(param_ctx);
        ccbfv_ciphertext_coeff_init(ctext_sum, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);
        rv = ccbfv_ciphertext_plaintext_add_ws(ws, ctext_sum, ctext, ptext2);
        is(rv, CCERR_OK, "cipher_plain_add: cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        rv = ccbfv_decrypt_ws(ws, ptext1, param_ctx, ctext_sum, secret_key);
        is(rv, CCERR_OK, "cipher_plain_add: decrypt (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        uint64_t values_decoded[degree];
        is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext1),
           CCERR_OK,
           "ccbfv_decode_simd_uint64_ws != CCERR_OK (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
        is(array_eq_uint64(degree, values_decoded, sum), true, "cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
    }
    // in-place
    {
        rv = ccbfv_ciphertext_plaintext_add_ws(ws, ctext, ctext, ptext2);
        is(rv, CCERR_OK, "cipher_plain_add: cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        rv = ccbfv_decrypt_ws(ws, ptext1, param_ctx, ctext, secret_key);
        is(rv, CCERR_OK, "cipher_plain_add: decrypt (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        uint64_t values_decoded[degree];
        is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext1),
           CCERR_OK,
           "ccbfv_decode_simd_uint64_ws != CCERR_OK (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
        is(array_eq_uint64(degree, values_decoded, sum), true, "cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
    }
    CC_FREE_BP_WS(ws, bp);
}

static void test_ccbfv_cipher_plain_add(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    // 1 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 1,
                                                                    .moduli = { 18014398509309953ULL } };

        test_ccbfv_cipher_plain_add_helper(ws, degree, plaintext_modulus, &encrypt_params);
    }
    // 4 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };

        test_ccbfv_cipher_plain_add_helper(ws, degree, plaintext_modulus, &encrypt_params);
    }
    CC_FREE_WORKSPACE(ws);
}

static void
test_ccbfv_mod_switch_helper(cc_ws_t ws, uint32_t degree, uint32_t plaintext_modulus, ccbfv_encrypt_params_const_t encrypt_params)
{
    CC_DECL_BP_WS(ws, bp);
    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, encrypt_params),
       CCERR_OK,
       "BFV param ctx init (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    uint64_t values[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        ccrng_uniform(global_test_rng, plaintext_modulus, values + i);
    }
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    is(ccbfv_encode_simd_uint64(ptext, param_ctx, degree, values),
       CCERR_OK,
       "ccbfv_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    uint32_t nctext_moduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    // mod switch down
    {
        int rv = ccbfv_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nctext_moduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "mod_switch: encrypt");
        for (uint32_t nmoduli = nctext_moduli; nmoduli > 1; --nmoduli) {
            rv = ccbfv_ciphertext_mod_switch_down_ws(ws, ctext);
            is(rv, CCERR_OK, "mod_switch: mod_switch_down");
            is(ccbfv_ciphertext_coeff_ctx(ctext)->dims.nmoduli, nmoduli - 1, "mod_switch: (%" PRIu32 " moduli)", nmoduli);
            rv = ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
            is(rv, CCERR_OK, "mod_switch: decrypt");
            uint64_t values_decoded[degree];
            is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext),
               CCERR_OK,
               "ccbfv_decode_simd_uint64_ws != CCERR_OK");
            is(array_eq_uint64(degree, values_decoded, values), true, "mod_switch: (%" PRIu32 " moduli)", nmoduli);
        }
        // Mod-switch with single ciphertext yields error
        rv = ccbfv_ciphertext_mod_switch_down_ws(ws, ctext);
        is(rv, CCERR_PARAMETER, "mod_switch: mod_switch_down with 1 modulus");
    }
    // mod switch down to single
    {
        int rv = ccbfv_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nctext_moduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "mod_switch: encrypt");
        rv = ccbfv_ciphertext_mod_switch_down_to_single_ws(ws, ctext);
        is(rv, CCERR_OK, "mod_switch: mod_switch_down_to_single");
        is(ccbfv_ciphertext_coeff_ctx(ctext)->dims.nmoduli, 1, "mod_switch: nmoduli");
        rv = ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
        is(rv, CCERR_OK, "mod_switch: decrypt");
        uint64_t values_decoded[degree];
        is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext), CCERR_OK, "ccbfv_decode_simd_uint64_ws != CCERR_OK");
        is(array_eq_uint64(degree, values_decoded, values), true, "mod_switch: (%" PRIu32 " moduli)", nctext_moduli);
    }
    CC_FREE_BP_WS(ws, bp);
}

static void test_ccbfv_mod_switch(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    // 1 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 1,
                                                                    .moduli = { 18014398509309953ULL } };

        test_ccbfv_mod_switch_helper(ws, degree, plaintext_modulus, &encrypt_params);
    }
    // 4 modulus
    {
        static const uint32_t degree = 4096;
        static const uint32_t plaintext_modulus = 40961;
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = degree,
                                                                    .plaintext_modulus = plaintext_modulus,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 18014398509309953ULL, 114689, 147457, 163841 } };

        test_ccbfv_mod_switch_helper(ws, degree, plaintext_modulus, &encrypt_params);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_cipher_plain_mul_helper(cc_ws_t ws, ccbfv_encrypt_params_const_t encrypt_params)
{
    CC_DECL_BP_WS(ws, bp);

    uint32_t degree = encrypt_params->poly_modulus_degree;
    ccrns_int plaintext_modulus = encrypt_params->plaintext_modulus;
    uint32_t nmoduli = encrypt_params->nmoduli;

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, encrypt_params),
       CCERR_OK,
       "ccbfv_param_ctx_init_ws (%" PRIu32 " modulus)",
       nmoduli);

    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context(param_ctx);
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_cipher_plain_ctx_const_t cipher_plain_ctx = ccbfv_param_ctx_cipher_plain_ctx_const(param_ctx, cipher_ctx->dims.nmoduli);

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t ctext_prod =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_eval_t ctext_eval =
        CCBFV_CIPHERTEXT_EVAL_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_eval_t ctext_eval_prod =
        CCBFV_CIPHERTEXT_EVAL_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_init(ctext_prod, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);
    ccbfv_ciphertext_eval_init(ctext_eval_prod, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
       CCERR_OK,
       "ccbfv_secret_key_generate_ws (%" PRIu32 " modulus)",
       nmoduli);

    uint64_t *values1 = (uint64_t *)CC_ALLOC_WS(ws, ccn_nof_sizeof(uint64_t) * degree);
    uint64_t *values2 = (uint64_t *)CC_ALLOC_WS(ws, ccn_nof_sizeof(uint64_t) * degree);
    uint64_t *prod = (uint64_t *)CC_ALLOC_WS(ws, ccn_nof_sizeof(uint64_t) * degree);
    uint64_t *values_decoded = (uint64_t *)CC_ALLOC_WS(ws, ccn_nof_sizeof(uint64_t) * degree);
    for (uint32_t i = 0; i < degree; ++i) {
        ccrng_uniform(global_test_rng, plaintext_modulus, values1 + i);
        ccrng_uniform(global_test_rng, plaintext_modulus, values2 + i);
        prod[i] = (values1[i] * values2[i]) % plaintext_modulus;
    }

    ccbfv_plaintext_t ptext1 = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    ccbfv_plaintext_t ptext2 = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    ccbfv_dcrt_plaintext_t dcrt_ptext2 = CCBFV_DCRT_PLAINTEXT_ALLOC_WS(ws, cipher_ctx);
    is(ccbfv_encode_simd_uint64(ptext1, param_ctx, degree, values1),
       CCERR_OK,
       "ccbfv_encode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(ccbfv_encode_simd_uint64(ptext2, param_ctx, degree, values2),
       CCERR_OK,
       "ccbfv_encode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(ccbfv_dcrt_plaintext_encode_ws(ws, dcrt_ptext2, ptext2, cipher_plain_ctx),
       CCERR_OK,
       "ccbfv_dcrt_plaintext_encode_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);

    int rv =
        ccbfv_encrypt_symmetric_ws(ws, ctext, ptext1, param_ctx, secret_key, cipher_ctx->dims.nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "cipher_plain_mul: encrypt (%" PRIu32 " modulus)", nmoduli);

    ccbfv_ciphertext_coeff_copy((ccbfv_ciphertext_coeff_t)ctext_eval, ctext);
    rv = ccbfv_ciphertext_fwd_ntt((ccbfv_ciphertext_coeff_t)ctext_eval);
    is(rv, CCERR_OK, "cipher_plain_mul: fwd_ntt (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_coeff plantext mul
    rv = ccbfv_ciphertext_coeff_plaintext_mul_ws(ws, ctext_prod, ctext, ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: ccbfv_ciphertext_coeff_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = ccbfv_decrypt_ws(ws, ptext1, param_ctx, ctext_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt (%" PRIu32 " modulus)", nmoduli);
    is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext1),
       CCERR_OK,
       "ccbfv_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_coeff dcrt-plaintext mul
    rv = ccbfv_ciphertext_coeff_dcrt_plaintext_mul(ctext_prod, ctext, dcrt_ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: ccbfv_ciphertext_dcrt_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = ccbfv_decrypt_ws(ws, ptext1, param_ctx, ctext_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt_dcrt (%" PRIu32 " modulus)", nmoduli);
    is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext1),
       CCERR_OK,
       "ccbfv_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_eval plantext mul
    rv = ccbfv_ciphertext_eval_plaintext_mul_ws(ws, ctext_eval_prod, ctext_eval, ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: ccbfv_ciphertext_eval_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = ccbfv_ciphertext_inv_ntt(ctext_eval_prod);
    is(rv, CCERR_OK, "cipher_plain_mul: inv_ntt (%" PRIu32 " modulus)", nmoduli);
    rv = ccbfv_decrypt_ws(ws, ptext1, param_ctx, (ccbfv_ciphertext_coeff_const_t)ctext_eval_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt (%" PRIu32 " modulus)", nmoduli);
    is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext1),
       CCERR_OK,
       "ccbfv_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_eval dcrt-plaintext mul
    rv = ccbfv_ciphertext_eval_dcrt_plaintext_mul(ctext_eval_prod, ctext_eval, dcrt_ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: ccbfv_ciphertext_dcrt_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = ccbfv_ciphertext_inv_ntt(ctext_eval_prod);
    is(rv, CCERR_OK, "cipher_plain_mul: inv_ntt (%" PRIu32 " modulus)", nmoduli);
    rv = ccbfv_decrypt_ws(ws, ptext1, param_ctx, (ccbfv_ciphertext_coeff_const_t)ctext_eval_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt_dcrt (%" PRIu32 " modulus)", nmoduli);
    is(ccbfv_decode_simd_uint64_ws(ws, degree, values_decoded, ptext1),
       CCERR_OK,
       "ccbfv_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    CC_FREE_BP_WS(ws, bp);
}

static void test_ccbfv_cipher_plain_mul(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // 1 modulus
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 1,
                                                                    .moduli = { 18014398509309953ULL } };
        test_ccbfv_cipher_plain_mul_helper(ws, &encrypt_params);
    }
    // 4 modulus
    {
        static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };
        test_ccbfv_cipher_plain_mul_helper(ws, &encrypt_params);
    }
    CC_FREE_WORKSPACE(ws);
}

int ccbfv_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int ntests = 0;
    ntests += 6;    // test_ccbfv_encrypt_params_eq
    ntests += 22;   // test_ccbfv_param_ctx_init
    ntests += 8;    // test_ccbfv_param_ctx_init_errors
    ntests += 10;   // test_ccbfv_param_ctx_eq
    ntests += 24;   // test_ccbfv_encode_decode_errors
    ntests += 9;    // test_ccbfv_encode_decode_poly_uint64
    ntests += 7;    // test_ccbfv_encode_decode_simd_uint64
    ntests += 7;    // test_ccbfv_encode_decode_simd_int64
    ntests += 5;    // test_ccbfv_encrypt_error
    ntests += 11;   // test_ccbfv_decrypt_error
    ntests += 4;    // test_ccbfv_encrypt_zero_seed
    ntests += 12;   // test_ccbfv_encrypt_decrypt_zero
    ntests += 14;   // test_ccbfv_encrypt_decrypt_nonzero
    ntests += 14;   // test_ccbfv_encrypt_decrypt_sk_from_seed
    ntests += 26;   // test_ccbfv_cipher_plain_add
    ntests += 50;   // test_ccbfv_cipher_plain_mul
    ntests += 32;   // test_ccbfv_mod_switch
    ntests += 1900; // test_ccbfv_galois
    ntests += 58;   // test_ccbfv_relin
    ntests += 55;   // test_ccbfv_serialization
    ntests += 41;   // test_ccbfv_compose_decompose

    ntests += ntests_ccbfv_public(); // test_ccbfv_public

    plan_tests(ntests);

    test_ccbfv_encrypt_params_eq();
    test_ccbfv_param_ctx_init();
    test_ccbfv_param_ctx_init_errors();
    test_ccbfv_param_ctx_eq();

    // encoding / decoding
    test_ccbfv_encode_decode_errors();
    test_ccbfv_encode_decode_poly_uint64();
    test_ccbfv_encode_decode_simd_uint64();
    test_ccbfv_encode_decode_simd_int64();

    // encryption / decryption
    test_ccbfv_encrypt_error();
    test_ccbfv_decrypt_error();
    test_ccbfv_encrypt_zero_seed();
    test_ccbfv_encrypt_decrypt_zero();
    test_ccbfv_encrypt_decrypt_nonzero();
    test_ccbfv_encrypt_decrypt_sk_from_seed();

    // operations
    test_ccbfv_cipher_plain_add();
    test_ccbfv_cipher_plain_mul();
    test_ccbfv_mod_switch();
    test_ccbfv_galois();
    test_ccbfv_relin();

    // serialization / deserialization
    test_ccbfv_serialization();

    // composition / decomposition
    test_ccbfv_compose_decompose();

    // public
    test_ccbfv_public();

    return 0;
}
