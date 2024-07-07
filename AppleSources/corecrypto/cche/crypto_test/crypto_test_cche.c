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
#include "crypto_test_cche.h"
#include "cche_debug.h"
#include "cche_internal.h"
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_debug.h"
#include <corecrypto/ccrng.h>
#include "cche_util.h"

#undef CC_DECL_WORKSPACE_TEST
#define CC_DECL_WORKSPACE_TEST(ws)                                    \
    int ws##_rv;                                                      \
    CC_DECL_WORKSPACE_RV(ws, ccn_nof_size(3 * 1024 * 1024), ws##_rv); \
    cc_try_abort_if(ws##_rv != CCERR_OK, "alloc ws");

cche_encrypt_params_const_t get_test_encrypt_params(cche_scheme_t he_scheme, uint32_t nmoduli)
{
    static const uint32_t degree = 16;
    static const ccrns_int plaintext_modulus = 40961;

    static const struct cche_encrypt_params encrypt_params_1_bfv = { .he_scheme = CCHE_SCHEME_BFV,
                                                                     .poly_modulus_degree = degree,
                                                                     .plaintext_modulus = plaintext_modulus,
                                                                     .nmoduli = 1,
                                                                     .moduli = { 18014398509309953ULL } };

    static const struct cche_encrypt_params encrypt_params_2_bfv = { .he_scheme = CCHE_SCHEME_BFV,
                                                                     .poly_modulus_degree = degree,
                                                                     .plaintext_modulus = plaintext_modulus,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 2,
                                                                     .moduli = { 18014398509309953ULL, 576460752303439873ULL } };

    static const struct cche_encrypt_params encrypt_params_3_bfv = { .he_scheme = CCHE_SCHEME_BFV,
                                                                     .poly_modulus_degree = degree,
                                                                     .plaintext_modulus = plaintext_modulus,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 3,
                                                                     .moduli = {
                                                                         536903681ULL, 68719403009ULL, 576460752303439873ULL } };

    static const struct cche_encrypt_params encrypt_params_4_bfv = {
        .he_scheme = CCHE_SCHEME_BFV,
        .poly_modulus_degree = degree,
        .plaintext_modulus = plaintext_modulus,
        .nskip_lsbs = { 0, 0 },
        .nmoduli = 4,
        .moduli = { 536903681ULL, 68719403009ULL, 1073692673ULL, 576460752303439873ULL }
    };

    static const struct cche_encrypt_params encrypt_params_5_bfv = {
        .he_scheme = CCHE_SCHEME_BFV,
        .poly_modulus_degree = degree,
        .plaintext_modulus = plaintext_modulus,
        .nskip_lsbs = { 0, 0 },
        .nmoduli = 5,
        .moduli = { 536903681ULL, 68719403009ULL, 1073692673ULL, 137438822401ULL, 576460752303439873ULL }
    };

    static const struct cche_encrypt_params encrypt_params_1_bgv = { .he_scheme = CCHE_SCHEME_BGV,
                                                                     .poly_modulus_degree = degree,
                                                                     .plaintext_modulus = plaintext_modulus,
                                                                     .nmoduli = 1,
                                                                     .moduli = { 18014398509309953ULL } };

    static const struct cche_encrypt_params encrypt_params_2_bgv = { .he_scheme = CCHE_SCHEME_BGV,
                                                                     .poly_modulus_degree = degree,
                                                                     .plaintext_modulus = plaintext_modulus,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 2,
                                                                     .moduli = { 18014398509309953ULL, 576460752303439873ULL } };

    static const struct cche_encrypt_params encrypt_params_3_bgv = { .he_scheme = CCHE_SCHEME_BGV,
                                                                     .poly_modulus_degree = degree,
                                                                     .plaintext_modulus = plaintext_modulus,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 3,
                                                                     .moduli = {
                                                                         536903681ULL, 68719403009ULL, 576460752303439873ULL } };

    static const struct cche_encrypt_params encrypt_params_4_bgv = {
        .he_scheme = CCHE_SCHEME_BGV,
        .poly_modulus_degree = degree,
        .plaintext_modulus = plaintext_modulus,
        .nskip_lsbs = { 0, 0 },
        .nmoduli = 4,
        .moduli = { 536903681ULL, 68719403009ULL, 1073692673ULL, 576460752303439873ULL }
    };

    static const struct cche_encrypt_params encrypt_params_5_bgv = {
        .he_scheme = CCHE_SCHEME_BGV,
        .poly_modulus_degree = degree,
        .plaintext_modulus = plaintext_modulus,
        .nskip_lsbs = { 0, 0 },
        .nmoduli = 5,
        .moduli = { 536903681ULL, 68719403009ULL, 1073692673ULL, 137438822401ULL, 576460752303439873ULL }
    };

    switch (he_scheme) {
    case CCHE_SCHEME_BFV: {
        switch (nmoduli) {
        case 1:
            return &encrypt_params_1_bfv;
        case 2:
            return &encrypt_params_2_bfv;
        case 3:
            return &encrypt_params_3_bfv;
        case 4:
            return &encrypt_params_4_bfv;
        case 5:
            return &encrypt_params_5_bfv;
        }
    }
    case CCHE_SCHEME_BGV: {
        switch (nmoduli) {
        case 1:
            return &encrypt_params_1_bgv;
        case 2:
            return &encrypt_params_2_bgv;
        case 3:
            return &encrypt_params_3_bgv;
        case 4:
            return &encrypt_params_4_bgv;
        case 5:
            return &encrypt_params_5_bgv;
        }
    }
    case CCHE_SCHEME_UNSPECIFIED: {
        cc_abort("Invalid he scheme");
    }
    }
}

static void verify_poly_ctx(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t nmoduli, const ccrns_int *cc_counted_by(nmoduli) moduli)
{
    is(ctx->dims.nmoduli, nmoduli, "verify_poly_ctx nmoduli");
    for (uint32_t i = 0; i < nmoduli; ++i) {
        cczp_const_t cczp_modulus = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx, i);
        ccrns_int modulus = ccpolyzp_po2cyc_modulus_to_rns_int(cczp_modulus);
        is(modulus, moduli[i], "verify_poly_ctx moduli");
    }
}

static void test_cche_encrypt_params_eq(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct cche_encrypt_params encrypt_params_1a = { .he_scheme = CCHE_SCHEME_BFV,
                                                                  .poly_modulus_degree = 1024,
                                                                  .plaintext_modulus = 11,
                                                                  .nskip_lsbs = { 1, 1 },
                                                                  .nmoduli = 2,
                                                                  .moduli = { 536903681ULL, 576460752303439873ULL } };
    // Same parameters
    {
        struct cche_encrypt_params *encrypt_params_1b =
            (struct cche_encrypt_params *)CC_ALLOC_WS(ws, cche_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        cche_encrypt_params_copy(encrypt_params_1b, &encrypt_params_1a);
        is(cche_encrypt_params_eq(&encrypt_params_1a, &encrypt_params_1a), true, "cche_encrypt_params_eq same pointer");
        is(cche_encrypt_params_eq(&encrypt_params_1a, encrypt_params_1b), true, "cche_encrypt_params_eq same object");
    }
    // Different he_scheme
    {
        struct cche_encrypt_params *encrypt_params_1b =
            (struct cche_encrypt_params *)CC_ALLOC_WS(ws, cche_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        cche_encrypt_params_copy(encrypt_params_1b, &encrypt_params_1a);
        encrypt_params_1b->he_scheme = CCHE_SCHEME_BGV;
        is(cche_encrypt_params_eq(&encrypt_params_1a, encrypt_params_1b), false, "cche_encrypt_params_eq different he_scheme");
    }
    // Different moduli
    {
        struct cche_encrypt_params *encrypt_params_2 =
            (struct cche_encrypt_params *)CC_ALLOC_WS(ws, cche_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        cche_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->moduli[1] = 68719403009ULL;
        is(cche_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2),
           false,
           "cche_encrypt_params_eq ciphertext moduli not eq");
    }
    // Different plaintext modulus
    {
        struct cche_encrypt_params *encrypt_params_2 =
            (struct cche_encrypt_params *)CC_ALLOC_WS(ws, cche_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        cche_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->plaintext_modulus = 13;
        is(cche_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2),
           false,
           "cche_encrypt_params_eq plaintext modulus not eq");
    }
    // Different polynomial modulus degree
    {
        struct cche_encrypt_params *encrypt_params_2 =
            (struct cche_encrypt_params *)CC_ALLOC_WS(ws, cche_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        cche_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->poly_modulus_degree = 2048;
        is(cche_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2), false, "cche_encrypt_params_eq degree not eq");
    }
    // Different nskip_lsbs
    {
        struct cche_encrypt_params *encrypt_params_2 =
            (struct cche_encrypt_params *)CC_ALLOC_WS(ws, cche_encrypt_params_nof_n(encrypt_params_1a.nmoduli));
        cche_encrypt_params_copy(encrypt_params_2, &encrypt_params_1a);
        encrypt_params_2->nskip_lsbs[0] = encrypt_params_1a.nskip_lsbs[0] + 1;
        is(cche_encrypt_params_eq(&encrypt_params_1a, encrypt_params_2), false, "cche_encrypt_params_eq nskip_lsbs not eq");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_param_ctx_init(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // one ciphertext modulus
    {
        static struct cche_encrypt_params encrypt_params = {
            .poly_modulus_degree = 4096, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
        };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (1 modulus)");
        static const ccrns_int plaintext_moduli[] = { 40961 };
        verify_poly_ctx(cche_param_ctx_plaintext_context(param_ctx), 1, plaintext_moduli);
        static const ccrns_int key_moduli[] = { 65537 };
        verify_poly_ctx(cche_param_ctx_encrypt_key_context(param_ctx), 1, key_moduli);
        static const ccrns_int coefficient_moduli[] = { 65537 };
        verify_poly_ctx(cche_param_ctx_ciphertext_context(param_ctx), 1, coefficient_moduli);
        is(cche_param_ctx_encrypt_key_context(param_ctx)->next, NULL, "BFV/BGV param ctx init (1 modulus), key_ctx->next = NULL");
        is(cche_param_ctx_encrypt_key_context(param_ctx),
           cche_param_ctx_ciphertext_context(param_ctx),
           "BFV/BGV param ctx init (1 moduli), key_ctx = ciphertext_ctx");
    }

    // three ciphertext moduli
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                             .plaintext_modulus = 40961,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 65537, 114689, 147457, 163841 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");
        static const ccrns_int plaintext_moduli[] = { 40961 };
        verify_poly_ctx(cche_param_ctx_plaintext_context(param_ctx), 1, plaintext_moduli);
        static const ccrns_int key_moduli[] = { 65537, 114689, 147457, 163841 };
        verify_poly_ctx(cche_param_ctx_encrypt_key_context(param_ctx), 4, key_moduli);
        static const ccrns_int coefficient_moduli[] = { 65537, 114689, 147457 };
        verify_poly_ctx(cche_param_ctx_ciphertext_context(param_ctx), 3, coefficient_moduli);
        is(cche_param_ctx_encrypt_key_context(param_ctx)->next,
           cche_param_ctx_ciphertext_context(param_ctx),
           "BFV/BGV param ctx init (4 moduli), key_ctx->next = ciphertext_ctx");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_param_ctx_init_errors(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    CC_DECL_BP_WS(ws, bp);
    // ok
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                             .plaintext_modulus = 18433,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "test_cche_param_ctx_init_errors ok");
        CC_FREE_BP_WS(ws, bp);
    }
    // unspecified HE scheme
    {
        static struct cche_encrypt_params encrypt_params = { .he_scheme = CCHE_SCHEME_UNSPECIFIED,
                                                             .poly_modulus_degree = 1023,
                                                             .plaintext_modulus = 18433,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "Unknown HE scheme");
        CC_FREE_BP_WS(ws, bp);
    }
    // invalid HE scheme
    {
        static struct cche_encrypt_params encrypt_params = { .he_scheme = CCHE_SCHEMES_COUNT + 1,
                                                             .poly_modulus_degree = 1023,
                                                             .plaintext_modulus = 18433,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "Invalid HE scheme");
        CC_FREE_BP_WS(ws, bp);
    }
    // polynomial degree is not power of two
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 1023,
                                                             .plaintext_modulus = 18433,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "polynomial degree is not power of two");
        CC_FREE_BP_WS(ws, bp);
    }
    // coefficient moduli contains repeated element
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                             .plaintext_modulus = 18433,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 5,
                                                             .moduli = { 40961, 59393, 61441, 65537, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "polynomial degree is not power of two");
        CC_FREE_BP_WS(ws, bp);
    }
    // plaintext modulus is the same as one of the coefficient moduli
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                             .plaintext_modulus = 40961,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
           CCERR_PARAMETER,
           "plaintext modulus is the same as one of the coefficient moduli");
        CC_FREE_BP_WS(ws, bp);
    }
    // plaintext modulus is not prime
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                             .plaintext_modulus = 1234,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "plaintext modulus is not prime");
        CC_FREE_BP_WS(ws, bp);
    }
    // one of the coefficient modulus is not NTT-friendly
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                             .plaintext_modulus = 18433,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 5,
                                                             .moduli = { 40867, 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
           CCERR_PARAMETER,
           "one of the coefficient modulus is not NTT-friendly");
        CC_FREE_BP_WS(ws, bp);
    }
    // plaintext modulus is larger than one of the coefficient modulus
    {
        static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 1024,
                                                             .plaintext_modulus = 133121,
                                                             .nskip_lsbs = { 0, 0 },
                                                             .nmoduli = 4,
                                                             .moduli = { 40961, 59393, 61441, 65537 } };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
           CCERR_PARAMETER,
           "plaintext modulus is larger than one of the coefficient modulus");
        CC_FREE_BP_WS(ws, bp);
    }
    // nskip_bits too large
    {
        static struct cche_encrypt_params encrypt_params = {
            .poly_modulus_degree = 1024,
            .plaintext_modulus = 18433,
            .nskip_lsbs = { 100, 0 },
            .nmoduli = 4,
            .moduli = { 40961, 59393, 61441, 65537 },
        };
        encrypt_params.he_scheme = he_scheme;
        cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
        is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_PARAMETER, "nskip_lsbs too large");
        CC_FREE_BP_WS(ws, bp);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_param_ctx_eq(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct cche_encrypt_params encrypt_params_1 = { .he_scheme = CCHE_SCHEME_BFV,
                                                                 .poly_modulus_degree = 1024,
                                                                 .plaintext_modulus = 11,
                                                                 .nskip_lsbs = { 0, 0 },
                                                                 .nmoduli = 2,
                                                                 .moduli = { 536903681ULL, 576460752303439873ULL } };
    cche_param_ctx_t param_ctx_1 = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_1);
    is(cche_param_ctx_init_ws(ws, param_ctx_1, &encrypt_params_1), CCERR_OK, "BFV/BGV param ctx init");

    // Same context
    {
        cche_param_ctx_t param_ctx_2 = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_1);
        is(cche_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_1), CCERR_OK, "BFV/BGV param ctx init");
        is(cche_param_ctx_eq(param_ctx_1, param_ctx_1), true, "cche_param_ctx_eq same pointer");
        is(cche_param_ctx_eq(param_ctx_1, param_ctx_2), true, "cche_param_ctx_eq same object");
    }
    // Different HE scheme
    {
        static const struct cche_encrypt_params encrypt_params_2 = { .he_scheme = CCHE_SCHEME_BGV,
                                                                     .poly_modulus_degree = 1024,
                                                                     .plaintext_modulus = 11,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 2,
                                                                     .moduli = { 536903681ULL, 576460752303439873ULL } };
        cche_param_ctx_t param_ctx_2 = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_2);
        is(cche_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_2), CCERR_OK, "BFV/BGV param ctx init");
        is(cche_param_ctx_eq(param_ctx_1, param_ctx_2), false, "cche_param_ctx_eq different HE scheme");
    }
    // Different moduli
    {
        static const struct cche_encrypt_params encrypt_params_2 = { .he_scheme = CCHE_SCHEME_BFV,
                                                                     .poly_modulus_degree = 1024,
                                                                     .plaintext_modulus = 11,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 2,
                                                                     .moduli = { 536903681ULL, 68719403009ULL } };
        cche_param_ctx_t param_ctx_2 = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_2);
        is(cche_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_2), CCERR_OK, "BFV/BGV param ctx init");
        is(cche_param_ctx_eq(param_ctx_1, param_ctx_2), false, "cche_param_ctx_eq different ciphertext moduli");
    }
    // Different plaintext modulus
    {
        static const struct cche_encrypt_params encrypt_params_2 = { .he_scheme = CCHE_SCHEME_BFV,
                                                                     .poly_modulus_degree = 1024,
                                                                     .plaintext_modulus = 13,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 2,
                                                                     .moduli = { 536903681ULL, 68719403009ULL } };
        cche_param_ctx_t param_ctx_2 = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_2);
        is(cche_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_2), CCERR_OK, "BFV/BGV param ctx init");
        is(cche_param_ctx_eq(param_ctx_1, param_ctx_2), false, "cche_param_ctx_eq different plaintext modulus");
    }
    // Different poly modulus degree
    {
        static const struct cche_encrypt_params encrypt_params_2 = { .he_scheme = CCHE_SCHEME_BFV,
                                                                     .poly_modulus_degree = 2048,
                                                                     .plaintext_modulus = 13,
                                                                     .nskip_lsbs = { 0, 0 },
                                                                     .nmoduli = 2,
                                                                     .moduli = { 536903681ULL, 68719403009ULL } };
        cche_param_ctx_t param_ctx_2 = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_2);
        is(cche_param_ctx_init_ws(ws, param_ctx_2, &encrypt_params_2), CCERR_OK, "BFV/BGV param ctx init");
        is(cche_param_ctx_eq(param_ctx_1, param_ctx_2), false, "cche_param_ctx_eq different plaintext modulus");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encode_decode_errors(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                         .plaintext_modulus = 40961,
                                                         .nskip_lsbs = { 0, 0 },
                                                         .nmoduli = 4,
                                                         .moduli = { 65537, 114689, 147457, 163841 } };
    encrypt_params.he_scheme = he_scheme;
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (3 moduli)");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);

    // too many values - encode poly uint64
    {
        uint64_t values[4097] = { 0 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_poly_uint64(ptext, param_ctx, 4097, values),
           CCERR_PARAMETER,
           "test_cche_encode_poly_uint64_errors too many values");
    }
    // too many values - encode uint64
    {
        uint64_t values[4097] = { 0 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_uint64(ptext, param_ctx, 4097, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_uint64_errors too many values");
    }
    // too many values - encode int64
    {
        int64_t values[4097] = { 0 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_int64(ptext, param_ctx, 4097, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_int64_errors too many values");
    }
    // too many values - decode poly uint64
    {
        uint64_t values[4096] = { 0 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_poly_uint64(ptext, param_ctx, 4096, values), CCERR_OK, "cche_encode_poly_uint64 != CCERR_OK");
        is(cche_decode_poly_uint64(4097, values, ptext), CCERR_PARAMETER, "test_cche_decode_poly_uint64_errors too many values");
    }
    // too many values - decode uint64
    {
        uint64_t values[4096] = { 0 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_uint64(ptext, param_ctx, 4096, values), CCERR_OK, "cche_encode_simd_uint64 != CCERR_OK");
        is(cche_decode_simd_uint64_ws(ws, param_ctx, 4097, values, ptext),
           CCERR_PARAMETER,
           "test_cche_decode_uint64_errors too many values");
    }
    // too many values - decode int64
    {
        int64_t values[4096] = { 0 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_int64(ptext, param_ctx, 4096, values), CCERR_OK, "cche_encode_simd_int64 != CCERR_OK");
        is(cche_decode_simd_int64_ws(ws, param_ctx, 4097, values, ptext),
           CCERR_PARAMETER,
           "test_cche_decode_int64_errors too many values");
    }
    // encode single too large value - uint64 poly
    {
        uint64_t values[] = { 40961 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_poly_uint64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_cche_encode_poly_uint64_errors single too large value");
    }
    // encode single too large value - uint64
    {
        uint64_t values[] = { 40961 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_uint64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_uint64_errors single too large value");
    }
    // encode multiple too large values - uint64 poly
    {
        uint64_t values[] = { 0, 40962, 40961 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_poly_uint64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_uint64_poly_errors multiple too large value");
    }
    // encode multiple too large values - uint64
    {
        uint64_t values[] = { 0, 40962, 40961 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_uint64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_uint64_errors multiple too large value");
    }
    // encode single too large values - int64 exceeds positive bound
    {
        int64_t values[] = { 20481 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_int64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_int64_errors single too large value postive ");
    }
    // encode multiple too large values - int64 exceeds positive bound
    {
        int64_t values[] = { 0, 20481, 20482 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_int64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_int64_errors multiple too large values positive");
    }
    // encode single too large value - int64 exceeds negative bound
    {
        int64_t values[] = { -20481 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_int64(ptext, param_ctx, 1, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_int64_errors single too large value negative ");
    }
    // encode multiple too large values - int64 exceeds negative bound
    {
        int64_t values[] = { 0, 0, -20481 };
        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_int64(ptext, param_ctx, 3, values),
           CCERR_PARAMETER,
           "test_cche_encode_simd_int64_errors multiple too large values negative ");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encode_decode_poly_uint64(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static struct cche_encrypt_params encrypt_params = {
        .poly_modulus_degree = 4096, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
    };
    encrypt_params.he_scheme = he_scheme;
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "cche_param_ctx_init_ws != CCERR_OK");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);

    // N values roundtrip
    {
        uint64_t values[4096] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_poly_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "cche_encode_poly_uint64 != CCERR_OK");
        is(cche_plaintext_modulus(ptext), encrypt_params.plaintext_modulus, "cche_plaintext_modulus");
        bool encode_values_match = true;
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccpolyzp_po2cyc_coeff_const_t poly = cche_plaintext_polynomial_const(ptext);
            ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, 0, i);
            encode_values_match &= (coeff == values[i]);
        }
        is(encode_values_match, true, "cche_encode_poly_uint64 N values mismatch");

        uint64_t values_decoded[4096] = { 0 };
        is(cche_decode_poly_uint64(4096, values_decoded, ptext), CCERR_OK, "cche_decode_poly_uint64 != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_cche_encode_decode_simd_uint64 N roundtrip");
    }
    // < N values roundtrip
    {
        uint64_t values[123] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_poly_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "cche_encode_poly_uint64 != CCERR_OK");
        is(cche_plaintext_modulus(ptext), encrypt_params.plaintext_modulus, "cche_plaintext_modulus");
        bool encode_values_match = true;
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccpolyzp_po2cyc_coeff_const_t poly = cche_plaintext_polynomial_const(ptext);
            ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, 0, i);
            encode_values_match &= (coeff == values[i]);
        }
        for (uint32_t i = CC_ARRAY_LEN(values); i < encrypt_params.poly_modulus_degree; ++i) {
            ccpolyzp_po2cyc_coeff_const_t poly = cche_plaintext_polynomial_const(ptext);
            ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, 0, i);
            encode_values_match &= (coeff == 0);
        }
        is(encode_values_match, true, "cche_encode_poly_uint64 <N values mismatch");

        uint64_t values_decoded[123] = { 0 };
        is(cche_decode_poly_uint64(123, values_decoded, ptext), CCERR_OK, "cche_decode_poly_uint64 != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_cche_encode_decode_poly_uint64 <N roundtrip");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encode_decode_simd_uint64(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static struct cche_encrypt_params encrypt_params = {
        .poly_modulus_degree = 4096, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
    };
    encrypt_params.he_scheme = he_scheme;
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "cche_param_ctx_init_ws != CCERR_OK");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);

    // N values roundtrip
    {
        uint64_t values[4096] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "cche_encode_simd_uint64 != CCERR_OK");
        is(cche_plaintext_modulus(ptext), encrypt_params.plaintext_modulus, "cche_plaintext_modulus");

        uint64_t values_decoded[4096] = { 0 };
        is(cche_decode_simd_uint64_ws(ws, param_ctx, 4096, values_decoded, ptext),
           CCERR_OK,
           "cche_decode_simd_uint64_ws != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_cche_encode_decode_simd_uint64 N roundtrip");
    }
    // < N values roundtrip
    {
        uint64_t values[123] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            ccrng_uniform(global_test_rng, 40961, &values[i]);
        }
        values[0] = 40960;

        cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
        is(cche_encode_simd_uint64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "cche_encode_simd_uint64 != CCERR_OK");
        is(cche_plaintext_modulus(ptext), encrypt_params.plaintext_modulus, "cche_plaintext_modulus");

        uint64_t values_decoded[123] = { 0 };
        is(cche_decode_simd_uint64_ws(ws, param_ctx, 123, values_decoded, ptext),
           CCERR_OK,
           "cche_decode_simd_uint64_ws != CCERR_OK");

        is(array_eq_uint64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_cche_encode_decode_simd_uint64 <N roundtrip");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encode_decode_simd_int64(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static struct cche_encrypt_params encrypt_params = {
        .poly_modulus_degree = 128, .plaintext_modulus = 40961, .nskip_lsbs = { 0, 0 }, .nmoduli = 1, .moduli = { 65537 }
    };
    encrypt_params.he_scheme = he_scheme;
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (3 moduli)");
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);

    // N values roundtrip
    {
        int64_t values[128] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            values[i] = uniform_int64(40961);
        }
        values[0] = -20480;
        values[1] = 20479;

        is(cche_encode_simd_int64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "cche_encode_simd_int64 != CCERR_OK");
        is(cche_plaintext_modulus(ptext), encrypt_params.plaintext_modulus, "cche_plaintext_modulus");

        int64_t values_decoded[128] = { 0 };
        is(cche_decode_simd_int64_ws(ws, param_ctx, 128, values_decoded, ptext),
           CCERR_OK,
           "cche_decode_simd_int64_ws != CCERR_OK");

        is(array_eq_int64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_cche_encode_decode_simd_int64 N roundtrip");
    }
    // < N values roundtrip
    {
        int64_t values[123] = { 0 };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(values); ++i) {
            values[i] = uniform_int64(40961);
        }
        values[0] = -20480;
        values[1] = 20479;
        is(cche_encode_simd_int64(ptext, param_ctx, CC_ARRAY_LEN(values), values),
           CCERR_OK,
           "cche_encode_simd_int64 != CCERR_OK");
        is(cche_plaintext_modulus(ptext), encrypt_params.plaintext_modulus, "cche_plaintext_modulus");

        int64_t values_decoded[123] = { 0 };
        is(cche_decode_simd_int64_ws(ws, param_ctx, 123, values_decoded, ptext),
           CCERR_OK,
           "cche_decode_simd_int64_ws != CCERR_OK");

        is(array_eq_int64(CC_ARRAY_LEN(values_decoded), values_decoded, values),
           true,
           "test_cche_encode_decode_simd_int64 <N roundtrip");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encrypt_error(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                         .plaintext_modulus = 40961,
                                                         .nskip_lsbs = { 0, 0 },
                                                         .nmoduli = 4,
                                                         .moduli = { 65537, 114689, 147457, 163841 } };
    encrypt_params.he_scheme = he_scheme;
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init");
    uint32_t nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    static const struct cche_encrypt_params encrypt_params_diff = { .he_scheme = CCHE_SCHEME_BFV,
                                                                    .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };
    cche_param_ctx_t param_ctx_diff = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_diff);
    is(cche_param_ctx_init_ws(ws, param_ctx_diff, &encrypt_params_diff), CCERR_OK, "BFV/BGV param ctx init");

    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    cche_secret_key_t secret_key_diff = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx_diff);
    is(cche_secret_key_generate_ws(ws, secret_key_diff, param_ctx_diff, global_test_rng), CCERR_OK, "Secret key generation");

    // ok
    {
        int rv = cche_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "BFV/BGV encrypt");
    }
    // secret key / parameter context mismatch
    {
        int rv = cche_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key_diff, nmoduli, NULL, global_test_rng);
        is(rv, CCERR_PARAMETER, "BFV/BGV encrypt different contexts");
    }
    // nmoduli too small
    {
        int rv = cche_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, 0, NULL, global_test_rng);
        is(rv, CCERR_PARAMETER, "BFV/BGV encrypt 0 moduli");
    }
    // nmoduli too large
    {
        int rv = cche_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli + 2, NULL, global_test_rng);
        is(rv, CCERR_PARAMETER, "BFV/BGV encrypt too many moduli");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_cche_decrypt_error(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    static struct cche_encrypt_params encrypt_params = { .poly_modulus_degree = 4096,
                                                         .plaintext_modulus = 40961,
                                                         .nskip_lsbs = { 0, 0 },
                                                         .nmoduli = 4,
                                                         .moduli = { 65537, 114689, 147457, 163841 } };
    encrypt_params.he_scheme = he_scheme;
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, &encrypt_params), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");
    uint32_t nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    static const struct cche_encrypt_params encrypt_params_diff = { .he_scheme = CCHE_SCHEME_BFV,
                                                                    .poly_modulus_degree = 1024,
                                                                    .plaintext_modulus = 40961,
                                                                    .nskip_lsbs = { 0, 0 },
                                                                    .nmoduli = 4,
                                                                    .moduli = { 65537, 114689, 147457, 163841 } };
    cche_param_ctx_t param_ctx_diff = CCHE_PARAM_CTX_ALLOC_WS(ws, &encrypt_params_diff);
    is(cche_param_ctx_init_ws(ws, param_ctx_diff, &encrypt_params_diff), CCERR_OK, "BFV/BGV param ctx init (4 moduli)");
    cche_secret_key_t secret_key_diff = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx_diff);
    is(cche_secret_key_generate_ws(ws, secret_key_diff, param_ctx_diff, global_test_rng), CCERR_OK, "Secret key generation");

    int rv = cche_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV/BGV encrypt");

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    is(cche_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key), CCERR_OK, "BFV/BGV decrypt");

    // secret key wrong parameter context
    {
        is(cche_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key_diff),
           CCERR_PARAMETER,
           "BFV/BGV decrypt secret key wrong context");
    }
    // ciphertext wrong parameter context
    {
        is(cche_decrypt_ws(ws, ptext, param_ctx_diff, ctext, secret_key_diff),
           CCERR_PARAMETER,
           "BFV/BGV decrypt ctext wrong context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void
test_cche_encrypt_decrypt_helper(cc_ws_t ws, cche_encrypt_params_const_t encrypt_params, bool all_zeros, bool sk_from_seed)
{
    CC_DECL_BP_WS(ws, bp);
    uint32_t degree = encrypt_params->poly_modulus_degree;
    ccrns_int plaintext_modulus = encrypt_params->plaintext_modulus;
    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params),
       CCERR_OK,
       "BFV/BGV param ctx init (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    uint32_t nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    if (!sk_from_seed) {
        is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
           CCERR_OK,
           "Secret key generation (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
    } else {
        struct ccpolyzp_po2cyc_block_rng_seed seed = { .data = { 1 } };
        is(cche_secret_key_generate_from_seed_ws(ws, secret_key, param_ctx, (cche_rng_seed_t)&seed),
           CCERR_OK,
           "Secret key generation with seed (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
    }

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    uint64_t values[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        if (all_zeros) {
            values[i] = 0;
        } else {
            ccrng_uniform(global_test_rng, plaintext_modulus, values + i);
        }
    }
    is(cche_encode_simd_uint64(ptext, param_ctx, degree, values),
       CCERR_OK,
       "cche_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    int rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV/BGV encrypt symmetric no seed (%" PRIu32 " moduli)", encrypt_params->nmoduli);
    is(ctext->correction_factor, 1, "BFV/BGV encryption -> correction_factor != 1");

    // Choose random correction factor
    ccrns_int scaling_factor;
    ccrng_uniform(global_test_rng, plaintext_modulus, &scaling_factor);
    ctext->correction_factor = scaling_factor;
    rv = cche_param_ctx_plaintext_modulus_inverse_ws(ws, &scaling_factor, param_ctx, ctext->correction_factor);
    is(rv, CCERR_OK, "BFV/BGV encrypt symmetric cche_param_ctx_plaintext_modulus_inverse_ws != CCERR_OK");
    ccpolyzp_po2cyc_ctx_const_t ctx = cche_param_ctx_plaintext_context(param_ctx);
    ccrns_modulus_const_t t = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx, 0);
    for (uint32_t i = 0; i < degree; ++i) {
        values[i] = ccpolyzp_po2cyc_scalar_mul_mod(values[i], scaling_factor, t);
    }

    rv = cche_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
    is(rv, CCERR_OK, "BFV/BGV decrypt symmetric no seed (%" PRIu32 " moduli)", encrypt_params->nmoduli);
    uint64_t values_decoded[degree];
    is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext),
       CCERR_OK,
       "cche_decode_simd_uint64_ws != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    is(array_eq_uint64(degree, values_decoded, values),
       true,
       "BFV/BGV encrypt decrypt (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    CC_FREE_BP_WS(ws, bp);
}

static void test_cche_encrypt_decrypt_zero_seed(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    bool all_zeros = true;
    bool sk_from_seed = true;
    for (uint32_t nmoduli = 1; nmoduli <= 5; ++nmoduli) {
        test_cche_encrypt_decrypt_helper(ws, get_test_encrypt_params(he_scheme, nmoduli), all_zeros, sk_from_seed);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encrypt_decrypt_zero(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    bool all_zeros = true;
    bool sk_from_seed = false;
    for (uint32_t nmoduli = 1; nmoduli <= 5; ++nmoduli) {
        test_cche_encrypt_decrypt_helper(ws, get_test_encrypt_params(he_scheme, nmoduli), all_zeros, sk_from_seed);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encrypt_decrypt_nonzero_seed(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    bool all_zeros = false;
    bool sk_from_seed = true;
    for (uint32_t nmoduli = 1; nmoduli <= 5; ++nmoduli) {
        test_cche_encrypt_decrypt_helper(ws, get_test_encrypt_params(he_scheme, nmoduli), all_zeros, sk_from_seed);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_cche_encrypt_decrypt_nonzero(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    bool all_zeros = false;
    bool sk_from_seed = false;
    for (uint32_t nmoduli = 1; nmoduli <= 5; ++nmoduli) {
        test_cche_encrypt_decrypt_helper(ws, get_test_encrypt_params(he_scheme, nmoduli), all_zeros, sk_from_seed);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_cche_cipher_plain_add_helper(cc_ws_t ws, cche_encrypt_params_const_t encrypt_params)
{
    CC_DECL_BP_WS(ws, bp);
    uint32_t degree = encrypt_params->poly_modulus_degree;
    ccrns_int plaintext_modulus = encrypt_params->plaintext_modulus;

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params),
       CCERR_OK,
       "BFV/BGV param ctx init (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    uint32_t nmoduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
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

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext1 = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    cche_plaintext_t ptext2 = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    is(cche_encode_simd_uint64(ptext1, param_ctx, degree, values1),
       CCERR_OK,
       "cche_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);
    is(cche_encode_simd_uint64(ptext2, param_ctx, degree, values2),
       CCERR_OK,
       "cche_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    int rv = cche_encrypt_symmetric_ws(ws, ctext, ptext1, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "cipher_plain_add: encrypt (%" PRIu32 " moduli)", encrypt_params->nmoduli);

    // out-of-place
    {
        cche_ciphertext_coeff_t ctext_sum =
            CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
        ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);
        cche_ciphertext_coeff_init(ctext_sum, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);
        rv = cche_ciphertext_plaintext_add_ws(ws, ctext_sum, ctext, ptext2);
        is(rv, CCERR_OK, "cipher_plain_add: cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        rv = cche_decrypt_ws(ws, ptext1, param_ctx, ctext_sum, secret_key);
        is(rv, CCERR_OK, "cipher_plain_add: decrypt (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        uint64_t values_decoded[degree];
        is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext1),
           CCERR_OK,
           "cche_decode_simd_uint64_ws != CCERR_OK (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
        is(array_eq_uint64(degree, values_decoded, sum), true, "cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
    }
    // in-place
    {
        rv = cche_ciphertext_plaintext_add_ws(ws, ctext, ctext, ptext2);
        is(rv, CCERR_OK, "cipher_plain_add: cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        rv = cche_decrypt_ws(ws, ptext1, param_ctx, ctext, secret_key);
        is(rv, CCERR_OK, "cipher_plain_add: decrypt (%" PRIu32 " moduli)", encrypt_params->nmoduli);
        uint64_t values_decoded[degree];
        is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext1),
           CCERR_OK,
           "cche_decode_simd_uint64_ws != CCERR_OK (%" PRIu32 " moduli)",
           encrypt_params->nmoduli);
        is(array_eq_uint64(degree, values_decoded, sum), true, "cipher_plain_add (%" PRIu32 " moduli)", encrypt_params->nmoduli);
    }
    CC_FREE_BP_WS(ws, bp);
}

static void test_cche_cipher_plain_add(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    for (uint32_t nmoduli = 1; nmoduli <= 5; ++nmoduli) {
        test_cche_cipher_plain_add_helper(ws, get_test_encrypt_params(he_scheme, nmoduli));
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_cche_mod_switch_helper(cc_ws_t ws, cche_encrypt_params_const_t encrypt_params)
{
    CC_DECL_BP_WS(ws, bp);
    uint32_t degree = encrypt_params->poly_modulus_degree;
    ccrns_int plaintext_modulus = encrypt_params->plaintext_modulus;

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params),
       CCERR_OK,
       "BFV/BGV param ctx init (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng), CCERR_OK, "Secret key generation");

    uint64_t values[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        ccrng_uniform(global_test_rng, plaintext_modulus, values + i);
    }
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_plaintext_t ptext = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    is(cche_encode_simd_uint64(ptext, param_ctx, degree, values),
       CCERR_OK,
       "cche_encode_simd_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       encrypt_params->nmoduli);

    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    uint32_t nctext_moduli = cche_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    // mod switch down
    {
        int rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nctext_moduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "mod_switch: encrypt");
        for (uint32_t nmoduli = nctext_moduli; nmoduli > 1; --nmoduli) {
            rv = cche_ciphertext_mod_switch_down_ws(ws, ctext);
            is(rv, CCERR_OK, "mod_switch: mod_switch_down");
            is(cche_ciphertext_coeff_ctx(ctext)->dims.nmoduli, nmoduli - 1, "mod_switch: (%" PRIu32 " moduli)", nmoduli);
            rv = cche_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
            is(rv, CCERR_OK, "mod_switch: decrypt");
            uint64_t values_decoded[degree];
            is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext),
               CCERR_OK,
               "cche_decode_simd_uint64_ws != CCERR_OK");
            is(array_eq_uint64(degree, values_decoded, values), true, "mod_switch: (%" PRIu32 " moduli)", nmoduli);
        }
        // Mod-switch with single ciphertext yields error
        rv = cche_ciphertext_mod_switch_down_ws(ws, ctext);
        is(rv, CCERR_PARAMETER, "mod_switch: mod_switch_down with 1 modulus");
    }
    // mod switch down to single
    {
        int rv = cche_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nctext_moduli, NULL, global_test_rng);
        is(rv, CCERR_OK, "mod_switch: encrypt");
        rv = cche_ciphertext_mod_switch_down_to_single_ws(ws, ctext);
        is(rv, CCERR_OK, "mod_switch: mod_switch_down_to_single");
        is(cche_ciphertext_coeff_ctx(ctext)->dims.nmoduli, 1, "mod_switch: nmoduli");
        rv = cche_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
        is(rv, CCERR_OK, "mod_switch: decrypt");
        uint64_t values_decoded[degree];
        is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext),
           CCERR_OK,
           "cche_decode_simd_uint64_ws != CCERR_OK");
        is(array_eq_uint64(degree, values_decoded, values), true, "mod_switch: (%" PRIu32 " moduli)", nctext_moduli);
    }
    CC_FREE_BP_WS(ws, bp);
}

static void test_cche_mod_switch(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    for (uint32_t nmoduli = 1; nmoduli <= 5; ++nmoduli) {
        test_cche_mod_switch_helper(ws, get_test_encrypt_params(he_scheme, nmoduli));
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_cche_cipher_plain_mul_helper(cc_ws_t ws, cche_encrypt_params_const_t encrypt_params)
{
    CC_DECL_BP_WS(ws, bp);

    uint32_t degree = encrypt_params->poly_modulus_degree;
    ccrns_int plaintext_modulus = encrypt_params->plaintext_modulus;
    uint32_t nmoduli = encrypt_params->nmoduli;

    cche_param_ctx_t param_ctx = CCHE_PARAM_CTX_ALLOC_WS(ws, encrypt_params);
    is(cche_param_ctx_init_ws(ws, param_ctx, encrypt_params), CCERR_OK, "cche_param_ctx_init_ws (%" PRIu32 " modulus)", nmoduli);

    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context(param_ctx);
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    cche_cipher_plain_ctx_const_t cipher_plain_ctx = cche_param_ctx_cipher_plain_ctx_const(param_ctx, cipher_ctx->dims.nmoduli);

    cche_ciphertext_coeff_t ctext =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_coeff_t ctext_prod =
        CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_eval_t ctext_eval =
        CCHE_CIPHERTEXT_EVAL_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_eval_t ctext_eval_prod =
        CCHE_CIPHERTEXT_EVAL_ALLOC_WS(ws, cche_param_ctx_ciphertext_context(param_ctx), cche_ciphertext_fresh_npolys());
    cche_ciphertext_coeff_init(ctext_prod, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);
    cche_ciphertext_eval_init(ctext_eval_prod, param_ctx, cche_ciphertext_fresh_npolys(), cipher_ctx);
    cche_secret_key_t secret_key = CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(cche_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
       CCERR_OK,
       "cche_secret_key_generate_ws (%" PRIu32 " modulus)",
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

    cche_plaintext_t ptext1 = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    cche_plaintext_t ptext2 = CCHE_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    cche_dcrt_plaintext_t dcrt_ptext2 = CCHE_DCRT_PLAINTEXT_ALLOC_WS(ws, cipher_ctx);
    is(cche_encode_simd_uint64(ptext1, param_ctx, degree, values1),
       CCERR_OK,
       "cche_encode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(cche_encode_simd_uint64(ptext2, param_ctx, degree, values2),
       CCERR_OK,
       "cche_encode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(cche_dcrt_plaintext_encode_ws(ws, dcrt_ptext2, ptext2, cipher_plain_ctx),
       CCERR_OK,
       "cche_dcrt_plaintext_encode_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);

    int rv = cche_encrypt_symmetric_ws(ws, ctext, ptext1, param_ctx, secret_key, cipher_ctx->dims.nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "cipher_plain_mul: encrypt (%" PRIu32 " modulus)", nmoduli);

    cche_ciphertext_coeff_copy((cche_ciphertext_coeff_t)ctext_eval, ctext);
    rv = cche_ciphertext_fwd_ntt((cche_ciphertext_coeff_t)ctext_eval);
    is(rv, CCERR_OK, "cipher_plain_mul: fwd_ntt (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_coeff plantext mul
    rv = cche_ciphertext_coeff_plaintext_mul_ws(ws, ctext_prod, ctext, ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: cche_ciphertext_coeff_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = cche_decrypt_ws(ws, ptext1, param_ctx, ctext_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt (%" PRIu32 " modulus)", nmoduli);
    is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext1),
       CCERR_OK,
       "cche_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_coeff dcrt-plaintext mul
    rv = cche_ciphertext_coeff_dcrt_plaintext_mul(ctext_prod, ctext, dcrt_ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: cche_ciphertext_dcrt_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = cche_decrypt_ws(ws, ptext1, param_ctx, ctext_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt_dcrt (%" PRIu32 " modulus)", nmoduli);
    is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext1),
       CCERR_OK,
       "cche_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_eval plantext mul
    rv = cche_ciphertext_eval_plaintext_mul_ws(ws, ctext_eval_prod, ctext_eval, ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: cche_ciphertext_eval_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = cche_ciphertext_inv_ntt(ctext_eval_prod);
    is(rv, CCERR_OK, "cipher_plain_mul: inv_ntt (%" PRIu32 " modulus)", nmoduli);
    rv = cche_decrypt_ws(ws, ptext1, param_ctx, (cche_ciphertext_coeff_const_t)ctext_eval_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt (%" PRIu32 " modulus)", nmoduli);
    is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext1),
       CCERR_OK,
       "cche_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    // test ciphertext_eval dcrt-plaintext mul
    rv = cche_ciphertext_eval_dcrt_plaintext_mul(ctext_eval_prod, ctext_eval, dcrt_ptext2);
    is(rv, CCERR_OK, "cipher_plain_mul: cche_ciphertext_dcrt_plaintext_mul_ws (%" PRIu32 " modulus)", nmoduli);
    rv = cche_ciphertext_inv_ntt(ctext_eval_prod);
    is(rv, CCERR_OK, "cipher_plain_mul: inv_ntt (%" PRIu32 " modulus)", nmoduli);
    rv = cche_decrypt_ws(ws, ptext1, param_ctx, (cche_ciphertext_coeff_const_t)ctext_eval_prod, secret_key);
    is(rv, CCERR_OK, "cipher_plain_mul: decrypt_dcrt (%" PRIu32 " modulus)", nmoduli);
    is(cche_decode_simd_uint64_ws(ws, param_ctx, degree, values_decoded, ptext1),
       CCERR_OK,
       "cche_decode_uint64_ws != CCERR_OK (%" PRIu32 " modulus)",
       nmoduli);
    is(array_eq_uint64(degree, values_decoded, prod), true, "cipher_plain_mul (%" PRIu32 " modulus)", nmoduli);

    CC_FREE_BP_WS(ws, bp);
}

static void test_cche_cipher_plain_mul(cche_scheme_t he_scheme)
{
    CC_DECL_WORKSPACE_TEST(ws);
    for (uint32_t nmoduli = 1; nmoduli <= 5; ++nmoduli) {
        test_cche_cipher_plain_mul_helper(ws, get_test_encrypt_params(he_scheme, nmoduli));
    }
    CC_FREE_WORKSPACE(ws);
}

int cche_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int ntests = 0;
    ntests += 7;                       // test_cche_encrypt_params_eq
    ntests += 12;                      // test_cche_param_ctx_eq
    ntests += 22 * CCHE_SCHEMES_COUNT; // test_cche_param_ctx_init
    ntests += 10 * CCHE_SCHEMES_COUNT; // test_cche_param_ctx_init_errors

    ntests += 18 * CCHE_SCHEMES_COUNT;   // test_cche_encode_decode_errors
    ntests += 11 * CCHE_SCHEMES_COUNT;   // test_cche_encode_decode_poly_uint64
    ntests += 9 * CCHE_SCHEMES_COUNT;    // test_cche_encode_decode_simd_uint64
    ntests += 9 * CCHE_SCHEMES_COUNT;    // test_cche_encode_decode_simd_int64
    ntests += 8 * CCHE_SCHEMES_COUNT;    // test_cche_encrypt_error
    ntests += 8 * CCHE_SCHEMES_COUNT;    // test_cche_decrypt_error
    ntests += 45 * CCHE_SCHEMES_COUNT;   // test_cche_encrypt_zero_seed
    ntests += 45 * CCHE_SCHEMES_COUNT;   // test_cche_encrypt_decrypt_zero_seed
    ntests += 45 * CCHE_SCHEMES_COUNT;   // test_cche_encrypt_decrypt_nonzero_seed
    ntests += 45 * CCHE_SCHEMES_COUNT;   // test_cche_encrypt_decrypt_nonzero
    ntests += 65 * CCHE_SCHEMES_COUNT;   // test_cche_cipher_plain_add
    ntests += 125 * CCHE_SCHEMES_COUNT;  // test_cche_cipher_plain_mul
    ntests += 85 * CCHE_SCHEMES_COUNT;   // test_cche_mod_switch
    ntests += 1922 * CCHE_SCHEMES_COUNT; // test_cche_galois
    ntests += 66 * CCHE_SCHEMES_COUNT;   // test_cche_relin
    ntests += 44 * CCHE_SCHEMES_COUNT;   // test_cche_compose_decompose
    ntests += 55;                        // test_cche_serialization
    ntests += ntests_cche_public();      // test_cche_public

    plan_tests(ntests);

    test_cche_encrypt_params_eq();
    test_cche_param_ctx_eq();
    for (uint32_t he_scheme = 1; he_scheme <= CCHE_SCHEMES_COUNT; ++he_scheme) {
        test_cche_param_ctx_init(he_scheme);
        test_cche_param_ctx_init_errors(he_scheme);

        // encoding / decoding
        test_cche_encode_decode_errors(he_scheme);
        test_cche_encode_decode_poly_uint64(he_scheme);
        test_cche_encode_decode_simd_uint64(he_scheme);
        test_cche_encode_decode_simd_int64(he_scheme);

        // encryption / decryption
        test_cche_encrypt_error(he_scheme);
        test_cche_decrypt_error(he_scheme);
        test_cche_encrypt_decrypt_zero_seed(he_scheme);
        test_cche_encrypt_decrypt_zero(he_scheme);
        test_cche_encrypt_decrypt_nonzero_seed(he_scheme);
        test_cche_encrypt_decrypt_nonzero(he_scheme);

        // operations
        test_cche_cipher_plain_add(he_scheme);
        test_cche_cipher_plain_mul(he_scheme);
        test_cche_mod_switch(he_scheme);
        test_cche_galois(he_scheme);
        test_cche_relin(he_scheme);

        // composition / decomposition
        test_cche_compose_decompose(he_scheme);
    }

    // serialization / deserialization
    test_cche_serialization();

    // public
    test_cche_public();

    return 0;
}
