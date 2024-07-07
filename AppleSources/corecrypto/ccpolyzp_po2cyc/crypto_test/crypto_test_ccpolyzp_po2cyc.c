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

#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ntt.h"
#include "ccpolyzp_po2cyc_scalar.h"
#include <corecrypto/ccrng.h>
#include "testmore.h"
#include "testccnBuffer.h"
#include "crypto_test_ccpolyzp_po2cyc.h"
#include "cc.h"

/// Returns a uniform random number in [0, max - 1].
ccrns_int rns_int_uniform(ccrns_int max)
{
    ccrns_int result;
    ccrng_uniform(global_test_rng, max, &result);
    return result;
}

CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_t ccpolyzp_po2cyc_ctx_init_helper(cc_ws_t ws,
                                                                     ccpolyzp_po2cyc_dims_const_t dims,
                                                                     const ccrns_int *moduli)
{
    ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, dims);
    is(ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, dims, moduli), CCERR_OK, "Error initializing chain context");
    return ccpolyzp_po2cyc_ctx_chain_context(ctx_chain, dims->nmoduli);
}

CC_NONNULL_ALL ccpolyzp_po2cyc_coeff_t ccpolyzp_po2cyc_coeff_init_helper(cc_ws_t ws,
                                                                         ccpolyzp_po2cyc_dims_const_t dims,
                                                                         const ccrns_int *moduli,
                                                                         const ccrns_int *coeffs)
{
    ccpolyzp_po2cyc_ctx_t ctx = ccpolyzp_po2cyc_ctx_init_helper(ws, dims, moduli);
    ccpolyzp_po2cyc_t poly = CCPOLYZP_PO2CYC_ALLOC_WS(ws, dims);
    is(ccpolyzp_po2cyc_init(poly, ctx, coeffs), CCERR_OK, "Error initializing poly");

    return (ccpolyzp_po2cyc_coeff_t)poly;
}

ccpolyzp_po2cyc_eval_t
ccpolyzp_po2cyc_eval_init_helper(cc_ws_t ws, ccpolyzp_po2cyc_dims_const_t dims, const ccrns_int *moduli, const ccrns_int *coeffs)
{
    return (ccpolyzp_po2cyc_eval_t)ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, coeffs);
}

ccpolyzp_po2cyc_coeff_t
ccpolyzp_po2cyc_coeff_init_zero_helper(cc_ws_t ws, ccpolyzp_po2cyc_dims_const_t dims, const ccrns_int *moduli)
{
    uint32_t ncoeffs = dims->nmoduli * dims->degree;
    ccrns_int zero_data[ncoeffs];
    cc_memset(zero_data, 0, ncoeffs * sizeof(ccrns_int));
    ccpolyzp_po2cyc_coeff_t data = ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, zero_data);
    return data;
}

ccpolyzp_po2cyc_eval_t
ccpolyzp_po2cyc_eval_init_zero_helper(cc_ws_t ws, ccpolyzp_po2cyc_dims_const_t dims, const ccrns_int *moduli)
{
    return (ccpolyzp_po2cyc_eval_t)ccpolyzp_po2cyc_coeff_init_zero_helper(ws, dims, moduli);
}

bool ccpolyzp_po2cyc_coeff_rns_in(ccpolyzp_po2cyc_coeff_const_t poly, ccrns_int *values, uint32_t nvalues)
{
    ccpolyzp_po2cyc_dims_const_t dims = &(poly)->context->dims;
    for (uint32_t rns_idx = 0; rns_idx < dims->nmoduli; ++rns_idx) {
        for (uint32_t coeff_idx = 0; coeff_idx < dims->degree; ++coeff_idx) {
            ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, rns_idx, coeff_idx);
            bool valid_coeff = false;
            for (uint32_t value_idx = 0; value_idx < nvalues; ++value_idx) {
                valid_coeff |= (coeff == values[value_idx]);
            }
            if (!valid_coeff) {
                return false;
            }
        }
    }
    return true;
}

bool ccpolyzp_po2cyc_has_zero_rns(ccpolyzp_po2cyc_const_t poly)
{
    ccpolyzp_po2cyc_dims_const_t dims = &((ccpolyzp_po2cyc_coeff_const_t)poly)->context->dims;
    bool any_zero = false;
    for (uint32_t rns_idx = 0; rns_idx < dims->nmoduli; ++rns_idx) {
        for (uint32_t coeff_idx = 0; coeff_idx < dims->degree; ++coeff_idx) {
            ccrns_int coeff = ccpolyzp_po2cyc_data_int(poly, rns_idx, coeff_idx);
            any_zero |= (coeff == 0);
        }
    }
    return any_zero;
}

float ccpolyzp_po2cyc_compute_variance(ccpolyzp_po2cyc_const_t poly)
{
    ccpolyzp_po2cyc_dims_const_t dims = &((ccpolyzp_po2cyc_coeff_const_t)poly)->context->dims;
    int64_t sum = 0;
    for (uint32_t rns_idx = 0; rns_idx < dims->nmoduli; ++rns_idx) {
        for (uint32_t coeff_idx = 0; coeff_idx < dims->degree; ++coeff_idx) {
            ccrns_int coeff = ccpolyzp_po2cyc_data_int(poly, rns_idx, coeff_idx);
            ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(((ccpolyzp_po2cyc_coeff_const_t)poly)->context, rns_idx);
            if (coeff > (modulus / 2)) {
                sum -= (int64_t)(modulus - coeff);
            } else {
                sum += coeff;
            }
        }
    }
    float average = (float)sum / (dims->degree * dims->nmoduli);
    float variance = 0;
    for (uint32_t rns_idx = 0; rns_idx < dims->nmoduli; ++rns_idx) {
        for (uint32_t coeff_idx = 0; coeff_idx < dims->degree; ++coeff_idx) {
            ccrns_int coeff = ccpolyzp_po2cyc_data_int(poly, rns_idx, coeff_idx);
            ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(((ccpolyzp_po2cyc_coeff_const_t)poly)->context, rns_idx);
            float deviation;
            if (coeff > (modulus / 2)) {
                deviation = average - (float)(modulus - coeff);
            } else {
                deviation = average - (float)coeff;
            }
            variance += deviation * deviation;
        }
    }
    variance /= (dims->degree * dims->nmoduli);
    return variance;
}

static void test_ccpolyzp_po2cyc_compute_variance(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 3 };
    ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1, 23, 31 };
    ccrns_int coeffs[] = { moduli[0] - 1, moduli[0] - 2, moduli[0] - 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs);
    float variance = ccpolyzp_po2cyc_compute_variance((ccpolyzp_po2cyc_const_t)poly_coeff);
    ok(variance < 12.917, "variance is above expected bounds: expected to be 12.91666...");
    ok(variance > 12.916, "variance is below expected bounds: expected to be 12.91666...");

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_ctx_init(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // Valid context
    {
        uint32_t valid_degrees[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 };
        uint32_t ndegrees = CC_ARRAY_LEN(valid_degrees);
        ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1 };

        for (uint32_t i = 0; i < ndegrees; ++i) {
            struct ccpolyzp_po2cyc_dims dims = { .degree = valid_degrees[i], .nmoduli = CC_ARRAY_LEN(moduli) };
            ccpolyzp_po2cyc_ctx_t context = CCPOLYZP_PO2CYC_CTX_ALLOC_WS(ws, dims.degree);
            is(ccpolyzp_po2cyc_ctx_init_ws(ws, context, &dims, moduli, NULL), CCERR_OK, "test_ccpolyzp_po2cyc_ctx_init valid");

            is(ccpolyzp_po2cyc_ctx_int_modulus(context, 0), moduli[0], "test_ccpolyzp_po2cyc_ctx_init wrong ccrns_int modulus");
            is(ccpolyzp_po2cyc_modulus_to_rns_int(ccpolyzp_po2cyc_ctx_cczp_modulus(context, 0)),
               moduli[0],
               "test_ccpolyzp_po2cyc_ctx_init wrong cczp modulus");
        }
    }
    // Degree not power of two
    {
        uint32_t invalid_degrees[] = { 0, 3, 5, 9, 25, 129 };
        uint32_t ndegrees = CC_ARRAY_LEN(invalid_degrees);
        ccrns_int moduli[] = { 19, 23, 31 };
        for (uint32_t i = 0; i < ndegrees; ++i) {
            struct ccpolyzp_po2cyc_dims dims = { .degree = invalid_degrees[i], .nmoduli = 3 };
            ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, &dims);
            is(ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, &dims, moduli),
               CCERR_PARAMETER,
               "test_ccpolyzp_po2cyc_ctx_init degree");
        }
    }
    // Moduli too large
    {
        ccrns_int moduli[] = { (UINT64_C(1) << 63) + 99 };
        struct ccpolyzp_po2cyc_dims dims = { .degree = 1024, .nmoduli = 1 };
        ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, &dims);
        is(ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, &dims, moduli),
           CCERR_PARAMETER,
           "test_ccpolyzp_po2cyc_ctx_init too large");
    }
    // Moduli not co-prime
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 3 };
        // Repeated modulus
        {
            ccrns_int moduli[] = { 19, 23, 19 };
            ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, &dims);
            is(ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, &dims, moduli),
               CCERR_PARAMETER,
               "test_ccpolyzp_po2cyc_ctx_init repeated moduli");
        }
#if CORECRYPTO_DEBUG
        // Non-prime modulus
        {
            ccrns_int moduli[] = { 15, 23, 31 };
            ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, &dims);
            is(ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, &dims, moduli),
               CCERR_PARAMETER,
               "test_ccpolyzp_po2cyc_ctx_init non-prime moduli");
        }
#endif // CORECRYPTO_DEBUG
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_ctx_chain_init(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // One modulus
    {
        ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1 };
        struct ccpolyzp_po2cyc_dims dims = { .degree = 32, .nmoduli = 1 };

        ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, &dims);
        is(ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, &dims, moduli),
           CCERR_OK,
           "ccpolyzp_po2cyc_ctx_chain_init_ws != CCERR_OK");
        ok(ccpolyzp_po2cyc_dims_eq(&ctx_chain->dims, &dims), "ccpolyzp_po2cyc_ctx_chain_init_ws L=1 dims not equal");

        ccpolyzp_po2cyc_ctx_const_t top_context = ccpolyzp_po2cyc_ctx_chain_context(ctx_chain, 1);
        is(top_context->dims.degree, dims.degree, "test_ccpolyzp_po2cyc_ctx_chain_init L=1 wrong degree");
        is(top_context->dims.nmoduli, 1, "test_ccpolyzp_po2cyc_ctx_chain_init L=1 wrong nmoduli");
        is(top_context->next, NULL, "test_ccpolyzp_po2cyc_ctx_chain_init L=1 next context not NULL");
        is(ccpolyzp_po2cyc_ctx_int_modulus(top_context, 0), moduli[0], "test_ccpolyzp_po2cyc_ctx_chain_init L=1 wrong modulus");
    }

    // Multiple moduli
    {
        ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1, 23, 31, 37, 41 };
        struct ccpolyzp_po2cyc_dims dims = { .degree = 32, .nmoduli = CC_ARRAY_LEN(moduli) };

        ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, &dims);
        is(ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, &dims, moduli),
           CCERR_OK,
           "ccpolyzp_po2cyc_ctx_chain_init_ws != CCERR_OK");

        for (uint32_t nmoduli = dims.nmoduli; nmoduli > 0; --nmoduli) {
            ccpolyzp_po2cyc_ctx_const_t context = ccpolyzp_po2cyc_ctx_chain_context(ctx_chain, nmoduli);

            is(context->dims.degree, dims.degree, "test_ccpolyzp_po2cyc_ctx_chain_init L=%" PRIu32 " wrong degree", nmoduli);
            is(context->dims.nmoduli, nmoduli, "test_ccpolyzp_po2cyc_ctx_chain_init L=%" PRIu32 " wrong nmoduli", nmoduli);
            for (uint32_t mod_idx = 0; mod_idx < nmoduli; ++mod_idx) {
                is(ccpolyzp_po2cyc_ctx_int_modulus(context, mod_idx),
                   moduli[mod_idx],
                   "test_ccpolyzp_po2cyc_ctx_chain_init wrong modulus");
            }
            if (nmoduli > 1) {
                ok(context->next != NULL, "test_ccpolyzp_po2cyc_ctx_chain_init L=%" PRIu32 " next context NULL", nmoduli);
            } else {
                is(context->next, NULL, "test_ccpolyzp_po2cyc_ctx_chain_init L=%" PRIu32 " last context next not NULL", nmoduli);
            }
        }
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_ctx_eq(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 3 };
    ccrns_int moduli[] = { 19, 23, 31 };
    ccpolyzp_po2cyc_ctx_t context0 = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli);

    // Match
    {
        ccpolyzp_po2cyc_ctx_t context1 = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli);
        is(ccpolyzp_po2cyc_ctx_eq(context0, context1), true, "test_ccpolyzp_po2cyc_ctx_eq match");
    }
    // Different degree
    {
        struct ccpolyzp_po2cyc_dims dims_diff = { .degree = 8, .nmoduli = 3 };
        ccpolyzp_po2cyc_ctx_t context1 = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_diff, moduli);
        is(ccpolyzp_po2cyc_ctx_eq(context0, context1), false, "test_ccpolyzp_po2cyc_ctx_eq degree");
    }
    // Different nmoduli
    {
        struct ccpolyzp_po2cyc_dims dims_diff = { .degree = 4, .nmoduli = 2 };
        ccpolyzp_po2cyc_ctx_t context1 = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_diff, moduli);
        is(ccpolyzp_po2cyc_ctx_eq(context0, context1), false, "test_ccpolyzp_po2cyc_ctx_eq nmoduli");
    }
    // Different moduli
    {
        ccrns_int moduli_diff[] = { 19, 23, 37 };
        ccpolyzp_po2cyc_ctx_t context1 = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli_diff);
        is(ccpolyzp_po2cyc_ctx_eq(context0, context1), false, "test_ccpolyzp_po2cyc_ctx_eq moduli");
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_ctx_q_prod_ws(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // 1 modulus
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1 };
        ccpolyzp_po2cyc_ctx_t context = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli);

        cc_size q_prod_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(context->dims.nmoduli);
        cc_unit *q_prod = CC_ALLOC_WS(ws, q_prod_max_nunits);
        ccpolyzp_po2cyc_ctx_q_prod_ws(ws, q_prod, context);
        cc_size q_prod_nunits = ccn_n(q_prod_max_nunits, q_prod);
        cc_unit moduli_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccpolyzp_po2cyc_rns_int_to_units(moduli_units, moduli[0]);
        is(ccn_cmpn(q_prod_nunits, q_prod, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, moduli_units),
           0,
           "test_ccpolyzp_po2cyc_ctx_q_prod_ws L=1");
    }
    // 5 moduli
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 5 };
        ccrns_int moduli[] = { (1ULL << 30) - 35, (1ULL << 60) - 93, (1ULL << 60) - 173, (1ULL << 28) - 57, (1ULL << 60) - 257 };
        ccpolyzp_po2cyc_ctx_t context = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli);

        cc_size q_prod_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(context->dims.nmoduli);
        cc_unit *q_prod = CC_ALLOC_WS(ws, q_prod_max_nunits);
        ccpolyzp_po2cyc_ctx_q_prod_ws(ws, q_prod, context);
        cc_size q_prod_nunits = ccn_n(q_prod_max_nunits, q_prod);

        ccnBuffer q_prod_buffer = mallocCcnBuffer(q_prod_nunits);
        q_prod_buffer->len = q_prod_nunits;
        q_prod_buffer->units = q_prod;

        ccnBuffer exp_q_prod_buffer = hexStringToCcn("3ffffef900007484002194cff066bfbead17cb9fb060b00d17fd045127ed");
        is(ccnAreEqual(q_prod_buffer, exp_q_prod_buffer), 1, "test_ccpolyzp_po2cyc_ctx_q_prod_ws L=5");
        free(q_prod_buffer);
        free(exp_q_prod_buffer);
    }

    CC_FREE_WORKSPACE(ws);
}

/// Arbitrary tests
static void test_ccpolyzp_po2cyc_init(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 3 };
    ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1, 23, 31 };
    ccrns_int coeffs[] = { 0x1122334455667788, moduli[0] - 2, moduli[0] - 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs);
    ccpolyzp_po2cyc_eval_t poly_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, coeffs);

    // Coefficient format
    {
        is(ccpolyzp_po2cyc_dims_eq(&poly_coeff->context->dims, &dims), true, "test_ccpolyzp_po2cyc_coeff_init wrong dimensions");
        for (uint32_t rns_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
            is(ccpolyzp_po2cyc_ctx_int_modulus(poly_coeff->context, rns_idx),
               moduli[rns_idx],
               "test_ccpolyzp_po2cyc_coeff_init wrong ccrns_int modulus");
            is(ccpolyzp_po2cyc_modulus_to_rns_int(ccpolyzp_po2cyc_ctx_cczp_modulus_const(poly_coeff->context, rns_idx)),
               moduli[rns_idx],
               "test_ccpolyzp_po2cyc_coeff_init wrong cczp_modulus_const modulus");
            is(ccpolyzp_po2cyc_ctx_ccrns_modulus(poly_coeff->context, rns_idx)->value,
               moduli[rns_idx],
               "test_ccpolyzp_po2cyc_coeff_init wrong ccrns_modulus modulus");
        }

        for (uint32_t rns_idx = 0, data_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
            for (uint32_t coeff_idx = 0; coeff_idx < dims.degree; ++coeff_idx) {
                ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly_coeff, rns_idx, coeff_idx);
                is(coeff, coeffs[data_idx++], "test_ccpolyzp_po2cyc_coeff_init wrong coeffs");
            }
        }
    }
    // Evaluation format
    {
        is(ccpolyzp_po2cyc_dims_eq(&poly_eval->context->dims, &dims), true, "test_ccpolyzp_po2cyc_eval_init wrong dimensions");
        for (uint32_t rns_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
            is(ccpolyzp_po2cyc_ctx_int_modulus(poly_eval->context, rns_idx),
               moduli[rns_idx],
               "test_ccpolyzp_po2cyc_coeff_init wrong ccrns_int modulus");
            is(ccpolyzp_po2cyc_ctx_ccrns_modulus(poly_eval->context, rns_idx)->value,
               moduli[rns_idx],
               "test_ccpolyzp_po2cyc_coeff_init wrong ccrns_modulus modulus");
        }

        for (uint32_t rns_idx = 0, data_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
            for (uint32_t coeff_idx = 0; coeff_idx < dims.degree; ++coeff_idx) {
                ccrns_int coeff = ccpolyzp_po2cyc_eval_data_int(poly_eval, rns_idx, coeff_idx);
                is(coeff, coeffs[data_idx++], "test_ccpolyzp_po2cyc_eval_init wrong coeffs");
            }
        }
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_init_zero(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 3 };
    ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1, 23, 31 };
    ccpolyzp_po2cyc_ctx_t ctx = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli);
    ccpolyzp_po2cyc_t poly_zero_coeff = CCPOLYZP_PO2CYC_ALLOC_WS(ws, &dims);
    ccpolyzp_po2cyc_init_zero(poly_zero_coeff, ctx);

    ccrns_int coeffs[12] = { 0 };
    ccpolyzp_po2cyc_coeff_t exp_poly_zero_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs);
    is(ccpolyzp_po2cyc_coeff_eq((ccpolyzp_po2cyc_coeff_t)poly_zero_coeff, exp_poly_zero_coeff),
       true,
       "test_ccpolyzp_po2cyc_init_zero");
    is(ccpolyzp_po2cyc_all_zero(poly_zero_coeff), true, "test_ccpolyzp_po2cyc_init_zero doesn't have all zeroes");
    is(ccpolyzp_po2cyc_has_zero_rns(poly_zero_coeff), true, "test_ccpolyzp_po2cyc_init_zero doesn't have any zeroes");
    is(ccpolyzp_po2cyc_compute_variance(poly_zero_coeff), 0, "test_ccpolyzp_po2cyc_init_zero doesn't have zero variance");

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_rns_int_convert(void)
{
    // Powers of two
    {
        ccrns_int xs[] = { 1, 2, 4, 8, 1ULL << 31, 1ULL << 32, 1ULL << 63, (1ULL << 60) };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(xs); ++i) {
            ccrns_int x = xs[i];
            cc_unit units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            ccpolyzp_po2cyc_rns_int_to_units(units, x);
            is(ccpolyzp_po2cyc_units_to_rns_int(units), x, "test_ccpolyzp_po2cyc_rns_int_convert power of two");
        }
    }
    // Random
    {
        uint32_t ntrials = 100;
        for (uint32_t trial = 0; trial < ntrials; ++trial) {
            ccrns_int x = rns_int_uniform(UINT64_MAX);
            cc_unit units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            ccpolyzp_po2cyc_rns_int_to_units(units, x);
            is(ccpolyzp_po2cyc_units_to_rns_int(units), x, "test_ccpolyzp_po2cyc_rns_int_convert random");
        }
    }
}

/// Arbitrary tests
static void test_ccpolyzp_po2cyc_eq(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 3 };
    ccrns_int moduli[] = { 19, 23, 31 };
    ccrns_int moduli_diff[] = { 19, 23, 101 };
    ccrns_int coeffs[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    ccrns_int coeffs_diff[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 99 };
    ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs);
    ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, coeffs);

    // Match
    {
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, poly1_coeff), true, "test_ccpolyzp_po2cyc_coeff_eq match");

        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, coeffs);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, poly1_eval), true, "test_ccpolyzp_po2cyc_eval_eq match");
    }
    // Different degree
    {
        struct ccpolyzp_po2cyc_dims dims_diff = { .degree = 2, .nmoduli = 3 };
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_diff, moduli, coeffs);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, poly1_coeff), false, "test_ccpolyzp_po2cyc_coeff_eq degree");

        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims_diff, moduli, coeffs);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, poly1_eval), false, "test_ccpolyzp_po2cyc_eval_eq degree");
    }
    // Different nmoduli
    {
        struct ccpolyzp_po2cyc_dims dims_diff = { .degree = 4, .nmoduli = 2 };
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_diff, moduli, coeffs);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, poly1_coeff), false, "test_ccpolyzp_po2cyc_coeff_eq nmoduli");

        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims_diff, moduli, coeffs);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, poly1_eval), false, "test_ccpolyzp_po2cyc_eval_eq nmoduli");
    }
    // Different moduli
    {
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli_diff, coeffs);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, poly1_coeff), false, "test_ccpolyzp_po2cyc_coeff_eq moduli");

        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli_diff, coeffs);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, poly1_eval), false, "test_ccpolyzp_po2cyc_eval_eq moduli");
    }
    // Different coefficients
    {
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs_diff);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, poly1_coeff), false, "test_ccpolyzp_po2cyc_coeff_eq coefficients");

        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, coeffs_diff);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, poly1_eval), false, "test_ccpolyzp_po2cyc_eval_eq coefficients");
    }
    CC_FREE_WORKSPACE(ws);
}

/// Arbitrary tests
static void test_ccpolyzp_po2cyc_negate(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 11, (1ULL << 60) - (1ULL << 18) + 1 };
    ccrns_int poly_data[] = { 1, 2, 3, 4, 0, 1, moduli[1] - 2, moduli[1] - 1 };
    ccrns_int negate_data[] = { 10, 9, 8, 7, 0, moduli[1] - 1, 2, 1 };
    ccpolyzp_po2cyc_coeff_t exp_poly_coeff_negate = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, negate_data);
    ccpolyzp_po2cyc_eval_t exp_poly_eval_negate = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, negate_data);

    ccrns_int poly_out_data[8] = { 0 };
    ccpolyzp_po2cyc_coeff_t poly_coeff_out = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_out_data);
    ccpolyzp_po2cyc_eval_t poly_eval_out = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_out_data);

    // poly_out = -poly
    {
        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_data);
        ccpolyzp_po2cyc_coeff_negate(poly_coeff_out, poly_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly_coeff_out, exp_poly_coeff_negate), true, "ccpolyzp_po2cyc_coeff_eq poly_out = -poly1");

        ccpolyzp_po2cyc_eval_t poly_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_data);
        ccpolyzp_po2cyc_eval_negate(poly_eval_out, poly_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly_eval_out, exp_poly_eval_negate), true, "ccpolyzp_po2cyc_eval_negate poly_out = -poly1");
    }
    // poly = -poly
    {
        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_data);
        ccpolyzp_po2cyc_coeff_negate(poly_coeff, poly_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly_coeff, exp_poly_coeff_negate), true, "ccpolyzp_po2cyc_coeff_negate poly = -poly");

        ccpolyzp_po2cyc_eval_t poly_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_data);
        ccpolyzp_po2cyc_eval_negate(poly_eval, poly_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly_eval, exp_poly_eval_negate), true, "ccpolyzp_po2cyc_eval_negate poly = -poly");
    }
    CC_FREE_WORKSPACE(ws);
}

/// Arbitrary tests
static void test_ccpolyzp_po2cyc_add(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 11, (1ULL << 60) - (1ULL << 18) + 1 };
    ccrns_int poly0_data[] = { 1, 2, 3, 4, 0, 1, moduli[1] - 2, moduli[1] - 1 };
    ccrns_int poly1_data[] = { 5, 6, 8, 9, 0, moduli[1] - 1, 1, 2 };
    ccrns_int sum_data[] = { 6, 8, 0, 2, 0, 0, moduli[1] - 1, 1 };
    ccpolyzp_po2cyc_coeff_t exp_poly_coeff_sum = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, sum_data);
    ccpolyzp_po2cyc_eval_t exp_poly_eval_sum = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, sum_data);

    ccrns_int poly_out_data[8] = { 0 };
    ccpolyzp_po2cyc_coeff_t poly_coeff_out = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_out_data);
    ccpolyzp_po2cyc_eval_t poly_eval_out = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_out_data);

    // poly0 + poly1
    {
        ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_coeff_add(poly_coeff_out, poly0_coeff, poly1_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly_coeff_out, exp_poly_coeff_sum), true, "ccpolyzp_po2cyc_coeff_add poly0 + poly1");

        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_add(poly_eval_out, poly0_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly_eval_out, exp_poly_eval_sum), true, "ccpolyzp_po2cyc_eval_add poly0 + poly1");
    }
    // poly0 += poly1
    {
        ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_coeff_add(poly0_coeff, poly0_coeff, poly1_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, exp_poly_coeff_sum), true, "ccpolyzp_po2cyc_coeff_add poly0 += poly1");

        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_add(poly0_eval, poly0_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, exp_poly_eval_sum), true, "ccpolyzp_po2cyc_eval_add poly0 += poly1");
    }
    // poly1 += poly0
    {
        ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_coeff_add(poly1_coeff, poly0_coeff, poly1_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly1_coeff, exp_poly_coeff_sum), true, "ccpolyzp_po2cyc_coeff_add poly1 += poly0");

        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_add(poly1_eval, poly0_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly1_eval, exp_poly_eval_sum), true, "ccpolyzp_po2cyc_eval_add poly1 += poly0");
    }
    // poly1 += poly1
    {
        ccrns_int sum_data[] = { 10, 1, 5, 7, 0, moduli[1] - 2, 2, 4 };
        ccpolyzp_po2cyc_coeff_t exp_poly_coeff_sum = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, sum_data);

        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_coeff_add(poly1_coeff, poly1_coeff, poly1_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly1_coeff, exp_poly_coeff_sum), true, "ccpolyzp_po2cyc_coeff_add poly1 += poly1");

        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_t exp_poly_eval_sum = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, sum_data);
        ccpolyzp_po2cyc_eval_add(poly1_eval, poly1_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly1_eval, exp_poly_eval_sum), true, "ccpolyzp_po2cyc_eval_add poly1 += poly1");
    }
    CC_FREE_WORKSPACE(ws);
}

/// Arbitrary tests
static void test_ccpolyzp_po2cyc_sub(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 11, (1ULL << 60) - (1ULL << 18) + 1 };
    ccrns_int poly0_data[] = { 1, 2, 3, 4, 0, 1, moduli[1] - 2, moduli[1] - 1 };
    ccrns_int poly1_data[] = { 1, 1, 5, 7, 0, moduli[1] - 1, 1, 2 };
    ccrns_int diff_0m1_data[] = { 0, 1, moduli[0] - 2, moduli[0] - 3, 0, 2, moduli[1] - 3, moduli[1] - 3 };
    ccrns_int diff_1m0_data[] = { 0, moduli[0] - 1, 2, 3, 0, moduli[1] - 2, 3, 3 };
    ccpolyzp_po2cyc_coeff_t exp_poly_coeff_diff_0m1 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, diff_0m1_data);
    ccpolyzp_po2cyc_eval_t exp_poly_eval_diff_0m1 = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, diff_0m1_data);
    ccpolyzp_po2cyc_coeff_t exp_poly_coeff_diff_1m0 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, diff_1m0_data);
    ccpolyzp_po2cyc_eval_t exp_poly_eval_diff_1m0 = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, diff_1m0_data);

    ccrns_int poly_out_data[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    ccpolyzp_po2cyc_coeff_t poly_coeff_out = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_out_data);
    ccpolyzp_po2cyc_eval_t poly_eval_out = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_out_data);

    // poly0 - poly1
    {
        ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_coeff_sub(poly_coeff_out, poly0_coeff, poly1_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly_coeff_out, exp_poly_coeff_diff_0m1), true, "ccpolyzp_po2cyc_coeff_sub poly0 - poly1");

        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_sub(poly_eval_out, poly0_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly_eval_out, exp_poly_eval_diff_0m1), true, "ccpolyzp_po2cyc_eval_sub poly0 - poly1");
    }
    // poly0 -= poly1
    {
        ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_coeff_sub(poly0_coeff, poly0_coeff, poly1_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, exp_poly_coeff_diff_0m1), true, "ccpolyzp_po2cyc_coeff_sub poly0 -= poly1");

        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_sub(poly0_eval, poly0_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, exp_poly_eval_diff_0m1), true, "ccpolyzp_po2cyc_eval_sub poly0 -= poly1");
    }
    // poly0 = poly1 - poly0
    {
        ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_coeff_t poly1_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_coeff_sub(poly0_coeff, poly1_coeff, poly0_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, exp_poly_coeff_diff_1m0),
           true,
           "ccpolyzp_po2cyc_coeff_sub poly0 = poly1 - poly0");

        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_sub(poly0_eval, poly1_eval, poly0_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, exp_poly_eval_diff_1m0), true, "ccpolyzp_po2cyc_eval_sub poly0 = poly1 - poly0");
    }
    // poly0 = poly0 - poly0
    {
        ccrns_int diff_data[8] = { 0 };
        ccpolyzp_po2cyc_coeff_t exp_poly_coeff_diff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, diff_data);

        ccpolyzp_po2cyc_coeff_t poly0_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_coeff_sub(poly0_coeff, poly0_coeff, poly0_coeff);
        is(ccpolyzp_po2cyc_coeff_eq(poly0_coeff, exp_poly_coeff_diff), true, "ccpolyzp_po2cyc_coeff_sub poly0 = poly0 - poly0");

        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t exp_poly_eval_diff = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, diff_data);
        ccpolyzp_po2cyc_eval_sub(poly0_eval, poly0_eval, poly0_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, exp_poly_eval_diff), true, "ccpolyzp_po2cyc_eval_sub poly0 = poly0 - poly0");
    }
    CC_FREE_WORKSPACE(ws);
}

/// Arbitrary tests
static void test_ccpolyzp_po2cyc_mul(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 11, (1ULL << 60) - (1ULL << 18) + 1 };
    ccrns_int poly0_data[] = { 1, 2, 3, 4, 0, 1, moduli[1] - 2, moduli[1] - 1 };
    ccrns_int poly1_data[] = { 1, 1, 5, 7, 0, moduli[1] - 1, 1, moduli[1] - 1 };
    ccrns_int prod_data[] = { 1, 2, 4, 6, 0, moduli[1] - 1, moduli[1] - 2, 1 };
    ccpolyzp_po2cyc_eval_t exp_poly_prod = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, prod_data);

    ccrns_int poly_out_data[8] = { 0 };
    ccpolyzp_po2cyc_eval_t poly_eval_out = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_out_data);

    // poly0 * poly1
    {
        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_mul(poly_eval_out, poly0_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly_eval_out, exp_poly_prod), true, "ccpolyzp_po2cyc_eval_mul poly0 * poly1");
    }
    // poly0 *= poly1
    {
        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_mul(poly0_eval, poly0_eval, poly1_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, exp_poly_prod), true, "ccpolyzp_po2cyc_eval_mul poly0 *= poly1");
    }
    // poly0 = poly1 * poly0
    {
        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_t poly1_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly1_data);
        ccpolyzp_po2cyc_eval_mul(poly0_eval, poly1_eval, poly0_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, exp_poly_prod), true, "ccpolyzp_po2cyc_eval_mul poly0  = poly1 * poly0");
    }
    // poly0 = poly0 * poly0
    {
        ccrns_int prod_data[] = { 1, 4, 9, 5, 0, 1, 4, 1 };
        ccpolyzp_po2cyc_eval_t exp_poly_eval_prod = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, prod_data);
        ccpolyzp_po2cyc_eval_t poly0_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly0_data);
        ccpolyzp_po2cyc_eval_mul(poly0_eval, poly0_eval, poly0_eval);
        is(ccpolyzp_po2cyc_eval_eq(poly0_eval, exp_poly_eval_prod), true, "ccpolyzp_po2cyc_eval_mul poly0 *= poly0");
    }
    CC_FREE_WORKSPACE(ws);
}

/// Arbitrary tests
static void test_ccpolyzp_po2cyc_coeff_scalar_mul(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 11, (1ULL << 60) - (1ULL << 18) + 1 };
    ccrns_int poly_data[] = { 1, 2, 3, 4, 0, 1, moduli[1] - 2, moduli[1] - 1 };

    ccrns_int poly_out_data[8] = { 0 };
    ccpolyzp_po2cyc_coeff_t poly_coeff_out = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_out_data);
    ccpolyzp_po2cyc_eval_t poly_eval_out = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_out_data);

    // scalar smaller than all moduli, between moduli, larger than all moduli, larger than product of moduli
    ccrns_int scalars[] = { 10, 20, moduli[1] + 1, moduli[0] * moduli[1] + 1 };
    ccrns_int prod_data[4][8] = { { 10, 9, 8, 7, 0, 10, moduli[1] - 20, moduli[1] - 10 },
                                  { 9, 7, 5, 3, 0, 20, moduli[1] - 40, moduli[1] - 20 },
                                  { 0, 0, 0, 0, 0, 1, moduli[1] - 2, moduli[1] - 1 },
                                  { 1, 2, 3, 4, 0, 1, moduli[1] - 2, moduli[1] - 1 } };

    for (uint32_t test_idx = 0; test_idx < CC_ARRAY_LEN(scalars); ++test_idx) {
        ccrns_int scalar = scalars[test_idx];
        ccrns_int scalars_mod_qi[dims.nmoduli];
        for (uint32_t i = 0; i < dims.nmoduli; ++i) {
            scalars_mod_qi[i] = scalar % moduli[i];
        }

        ccpolyzp_po2cyc_coeff_t exp_poly_prod_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, prod_data[test_idx]);
        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_data);
        ccpolyzp_po2cyc_coeff_scalar_mul_ws(ws, poly_coeff_out, poly_coeff, scalars_mod_qi);
        is(ccpolyzp_po2cyc_coeff_eq(poly_coeff_out, exp_poly_prod_coeff),
           true,
           "ccpolyzp_po2cyc_coeff_scalar_mul poly * scalar %" PRIu64,
           (uint64_t)scalar);

        ccpolyzp_po2cyc_coeff_scalar_mul_ws(ws, poly_coeff, poly_coeff, scalars_mod_qi);
        is(ccpolyzp_po2cyc_coeff_eq(poly_coeff, exp_poly_prod_coeff),
           true,
           "ccpolyzp_po2cyc_coeff_scalar_mul poly *= scalar %" PRIu64,
           (uint64_t)scalar);

        ccpolyzp_po2cyc_eval_t exp_poly_prod_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, prod_data[test_idx]);
        ccpolyzp_po2cyc_eval_t poly_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, poly_data);
        ccpolyzp_po2cyc_eval_scalar_mul_ws(ws, poly_eval_out, poly_eval, scalars_mod_qi);
        is(ccpolyzp_po2cyc_eval_eq(poly_eval_out, exp_poly_prod_eval),
           true,
           "ccpolyzp_po2cyc_eval_scalar_mul poly * scalar %" PRIu64,
           (uint64_t)scalar);
        ccpolyzp_po2cyc_eval_scalar_mul_ws(ws, poly_eval, poly_eval, scalars_mod_qi);
        is(ccpolyzp_po2cyc_eval_eq(poly_eval, exp_poly_prod_eval),
           true,
           "ccpolyzp_po2cyc_coeff_scalar_mul poly *= scalar %" PRIu64,
           (uint64_t)scalar);
    }
    CC_FREE_WORKSPACE(ws);
}

/// Returns true if test passed
static bool ntt_test_helper(cc_ws_t ws,
                            ccpolyzp_po2cyc_dims_const_t dims,
                            ccrns_int *moduli,
                            const ccrns_int *data_coeff,
                            const ccrns_int *data_eval)
{
    // fwd_ntt
    {
        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, data_coeff);
        ccpolyzp_po2cyc_eval_t poly_eval = ccpolyzp_po2cyc_eval_init_helper(ws, dims, moduli, data_eval);
        is(ccpolyzp_po2cyc_fwd_ntt(poly_coeff), CCERR_OK, "Error computing fwd_ntt");
        if (!ccpolyzp_po2cyc_eval_eq((ccpolyzp_po2cyc_eval_t)poly_coeff, poly_eval)) {
            return false;
        };
    }
    // inv_ntt
    {
        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, data_coeff);
        ccpolyzp_po2cyc_eval_t poly_eval = ccpolyzp_po2cyc_eval_init_helper(ws, dims, moduli, data_eval);
        is(ccpolyzp_po2cyc_inv_ntt(poly_eval), CCERR_OK, "Error computing inv_ntt");
        if (!ccpolyzp_po2cyc_coeff_eq((ccpolyzp_po2cyc_coeff_t)poly_eval, poly_coeff)) {
            return false;
        };
    }
    return true;
}

static void test_ccpolyzp_po2cyc_ntt(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // is_ntt_modulus_and_degree
    {
        is(is_ntt_modulus_and_degree(73, 4), true, "is_ntt_modulus_and_degree(p=73, N=4)");
        is(is_ntt_modulus_and_degree(73, 8), false, "is_ntt_modulus_and_degree(p=73, N=8)");
        is(is_ntt_modulus_and_degree(11, 5), false, "is_ntt_modulus_and_degree(p=11, N=5)");
    }

    // Pre-computed values - 1 modulus
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { 73 };
        ccpolyzp_po2cyc_ctx_t context = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli);

        is(ccpolyzp_po2cyc_ctx_rou(context, 0), 10, "test_ccpolyzp_po2cyc_ntt L=1 rou != 10");

        cc_unit *rou_powers = ccpolyzp_po2cyc_ctx_rou_powers(context, 0);
        const cc_unit *rou_powers_const = ccpolyzp_po2cyc_ctx_rou_powers_const(context, 0);
        ccrns_int exp_rou_powers[4] = { 1, 27, 10, 51 };
        for (uint32_t i = 0; i < 4; ++i) {
            ccrns_int w = ccpolyzp_po2cyc_units_to_rns_int(&rou_powers[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            ccrns_int w_const = ccpolyzp_po2cyc_units_to_rns_int(&rou_powers_const[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            is(w, exp_rou_powers[i], "test_ccpolyzp_po2cyc_ntt L=1 rou_powers mismatch at %" PRIu32 "", i);
            is(w_const, exp_rou_powers[i], "test_ccpolyzp_po2cyc_ntt L=1 rou_powers_const mismatch at %" PRIu32 "", i);
        }

        is(ccpolyzp_po2cyc_ctx_inv_rou(context, 0), 22, "test_ccpolyzp_po2cyc_ntt L=1 inv_rou != 22");
        cc_unit *inv_rou_powers = ccpolyzp_po2cyc_ctx_inv_rou_powers(context, 0);
        const cc_unit *inv_rou_powers_const = ccpolyzp_po2cyc_ctx_inv_rou_powers_const(context, 0);
        ccrns_int exp_inv_rou_powers[4] = { 1, 22, 63, 46 };
        for (uint32_t i = 0; i < 4; ++i) {
            ccrns_int inv_w = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            ccrns_int inv_w_const = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers_const[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            is(inv_w, exp_inv_rou_powers[i], "test_ccpolyzp_po2cyc_ntt L=1 inv_rou_powers mismatch at %" PRIu32 "", i);
            is(inv_w_const,
               exp_inv_rou_powers[i],
               "test_ccpolyzp_po2cyc_ntt L=1 inv_rou_powers_const mismatch at %" PRIu32 "",
               i);
        }

        // ccpolyzp_po2cyc_ctx_inv_rou_power_n2
        {
            ccrns_mul_modulus_t n_inv_w_n2 = ccpolyzp_po2cyc_ctx_inv_rou_power_n2(context, 0);
            is(n_inv_w_n2->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2");
            is(n_inv_w_n2->multiplicand, 48, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2");
        }
        {
            ccrns_mul_modulus_const_t n_inv_w_n2 = ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const(context, 0);
            is(n_inv_w_n2->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const");
            is(n_inv_w_n2->multiplicand, 48, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const");
        }
        // ccpolyzp_po2cyc_ctx_inv_degree
        {
            ccrns_mul_modulus_t n_inv = ccpolyzp_po2cyc_ctx_inv_degree(context, 0);
            is(n_inv->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_degree");
            is(n_inv->multiplicand, 55, "ccpolyzp_po2cyc_ctx_inv_degree");
        }
        {
            ccrns_mul_modulus_const_t n_inv = ccpolyzp_po2cyc_ctx_inv_degree_const(context, 0);
            is(n_inv->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_degree_const");
            is(n_inv->multiplicand, 55, "ccpolyzp_po2cyc_ctx_inv_degree_const");
        }
    }
    // Pre-computed values - 2 moduli
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli[] = { 73, 113 };
        ccpolyzp_po2cyc_ctx_t context = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims, moduli);

        is(ccpolyzp_po2cyc_ctx_rou(context, 0), 10, "test_ccpolyzp_po2cyc_ntt L=2 rou != 10");
        is(ccpolyzp_po2cyc_ctx_rou(context, 1), 18, "test_ccpolyzp_po2cyc_ntt L=2 rou != 18");

        cc_unit *rou_powers = ccpolyzp_po2cyc_ctx_rou_powers(context, 0);
        const cc_unit *rou_powers_const = ccpolyzp_po2cyc_ctx_rou_powers_const(context, 0);
        ccrns_int exp_rou_powers_idx_0[4] = { 1, 27, 10, 51 };
        for (uint32_t i = 0; i < 4; ++i) {
            ccrns_int w = ccpolyzp_po2cyc_units_to_rns_int(&rou_powers[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            ccrns_int w_const = ccpolyzp_po2cyc_units_to_rns_int(&rou_powers_const[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            is(w, exp_rou_powers_idx_0[i], "test_ccpolyzp_po2cyc_ntt L=2 rou_powers mismatch at 0, %" PRIu32, i);
            is(w_const, exp_rou_powers_idx_0[i], "test_ccpolyzp_po2cyc_ntt L=2 rou_powers_const mismatch at 0, %" PRIu32, i);
        }

        rou_powers = ccpolyzp_po2cyc_ctx_rou_powers(context, 1);
        rou_powers_const = ccpolyzp_po2cyc_ctx_rou_powers_const(context, 1);
        ccrns_int exp_rou_powers_idx_1[4] = { 1, 98, 18, 69 };
        for (uint32_t i = 0; i < 4; ++i) {
            ccrns_int w = ccpolyzp_po2cyc_units_to_rns_int(&rou_powers[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            ccrns_int w_const = ccpolyzp_po2cyc_units_to_rns_int(&rou_powers_const[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            is(w, exp_rou_powers_idx_1[i], "test_ccpolyzp_po2cyc_ntt L=2 rou_powers mismatch at 1, %" PRIu32, i);
            is(w_const, exp_rou_powers_idx_1[i], "test_ccpolyzp_po2cyc_ntt L=2 rou_powers_const mismatch at 1, %" PRIu32, i);
        }

        is(ccpolyzp_po2cyc_ctx_inv_rou(context, 0), 22, "test_ccpolyzp_po2cyc_ntt L=2 inv_rou != 22");
        is(ccpolyzp_po2cyc_ctx_inv_rou(context, 1), 44, "test_ccpolyzp_po2cyc_ntt L=2 inv_rou != 44");
        cc_unit *inv_rou_powers = ccpolyzp_po2cyc_ctx_inv_rou_powers(context, 0);
        const cc_unit *inv_rou_powers_const = ccpolyzp_po2cyc_ctx_inv_rou_powers_const(context, 0);
        ccrns_int exp_inv_rou_powers_idx_0[4] = { 1, 22, 63, 46 };
        for (uint32_t i = 0; i < 4; ++i) {
            ccrns_int inv_w = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            ccrns_int inv_w_const = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers_const[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            is(inv_w, exp_inv_rou_powers_idx_0[i], "test_ccpolyzp_po2cyc_ntt L=2 inv_rou_powers mismatch at 0, %" PRIu32, i);
            is(inv_w_const,
               exp_inv_rou_powers_idx_0[i],
               "test_ccpolyzp_po2cyc_ntt L=2 inv_rou_powers_const mismatch at 0, %" PRIu32,
               i);
        }

        inv_rou_powers = ccpolyzp_po2cyc_ctx_inv_rou_powers(context, 1);
        inv_rou_powers_const = ccpolyzp_po2cyc_ctx_inv_rou_powers_const(context, 1);
        ccrns_int exp_inv_rou_powers_idx_1[4] = { 1, 44, 95, 15 };
        for (uint32_t i = 0; i < 4; ++i) {
            ccrns_int inv_w = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            ccrns_int inv_w_const = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers_const[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            is(inv_w, exp_inv_rou_powers_idx_1[i], "test_ccpolyzp_po2cyc_ntt L=2 inv_rou_powers mismatch at 1, %" PRIu32, i);
            is(inv_w_const,
               exp_inv_rou_powers_idx_1[i],
               "test_ccpolyzp_po2cyc_ntt L=2 inv_rou_powers_const mismatch at 1, %" PRIu32,
               i);
        }

        // ccpolyzp_po2cyc_ctx_inv_rou_power_n2
        {
            ccrns_mul_modulus_t n_inv_w_n2 = ccpolyzp_po2cyc_ctx_inv_rou_power_n2(context, 0);
            is(n_inv_w_n2->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2");
            is(n_inv_w_n2->multiplicand, 48, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2");
        }
        {
            ccrns_mul_modulus_const_t n_inv_w_n2 = ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const(context, 0);
            is(n_inv_w_n2->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const");
            is(n_inv_w_n2->multiplicand, 48, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const");
        }
        // ccpolyzp_po2cyc_ctx_inv_degree
        {
            ccrns_mul_modulus_t n_inv = ccpolyzp_po2cyc_ctx_inv_degree(context, 0);
            is(n_inv->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_degree");
            is(n_inv->multiplicand, 55, "ccpolyzp_po2cyc_ctx_inv_degree");
        }
        {
            ccrns_mul_modulus_const_t n_inv = ccpolyzp_po2cyc_ctx_inv_degree_const(context, 0);
            is(n_inv->modulus, 73, "ccpolyzp_po2cyc_ctx_inv_degree_const");
            is(n_inv->multiplicand, 55, "ccpolyzp_po2cyc_ctx_inv_degree_const");
        }

        // ccpolyzp_po2cyc_ctx_inv_rou_power_n2
        {
            ccrns_mul_modulus_t n_inv_w_n2 = ccpolyzp_po2cyc_ctx_inv_rou_power_n2(context, 1);
            is(n_inv_w_n2->modulus, 113, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2");
            is(n_inv_w_n2->multiplicand, 32, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2");
        }
        {
            ccrns_mul_modulus_const_t n_inv_w_n2 = ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const(context, 1);
            is(n_inv_w_n2->modulus, 113, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const");
            is(n_inv_w_n2->multiplicand, 32, "ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const");
        }
        // ccpolyzp_po2cyc_ctx_inv_degree
        {
            ccrns_mul_modulus_t n_inv = ccpolyzp_po2cyc_ctx_inv_degree(context, 1);
            is(n_inv->modulus, 113, "ccpolyzp_po2cyc_ctx_inv_degree");
            is(n_inv->multiplicand, 85, "ccpolyzp_po2cyc_ctx_inv_degree");
        }
        {
            ccrns_mul_modulus_const_t n_inv = ccpolyzp_po2cyc_ctx_inv_degree_const(context, 1);
            is(n_inv->modulus, 113, "ccpolyzp_po2cyc_ctx_inv_degree_const");
            is(n_inv->multiplicand, 85, "ccpolyzp_po2cyc_ctx_inv_degree_const");
        }
    }
    // NTT tests
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { 73 };
        ccrns_int data_coeff[] = { 1, 2, 3, 4 };
        ccrns_int data_eval[] = { 14, 4, 62, 70 };
        is(ntt_test_helper(ws, &dims, moduli, data_coeff, data_eval), true, "test_ntt N=4/L=1");
    }
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { 113 };
        ccrns_int data_coeff[] = { 94, 109, 11, 18 };
        ccrns_int data_eval[] = { 82, 2, 81, 98 };
        is(ntt_test_helper(ws, &dims, moduli, data_coeff, data_eval), true, "test_ntt N=4/L=1");
    }
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli[] = { 73, 113 };
        ccrns_int data_coeff[] = { 1, 2, 3, 4, 94, 109, 11, 18 };
        ccrns_int data_eval[] = { 14, 4, 62, 70, 82, 2, 81, 98 };
        is(ntt_test_helper(ws, &dims, moduli, data_coeff, data_eval), true, "test_ntt N=4/L=2");
    }
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 8, .nmoduli = 2 };
        ccrns_int q0 = (1ULL << 36) - (1ULL << 18) + (1ULL << 14) + 1;
        ccrns_int q1 = (1ULL << 60) - (1ULL << 18) + 1;
        ccrns_int moduli[] = { q0, q1 };
        ccrns_int data_coeff[] = {
            1, q0 - 2, 3, q0 - 4, 5, q0 - 6, 7, q0 - 8, 9, q1 - 10, 11, q1 - 12, 13, q1 - 14, 15, q1 - 16
        };
        ccrns_int data_eval[] = { 32628106561,        62299913688,        20964738505,        2087372808,
                                  14286010853,        54600424889,        42033554224,        45976802388,
                                  414646600533235285, 317175493889485452, 897139828300598499, 706240413915504341,
                                  424563422226887324, 218783155887760566, 256560696891564704, 223654902174718400 };
        is(ntt_test_helper(ws, &dims, moduli, data_coeff, data_eval), true, "test_ntt N=8/L=1");
    }
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 32, .nmoduli = 2 };
        ccrns_int q0 = (1ULL << 36) - (1ULL << 18) + (1ULL << 14) + 1;
        ccrns_int q1 = (1ULL << 60) - (1ULL << 18) + 1;
        ccrns_int moduli[] = { q0, q1 };
        ccrns_int data_coeff[] = { 1,  q0 - 2,  3,  q0 - 4,  5,  q0 - 6,  7,  q0 - 8,  9,  q0 - 10, 11, q0 - 12, 13, q0 - 14,
                                   15, q0 - 16, 17, q0 - 18, 19, q0 - 20, 21, q0 - 22, 23, q0 - 24, 25, q0 - 26, 27, q0 - 28,
                                   29, q0 - 30, 31, q0 - 32, 33, q1 - 34, 35, q1 - 36, 37, q1 - 38, 39, q1 - 40, 41, q1 - 42,
                                   43, q1 - 44, 45, q1 - 46, 47, q1 - 48, 49, q1 - 50, 51, q1 - 52, 53, q1 - 54, 55, q1 - 56,
                                   57, q1 - 58, 59, q1 - 60, 61, q1 - 62, 63, q1 - 64 };
        ccrns_int data_eval[] = {
            28044854107,         18650603107,        3861724871,          66198379462,         315081065,
            14456352558,         2950059311,         55712530496,         22284579988,         6473620204,
            8031687225,          6499789505,         35883668535,         25169744794,         23495556062,
            22067707938,         23378616434,        51731875359,         23576951206,         20927515723,
            48762629201,         18600463890,        33186520778,         14331556737,         7551921180,
            23294727244,         63681185683,        10292292088,         59600650675,         10081563528,
            44663597651,         30872765151,        91199957565860715,   1024380258154772216, 266074987590640852,
            1107050838457574193, 981855602276550557, 78311430491863095,   279721121437155843,  1054749721596420339,
            751325697870921853,  322399853072516492, 86056358587105643,   555748609019276168,  453609568351810814,
            838000738164092603,  62372701601138772,  827866271428197537,  993277833622560555,  563821764406796988,
            640317575199862016,  188826581296003855, 1047841542966818051, 114767784786862291,  107477682670846271,
            309677486713403169,  823691139963877913, 854373302230170672,  333600021006359648,  766328857338913786,
            630240104655174426,  856225811507715836, 303061135513120256,  1132491734160974959
        };
        ok(ntt_test_helper(ws, &dims, moduli, data_coeff, data_eval), "test_ntt N=32/L=1");
    }
    // Random round-trip
    {
        ccrns_int moduli[] = { 40961, (1ULL << 60) - (1ULL << 18) + 1 };
        uint32_t nmoduli = CC_ARRAY_LEN(moduli);
        for (uint32_t degree = 4; degree <= 1024; degree <<= 1) {
            struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = nmoduli };
            ccrns_int data_coeff[nmoduli * dims.degree];
            for (uint32_t rns_idx = 0, data_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
                for (uint32_t coeff_idx = 0; coeff_idx < dims.degree; ++coeff_idx) {
                    data_coeff[data_idx++] = rns_int_uniform(moduli[rns_idx]);
                }
            }

            ccpolyzp_po2cyc_coeff_t poly_orig_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, data_coeff);
            ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, data_coeff);

            is(ccpolyzp_po2cyc_fwd_ntt(poly_coeff), CCERR_OK, "test_fwd_ntt error");
            is(ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)poly_coeff), CCERR_OK, "test_inv_ntt error");
            is(ccpolyzp_po2cyc_coeff_eq(poly_coeff, poly_orig_coeff), true, "test_ntt roundtrip");
        }
    }
    // NTT can be used for polynomial multiplication
    {
        ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1 };
        for (uint32_t degree = 4; degree <= 1024; degree <<= 1) {
            struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(moduli) };
            ccrns_int data_x_coeff[dims.nmoduli * dims.degree];
            ccrns_int data_y_coeff[dims.nmoduli * dims.degree];
            ccrns_int data_out_coeff[dims.nmoduli * dims.degree];
            for (uint32_t rns_idx = 0, data_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
                for (uint32_t coeff_idx = 0; coeff_idx < dims.degree; ++coeff_idx, ++data_idx) {
                    data_x_coeff[data_idx] = rns_int_uniform(moduli[rns_idx]);
                    data_y_coeff[data_idx] = rns_int_uniform(moduli[rns_idx]);
                    data_out_coeff[data_idx] = 0;
                }
            }

            ccpolyzp_po2cyc_coeff_t naive_out_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, data_out_coeff);
            {
                ccpolyzp_po2cyc_coeff_const_t x_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, data_x_coeff);
                ccpolyzp_po2cyc_coeff_const_t y_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, data_y_coeff);
                // Schoolbook multiplication
                cc_unit coeff_tmp[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
                for (uint32_t rns_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
                    cczp_const_t modulus = ccpolyzp_po2cyc_ctx_cczp_modulus_const(x_coeff->context, rns_idx);
                    for (uint32_t i = 0; i < dims.degree; ++i) {
                        for (uint32_t j = 0; j <= i; ++j) {
                            // out[i] += x[j] * y[i-j]
                            const cc_unit *x_j = CCPOLYZP_PO2CYC_DATA_CONST(x_coeff, rns_idx, j);
                            const cc_unit *y_i_minus_j = CCPOLYZP_PO2CYC_DATA_CONST(y_coeff, rns_idx, i - j);
                            cc_unit *out_i = CCPOLYZP_PO2CYC_DATA(naive_out_coeff, rns_idx, i);
                            cczp_mul_ws(ws, modulus, coeff_tmp, x_j, y_i_minus_j);
                            cczp_add_ws(ws, modulus, out_i, out_i, coeff_tmp);
                        }
                        // Reduce using X^N == -1
                        for (uint32_t j = i + 1; j < dims.degree; ++j) {
                            const cc_unit *x_j = CCPOLYZP_PO2CYC_DATA_CONST(x_coeff, rns_idx, j);
                            const cc_unit *y_n_plus_i_minus_j = CCPOLYZP_PO2CYC_DATA_CONST(y_coeff, rns_idx, dims.degree + i - j);
                            cc_unit *out_i = CCPOLYZP_PO2CYC_DATA(naive_out_coeff, rns_idx, i);
                            cczp_mul_ws(ws, modulus, coeff_tmp, x_j, y_n_plus_i_minus_j);
                            cczp_sub_ws(ws, modulus, out_i, out_i, coeff_tmp);
                        }
                    }
                }
            }
            // NTT multiplication
            ccpolyzp_po2cyc_coeff_t x_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, data_x_coeff);
            ccpolyzp_po2cyc_coeff_t y_coeff = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, data_y_coeff);

            ccpolyzp_po2cyc_eval_t ntt_out_eval = ccpolyzp_po2cyc_eval_init_helper(ws, &dims, moduli, data_out_coeff);
            is(ccpolyzp_po2cyc_fwd_ntt(x_coeff), CCERR_OK, "test_fwd_ntt error");
            is(ccpolyzp_po2cyc_fwd_ntt(y_coeff), CCERR_OK, "test_fwd_ntt error");
            ccpolyzp_po2cyc_eval_mul(ntt_out_eval, (ccpolyzp_po2cyc_eval_const_t)x_coeff, (ccpolyzp_po2cyc_eval_const_t)y_coeff);
            is(ccpolyzp_po2cyc_inv_ntt(ntt_out_eval), CCERR_OK, "test_inv_ntt error");

            is(ccpolyzp_po2cyc_coeff_eq((ccpolyzp_po2cyc_coeff_const_t)ntt_out_eval, naive_out_coeff),
               true,
               "test_ntt multiplication matches schoolbook");
        }
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_divide_and_round_q_last(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // Single modulus
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 2, .nmoduli = 1 };
        ccrns_int moduli[] = { (1ULL << 60) - (1ULL << 18) + 1 };
        ccrns_int poly_data[] = { 2, 2 };

        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, poly_data);
        is(ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, poly),
           CCERR_PARAMETER,
           "ccpolyzp_po2cyc_divide_and_round_q_last single modulus");
    }
    // round to 0 in one case
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 2, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 13, 17 };
        ccrns_int poly_in_data[] = { 2, 2, 7, 2 }; // x = [41, 2]

        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 2, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 13 };
        ccrns_int poly_out_data[] = { 2, 0 }; // round(x/17) = [2, 0]

        ccpolyzp_po2cyc_coeff_t exp_poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_out, moduli_out, poly_out_data);
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_in, moduli_in, poly_in_data);
        is(ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, poly),
           CCERR_OK,
           "ccpolyzp_po2cyc_divide_and_round_q_last_ws != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, exp_poly), true, "ccpolyzp_po2cyc_divide_and_round_q_last round to zero");
    }
    // close rounding
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 2, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 13, 17 };
        ccrns_int poly_in_data[] = { 3, 4, 8, 9 }; // x = [42, 43]

        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 2, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 13 };
        // round(x / 17) = round([42/17, 43/17]) = round([2.47, 2.53]) = [2, 3]
        ccrns_int poly_out_data[] = { 2, 3 };
        ccpolyzp_po2cyc_coeff_t exp_poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_out, moduli_out, poly_out_data);
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_in, moduli_in, poly_in_data);
        is(ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, poly),
           CCERR_OK,
           "Error during ccpolyzp_po2cyc_divide_and_round_q_last_ws");
        is(ccpolyzp_po2cyc_coeff_eq(poly, exp_poly), true, "ccpolyzp_po2cyc_divide_and_round_q_last close rounding");
    }
    // 3 moduli
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 2, .nmoduli = 3 };
        ccrns_int moduli_in[] = { 13, 17, 29 };
        ccrns_int poly_in_data[] = { 12, 12, 8, 9, 25, 8 }; // x = [25, 298]

        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 2, .nmoduli = 2 };
        ccrns_int moduli_out[] = { 13, 17 };
        // round(x / 29) = round([25/29, 298/29]) = round(0.86, 10.28) = [1, 10]
        ccrns_int poly_out_data[] = { 1, 10, 1, 10 };
        ccpolyzp_po2cyc_coeff_t exp_poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_out, moduli_out, poly_out_data);
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_in, moduli_in, poly_in_data);
        is(ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, poly),
           CCERR_OK,
           "Error during ccpolyzp_po2cyc_divide_and_round_q_last_ws");
        is(ccpolyzp_po2cyc_coeff_eq(poly, exp_poly), true, "ccpolyzp_po2cyc_divide_and_round_q_last 3 moduli");
    }
    // large moduli
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 3 };
        ccrns_int moduli_in[] = { 68719403009, 68719230977, 137438822401 };
        // x = [2^30, 2^50, 2^70, 2^90]
        ccrns_int poly_in_data[] = { 1 << 30,     1207943168,  52898469889, 31593762561, 1 << 30,      4026515456,
                                     66638794753, 65212578818, 1 << 30,     1073733632,  129922621441, 121332752385 };

        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_out[] = { 68719403009, 68719230977 };

        // round(x / 137438822401) = [0, 8192, 8589942784, 9007207844618240]
        ccrns_int poly_out_data[] = { 0, 8192, 8589942784, 18253422592, 0, 8192, 8589942784, 40802000896 };
        ccpolyzp_po2cyc_coeff_t exp_poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_out, moduli_out, poly_out_data);
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_in, moduli_in, poly_in_data);
        is(ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, poly),
           CCERR_OK,
           "Error during ccpolyzp_po2cyc_divide_and_round_q_last_ws");
        is(ccpolyzp_po2cyc_coeff_eq(poly, exp_poly), true, "ccpolyzp_po2cyc_divide_and_round_q_last 3 large moduli");
    }
    // large moduli: q_L >> q_i
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 3 };
        ccrns_int moduli_in[] = {
            137438822401,
            68719403009,
            (1ULL << 60) - (1ULL << 18) + 1,
        };
        // x = [2^30, 2^50, 2^70, 2^90]
        ccrns_int poly_in_data[] = { 1073741824,  1073733632,  129922621441, 121332752385,     1073741824, 1207943168,
                                     52898469889, 31593762561, 1073741824,   1125899906842624, 268434432,  281473902968832 };

        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_out[] = { 137438822401, 68719403009 };

        // round(x / 137438822401) = [0, 0, 1024, 1073741824]
        ccrns_int poly_out_data[] = { 0, 0, 1024, 1073741824, 0, 0, 1024, 1073741824 };
        ccpolyzp_po2cyc_coeff_t exp_poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_out, moduli_out, poly_out_data);
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_in, moduli_in, poly_in_data);
        int rv = ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, poly);
        is(rv, CCERR_OK, "Error during ccpolyzp_po2cyc_divide_and_round_q_last_ws");
        is(ccpolyzp_po2cyc_coeff_eq(poly, exp_poly), true, "ccpolyzp_po2cyc_divide_and_round_q_last 3 large moduli (q_L >> q_i");
    }

    CC_FREE_WORKSPACE(ws);
}

int ccpolyzp_po2cyc_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int ntests = 6576;
#if CORECRYPTO_DEBUG
    ntests += 1;
#endif
    plan_tests(ntests);

    // ccpolyzp_po2cyc_ctx
    test_ccpolyzp_po2cyc_ctx_init();
    test_ccpolyzp_po2cyc_ctx_chain_init();
    test_ccpolyzp_po2cyc_ctx_eq();
    test_ccpolyzp_po2cyc_ctx_q_prod_ws();
    test_ccpolyzp_po2cyc_compute_variance();

    // ccpolyzp_po2cyc
    test_ccpolyzp_po2cyc_init();
    test_ccpolyzp_po2cyc_init_zero();
    test_ccpolyzp_po2cyc_rns_int_convert();
    test_ccpolyzp_po2cyc_eq();
    test_ccpolyzp_po2cyc_negate();
    test_ccpolyzp_po2cyc_add();
    test_ccpolyzp_po2cyc_sub();
    test_ccpolyzp_po2cyc_mul();
    test_ccpolyzp_po2cyc_coeff_scalar_mul();
    test_ccpolyzp_po2cyc_ntt();
    test_ccpolyzp_po2cyc_divide_and_round_q_last();
    test_ccpolyzp_po2cyc_random();
    test_ccpolyzp_po2cyc_serialization();
    test_ccpolyzp_po2cyc_base_convert();
    test_ccpolyzp_po2cyc_galois();
    test_ccpolyzp_po2cyc_scalar();

    return 0;
}
