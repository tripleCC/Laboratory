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

#include "ccperf.h"
#include <corecrypto/ccrng.h>
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_random.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"

#define MODULUS_60_BIT 1152921504606584833

const ccrns_int perf_moduli[] = { MODULUS_60_BIT };

/// Returns a uniform random number in [0, max - 1].
static ccrns_int rns_int_uniform(ccrns_int max)
{
    ccrns_int result;
    ccrng_uniform(rng, max, &result);
    return result;
}

/// Initializes data with uniform random numbers
static void ccpolyzp_po2cyc_data_init_random(ccrns_int *coefficients, ccpolyzp_po2cyc_ctx_const_t ctx)
{
    for (uint32_t rns_idx = 0; rns_idx < ctx->dims.nmoduli; ++rns_idx) {
        ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(ctx, rns_idx);
        for (uint32_t coeff_idx = 0; coeff_idx < ctx->dims.degree; ++coeff_idx) {
            coefficients[ctx->dims.degree * rns_idx + coeff_idx] = rns_int_uniform(modulus - 1);
        }
    }
}

/// Initializes a ccpolyzp_po2cyc_coeff_t with uniform random elements
static ccpolyzp_po2cyc_coeff_t
ccpolyzp_po2cyc_coeff_init_random_ws(struct cc_ws *ws, ccpolyzp_po2cyc_dims_const_t dims, const ccrns_int *moduli)
{
    ccpolyzp_po2cyc_ctx_chain_t ctx_chain = CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, dims);
    if (ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, dims, moduli) != CCERR_OK) {
        abort();
    }
    ccpolyzp_po2cyc_ctx_t ctx = ccpolyzp_po2cyc_ctx_chain_context(ctx_chain, dims->nmoduli);
    ccrns_int coefficients[dims->degree * dims->nmoduli];
    ccpolyzp_po2cyc_data_init_random(coefficients, ctx);

    ccpolyzp_po2cyc_t poly = CCPOLYZP_PO2CYC_ALLOC_WS(ws, dims);
    if (ccpolyzp_po2cyc_init(poly, ctx, (const ccrns_int *)coefficients) != CCERR_OK) {
        abort();
    }

    return (ccpolyzp_po2cyc_coeff_t)poly;
}

/// Initializes a ccpolyzp_po2cyc_eval_t with uniform random elements
/// Note, using struct cc_ws avoids generating workspace headers
static ccpolyzp_po2cyc_eval_t
ccpolyzp_po2cyc_eval_init_random_ws(struct cc_ws *ws, ccpolyzp_po2cyc_dims_const_t dims, const ccrns_int *moduli)
{
    return (ccpolyzp_po2cyc_eval_t)ccpolyzp_po2cyc_coeff_init_random_ws(ws, dims, moduli);
}

static double perf_ccpolyzp_po2cyc_ctx_init_ws(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_ctx_t context = CCPOLYZP_PO2CYC_CTX_ALLOC_WS(ws, degree);
    perf_start();
    do {
        if (ccpolyzp_po2cyc_ctx_init_ws(ws, context, &dims, perf_moduli, NULL) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_init(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_ctx_t context = CCPOLYZP_PO2CYC_CTX_ALLOC_WS(ws, degree);
    if (ccpolyzp_po2cyc_ctx_init_ws(ws, context, &dims, perf_moduli, NULL) != CCERR_OK) {
        abort();
    }

    ccrns_int coefficients[dims.degree * dims.nmoduli];
    ccpolyzp_po2cyc_data_init_random(coefficients, context);

    ccpolyzp_po2cyc_t poly = CCPOLYZP_PO2CYC_ALLOC_WS(ws, &dims);

    perf_start();
    do {
        if (ccpolyzp_po2cyc_init(poly, context, coefficients) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_eval_negate(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_eval_t poly = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);

    perf_start();
    do {
        ccpolyzp_po2cyc_eval_negate(poly, poly);
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

#define CCPOLYZP_PO2CYC_N_PERF_FUNCTION_EVAL_X_Y(func)                                                 \
    static double perf_##func(size_t loops, uint32_t degree)                                           \
    {                                                                                                  \
        CC_DECL_WORKSPACE_TEST(ws);                                                                    \
        struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) }; \
        ccpolyzp_po2cyc_eval_t x = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);        \
        ccpolyzp_po2cyc_eval_t y = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);        \
        perf_start();                                                                                  \
        do                                                                                             \
            (void)func(x, x, y);                                                                       \
        while (--loops != 0);                                                                          \
        double perf_res = perf_seconds();                                                              \
        CC_FREE_WORKSPACE(ws);                                                                         \
        return perf_res;                                                                               \
    }

CCPOLYZP_PO2CYC_N_PERF_FUNCTION_EVAL_X_Y(ccpolyzp_po2cyc_eval_add)
CCPOLYZP_PO2CYC_N_PERF_FUNCTION_EVAL_X_Y(ccpolyzp_po2cyc_eval_sub)
CCPOLYZP_PO2CYC_N_PERF_FUNCTION_EVAL_X_Y(ccpolyzp_po2cyc_eval_mul)

static double perf_ccpolyzp_po2cyc_fwd_ntt(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_random_ws(ws, &dims, perf_moduli);

    perf_start();
    do {
        (void)ccpolyzp_po2cyc_fwd_ntt(poly);
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_inv_ntt(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_eval_t poly = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);

    perf_start();
    do {
        (void)ccpolyzp_po2cyc_inv_ntt(poly);
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_eval_scalar_mul_ws(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_eval_t poly = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);
    ccrns_int scalar[CC_ARRAY_LEN(perf_moduli)];
    for (uint32_t i = 0; i < CC_ARRAY_LEN(perf_moduli); ++i) {
        scalar[i] = rns_int_uniform(perf_moduli[i]);
    }

    perf_start();
    do {
        ccpolyzp_po2cyc_eval_scalar_mul_ws(ws, poly, poly, scalar);
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_divide_and_round_q_last_ws(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccrns_int moduli[] = {
        1152921504606830593ULL,
        perf_moduli[0],
    };

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(moduli) };
    ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_random_ws(ws, &dims, moduli);
    ccpolyzp_po2cyc_ctx_const_t top_context = poly->context;
    perf_start();
    do {
        if (ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, poly) != CCERR_OK) {
            abort();
        }
        poly->context = top_context;
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_random_uniform(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_eval_t poly = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);

    perf_start();
    do {
        (void)ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_random_cbd_ws(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_eval_t poly = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);

    perf_start();
    do {
        (void)ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly, rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2);
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

static double perf_ccpolyzp_po2cyc_random_ternary_ws(size_t loops, uint32_t degree)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = CC_ARRAY_LEN(perf_moduli) };
    ccpolyzp_po2cyc_eval_t poly = ccpolyzp_po2cyc_eval_init_random_ws(ws, &dims, perf_moduli);

    perf_start();
    do {
        (void)ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
    } while (--loops != 0);
    double perf_res = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return perf_res;
}

#define _TEST(_x, _q)                          \
    {                                          \
        .name = #_x "_" #_q, .func = perf_##_x \
    }

static struct ccpolyzp_po2cyc_perf_test {
    const char *name;
    double (*func)(size_t loops, uint32_t degree);
} ccpolyzp_po2cyc_perf_tests[] = { _TEST(ccpolyzp_po2cyc_init, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_ctx_init_ws, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_eval_negate, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_eval_add, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_eval_sub, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_eval_mul, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_eval_scalar_mul_ws, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_fwd_ntt, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_inv_ntt, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_divide_and_round_q_last_ws, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_random_uniform, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_random_cbd_ws, MODULUS_60_BIT),
                                   _TEST(ccpolyzp_po2cyc_random_ternary_ws, MODULUS_60_BIT) };

static double perf_ccpolyzp_po2cyc(size_t loops, size_t *psize, const void *arg)
{
    const struct ccpolyzp_po2cyc_perf_test *test = arg;
    return test->func(loops, (uint32_t)*psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccpolyzp_po2cyc(int argc, char *argv[])
{
    F_GET_ALL(family, ccpolyzp_po2cyc);
    static const size_t group_degrees[] = { 4096, 8192 };
    F_SIZES_FROM_ARRAY(family, group_degrees);
    family.size_kind = ccperf_size_units;
    return &family;
}
