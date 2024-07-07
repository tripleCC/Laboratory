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

#include "crypto_test_ccpolyzp_po2cyc.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "ccpolyzp_po2cyc_base_convert.h"
#include "ccpolyzp_po2cyc_random.h"
#include "ccrng.h"
#include "testmore.h"
#include "testccnBuffer.h"

static void test_ccpolyzp_po2cyc_base_convert_init_errors(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // Different degrees
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 3 };
        ccrns_int moduli_in[] = { 13, 29, 41 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 2, .nmoduli = 2 };
        ccrns_int moduli_out[] = { 13, 29 };

        ccpolyzp_po2cyc_ctx_const_t ctx_in = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_in, moduli_in);
        ccpolyzp_po2cyc_ctx_const_t ctx_out = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_out, moduli_out);

        ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
        is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
           CCERR_PARAMETER,
           "test_ccpolyzp_po2cyc_base_convert_init_errors different degrees");
    }
    // modulus co-prime to gamma
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 3 };
        ccrns_int moduli_in[] = { CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA, 29, 41 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 2, .nmoduli = 2 };
        ccrns_int moduli_out[] = { 13, 29 };

        ccpolyzp_po2cyc_ctx_const_t ctx_in = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_in, moduli_in);
        ccpolyzp_po2cyc_ctx_const_t ctx_out = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_out, moduli_out);

        ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
        is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
           CCERR_PARAMETER,
           "test_ccpolyzp_po2cyc_base_convert_init_errors q not co-prime to gamma");
    }

    CC_FREE_WORKSPACE(ws);
}

CC_NONNULL_ALL static void test_ccpolyzp_po2cyc_base_convert_init_helper_ws(cc_ws_t ws,
                                                                            uint32_t nmoduli_in,
                                                                            const ccrns_int *cc_counted_by(nmoduli_in) moduli_in,
                                                                            uint32_t nmoduli_out,
                                                                            const ccrns_int *cc_counted_by(nmoduli_out)
                                                                                moduli_out,
                                                                            const ccrns_int *exp_punc_prods,
                                                                            const ccrns_int *cc_counted_by(nmoduli_in)
                                                                                exp_inv_punc_prods,
                                                                            ccrns_int q_mod_t0)
{
    // Use arbitrary degree
    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 1, .nmoduli = nmoduli_in };
    struct ccpolyzp_po2cyc_dims dims_out = { .degree = 1, .nmoduli = nmoduli_out };

    ccpolyzp_po2cyc_ctx_const_t ctx_in = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_out = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_out, moduli_out);

    ccrns_int q_last = moduli_in[nmoduli_in - 1];

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_init_helper error");

    for (uint32_t rns_idx_in = 0; rns_idx_in < nmoduli_in; ++rns_idx_in) {
        ccrns_int exp_inv_punc_prod = exp_inv_punc_prods[rns_idx_in];

        // check inverse punctured products
        {
            ccrns_mul_modulus_const_t inv_punc_prod = ccpolyzp_po2cyc_base_convert_inv_punc_prod_const(base_cvt, rns_idx_in);
            is(inv_punc_prod->multiplicand,
               exp_inv_punc_prod,
               "cpolyzp_po2cyc_base_convert_init inv_punc_prod_const[%" PRIu32 "] mismatch",
               rns_idx_in);
            is(inv_punc_prod->modulus,
               moduli_in[rns_idx_in],
               "cpolyzp_po2cyc_base_convert_init inv_punc_prod_const[%" PRIu32 "] mismatch",
               rns_idx_in);
        }
        {
            ccrns_mul_modulus_const_t inv_punc_prod = ccpolyzp_po2cyc_base_convert_inv_punc_prod(base_cvt, rns_idx_in);
            is(inv_punc_prod->multiplicand,
               exp_inv_punc_prod,
               "ccpolyzp_po2cyc_base_convert_init inv_punc_prod[%" PRIu32 "] mismatch",
               rns_idx_in);
            is(inv_punc_prod->modulus,
               moduli_in[rns_idx_in],
               "cpolyzp_po2cyc_base_convert_init inv_punc_prod[%" PRIu32 "] mismatch",
               rns_idx_in);
        }
        // check punctured products
        for (uint32_t rns_idx_out = 0; rns_idx_out < nmoduli_out; ++rns_idx_out) {
            ccrns_int exp_punc_prod = *exp_punc_prods++;
            {
                ccrns_mul_modulus_const_t punc_prod =
                    ccpolyzp_po2cyc_base_convert_punc_prod_const(base_cvt, rns_idx_in, rns_idx_out);
                is(punc_prod->multiplicand,
                   exp_punc_prod,
                   "cpolyzp_po2cyc_base_convert_init punc_prod_const[%" PRIu32 ", %" PRIu32 "] multiplicand mismatch",
                   rns_idx_in,
                   rns_idx_out);
                is(punc_prod->modulus,
                   moduli_out[rns_idx_out],
                   "cpolyzp_po2cyc_base_convert_init punc_prod_const[%" PRIu32 ", %" PRIu32 "] multiplicand mismatch",
                   rns_idx_in,
                   rns_idx_out);
            }
            {
                ccrns_mul_modulus_t punc_prod = ccpolyzp_po2cyc_base_convert_punc_prod(base_cvt, rns_idx_in, rns_idx_out);
                is(punc_prod->multiplicand,
                   exp_punc_prod,
                   "cpolyzp_po2cyc_base_convert_init punc_prod_const[%" PRIu32 ", %" PRIu32 "] multiplicand mismatch",
                   rns_idx_in,
                   rns_idx_out);
                is(punc_prod->modulus,
                   moduli_out[rns_idx_out],
                   "cpolyzp_po2cyc_base_convert_init punc_prod_const[%" PRIu32 ", %" PRIu32 "] multiplicand mismatch",
                   rns_idx_in,
                   rns_idx_out);
            }
        }

        if (rns_idx_in < nmoduli_in - 1) {
            ccrns_int qi = moduli_in[rns_idx_in];
            // ccpolyzp_po2cyc_base_convert_q_last_mod_qi / ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi
            {
                ccrns_mul_modulus_t q_last_mod_qi = ccpolyzp_po2cyc_base_convert_q_last_mod_qi(base_cvt, rns_idx_in);
                is(q_last_mod_qi->modulus, qi, "ccpolyzp_po2cyc_base_convert_q_last_mod_qi->modulus");
                is(q_last_mod_qi->multiplicand, q_last % qi, "ccpolyzp_po2cyc_base_convert_q_last_mod_qi->multiplicand");
            }
            {
                ccrns_mul_modulus_const_t q_last_mod_qi = ccpolyzp_po2cyc_base_convert_q_last_mod_qi_const(base_cvt, rns_idx_in);
                is(q_last_mod_qi->modulus, qi, "ccpolyzp_po2cyc_base_convert_q_last_mod_qi_const->modulus");
                is(q_last_mod_qi->multiplicand, q_last % qi, "ccpolyzp_po2cyc_base_convert_q_last_mod_qi_const->multiplicand");
            }
            {
                ccrns_mul_modulus_t inv_q_last_mod_qi = ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi(base_cvt, rns_idx_in);
                is(inv_q_last_mod_qi->modulus, qi, "ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi->modulus");
                is(ccpolyzp_po2cyc_scalar_shoup_mul_mod(q_last, inv_q_last_mod_qi),
                   1,
                   "cpolyzp_po2cyc_base_convert_init inv_q_last_mod_qi.multiplicand");
            }
            {
                ccrns_mul_modulus_const_t inv_q_last_mod_qi =
                    ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi_const(base_cvt, rns_idx_in);
                is(inv_q_last_mod_qi->modulus, qi, "ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi_const->modulus");
                is(ccpolyzp_po2cyc_scalar_shoup_mul_mod(q_last, inv_q_last_mod_qi),
                   1,
                   "cpolyzp_po2cyc_base_convert_init inv_q_last_mod_qi_const.multiplicand");
            }
        }
    }

    // check q_mod_t0
    is(base_cvt->q_mod_t0.multiplicand, q_mod_t0, "cpolyzp_po2cyc_base_convert_init q_mod_t0.multiplicand");
    is(base_cvt->q_mod_t0.modulus, moduli_out[0], "cpolyzp_po2cyc_base_convert_init q_mod_t0.modulus");

    // check inv_q_last_mod_t
    is(ccpolyzp_po2cyc_scalar_shoup_mul_mod(q_last, &base_cvt->inv_q_last_mod_t),
       1,
       "cpolyzp_po2cyc_base_convert_init inv_q_last_mod_t.multiplicand");
    is(base_cvt->inv_q_last_mod_t.modulus, moduli_out[0], "cpolyzp_po2cyc_base_convert_init inv_q_last_mod_t.modulus");
}

static void test_ccpolyzp_po2cyc_base_convert_init(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccrns_int q0 = (1ULL << 60) - 93;
    ccrns_int q1 = (1ULL << 60) - 173;
    ccrns_int q2 = (1ULL << 60) - 257;

    // sub-base
    {
        ccrns_int moduli_in[] = { q0, q1, q2 };
        ccrns_int moduli_out[] = { q0, q1 };
        uint32_t nmoduli_in = CC_ARRAY_LEN(moduli_in);
        uint32_t nmoduli_out = CC_ARRAY_LEN(moduli_out);

        ccrns_int exp_punc_prods[] = { 13120, 0, 0, 1152921504606840083ULL, 0, 0 };
        ccrns_int exp_inv_punc_prods[] = { 60897454473517141ULL, 224236370018028091ULL, 867787680115301512ULL };
        ccrns_int q_mod_t0 = 0;
        test_ccpolyzp_po2cyc_base_convert_init_helper_ws(
            ws, nmoduli_in, moduli_in, nmoduli_out, moduli_out, exp_punc_prods, exp_inv_punc_prods, q_mod_t0);
    }
    // small co-prime base
    {
        ccrns_int moduli_in[] = { 17, 29, 31 };
        ccrns_int moduli_out[] = { 23, 41 };
        uint32_t nmoduli_in = CC_ARRAY_LEN(moduli_in);
        uint32_t nmoduli_out = CC_ARRAY_LEN(moduli_out);

        ccrns_int exp_punc_prods[] = { 2, 38, 21, 35, 10, 1 };
        ccrns_int exp_inv_punc_prods[] = { 8, 6, 10 };
        ccrns_int q_mod_t0 = 11;
        test_ccpolyzp_po2cyc_base_convert_init_helper_ws(
            ws, nmoduli_in, moduli_in, nmoduli_out, moduli_out, exp_punc_prods, exp_inv_punc_prods, q_mod_t0);
    }
    // big co-prime base
    {
        ccrns_int t0 = (1ULL << 60) - 107;
        ccrns_int t1 = (1ULL << 60) - 179;

        ccrns_int moduli_in[] = { q0, q1, q2 };
        ccrns_int moduli_out[] = { t0, t1 };
        uint32_t nmoduli_in = CC_ARRAY_LEN(moduli_in);
        uint32_t nmoduli_out = CC_ARRAY_LEN(moduli_out);

        ccrns_int exp_punc_prods[] = {
            9900, 1152921504606846329ULL, 1152921504606844769ULL, 1152921504606840089ULL, 1152921504606845945, 516
        };
        ccrns_int exp_inv_punc_prods[] = { 60897454473517141ULL, 224236370018028091ULL, 867787680115301512ULL };
        ccrns_int q_mod_t0 = 138600;
        test_ccpolyzp_po2cyc_base_convert_init_helper_ws(
            ws, nmoduli_in, moduli_in, nmoduli_out, moduli_out, exp_punc_prods, exp_inv_punc_prods, q_mod_t0);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_poly_errors(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli_in[] = { 17, 41 };
    struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 1 };
    ccrns_int moduli_out[] = { 17 };

    ccpolyzp_po2cyc_ctx_const_t ctx_in = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_out = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_out, moduli_out);

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_out, moduli_out);

    // okay
    {
        is(ccpolyzp_po2cyc_base_convert_poly_ws(ws, poly_out, poly_in, base_cvt),
           CCERR_OK,
           "ccpolyzp_po2cyc_base_convert_poly_ws != CCERR_OK");
    }
    // wrong input context
    {
        is(ccpolyzp_po2cyc_base_convert_poly_ws(ws, poly_out, poly_out, base_cvt),
           CCERR_PARAMETER,
           "test_ccpolyzp_po2cyc_base_convert_poly_errors wrong input context");
    }
    // wrong output context
    {
        is(ccpolyzp_po2cyc_base_convert_poly_ws(ws, poly_in, poly_in, base_cvt),
           CCERR_PARAMETER,
           "test_ccpolyzp_po2cyc_base_convert_poly_errors wrong output context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_poly_helper(cc_ws_t ws,
                                                          ccpolyzp_po2cyc_dims_const_t dims_in,
                                                          const ccrns_int *moduli_in,
                                                          ccpolyzp_po2cyc_dims_const_t dims_out,
                                                          const ccrns_int *moduli_out,
                                                          const ccrns_int *data_in,
                                                          const ccrns_int *exp_data_out,
                                                          const char *test_name)
{
    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_helper(ws, dims_in, moduli_in, data_in);
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, dims_out, moduli_out);
    ccpolyzp_po2cyc_coeff_t exp_poly_out = ccpolyzp_po2cyc_coeff_init_helper(ws, dims_out, moduli_out, exp_data_out);

    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;
    ccpolyzp_po2cyc_ctx_const_t ctx_out = poly_out->context;
    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in->nmoduli, dims_out->nmoduli);

    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "%s ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK",
       test_name);

    is(ccpolyzp_po2cyc_base_convert_poly_ws(ws, poly_out, poly_in, base_cvt),
       CCERR_OK,
       " %s ccpolyzp_po2cyc_base_convert_poly_ws != CCERR_OK",
       test_name);

    is(ccpolyzp_po2cyc_coeff_eq(exp_poly_out, poly_out), true, "%s", test_name);
}

static void test_ccpolyzp_po2cyc_base_convert_poly_simple(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // trivial, no base conversion L=1
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli_in[] = { 3 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 3 };
        ccrns_int x_data[] = { 0, 1, 2, 0 };
        ccrns_int exp_data[] = { 0, 1, 2, 0 };
        const char *test_name = "test_ccpolyzp_po2cyc_base_convert_poly trivial L=1";
        test_ccpolyzp_po2cyc_base_convert_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, test_name);
    }
    // trivial, no base conversion L=2
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 17, 29 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_out[] = { 17, 29 };
        ccrns_int x_data[] = { 16, 15, 14, 13, 28, 27, 26, 25 };
        ccrns_int exp_data[] = { 16, 15, 14, 13, 28, 27, 26, 25 };
        const char *test_name = "test_ccpolyzp_po2cyc_base_convert_poly trivial L=2";
        test_ccpolyzp_po2cyc_base_convert_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, test_name);
    }
    // convert to sub-base
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 17, 41 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 17 };
        ccrns_int x_data[] = { 13, 14, 15, 16, 25, 26, 27, 28 };
        ccrns_int exp_data[] = { 13, 14, 15, 16 };
        test_ccpolyzp_po2cyc_base_convert_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, "test_ccpolyzp_po2cyc_base_convert_poly sub-base");
    }
    // convert to co-prime base
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 2, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 29, 41 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 2, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 17 };
        ccrns_int x_data[] = { 1, 0, 4, 2 };
        ccrns_int exp_data[] = { 1, 0 };
        const char *test_name = "test_ccpolyzp_po2cyc_base_convert_poly co-prime base";
        test_ccpolyzp_po2cyc_base_convert_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, test_name);
    }
    // convert to extended base base
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 17, 29 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 3 };
        ccrns_int moduli_out[] = { 17, 29, 41 };
        ccrns_int x_data[] = { 0, 0, 1, 3, 2, 2, 4, 5 };
        ccrns_int exp_data[] = { 0, 0, 1, 3, 2, 2, 4, 5, 39, 39, 39, 1 };
        const char *test_name = "test_ccpolyzp_po2cyc_base_convert_poly extended sub-base";
        test_ccpolyzp_po2cyc_base_convert_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, test_name);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_poly_random_helper(uint32_t nmoduli_in,
                                                                 const ccrns_int *cc_counted_by(nmoduli_in) moduli_in,
                                                                 ccrns_int modulus_out,
                                                                 const char *test_name)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 128, .nmoduli = nmoduli_in };
    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;

    struct ccpolyzp_po2cyc_dims dims_out = { .degree = dims_in.degree, .nmoduli = 1 };
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_out, &modulus_out);
    ccpolyzp_po2cyc_ctx_const_t ctx_out = poly_out->context;

    // compute the entire product q
    cc_size q_prod_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(ctx_in->dims.nmoduli);
    cc_unit *q_prod = CC_ALLOC_WS(ws, q_prod_max_nunits);
    ccpolyzp_po2cyc_ctx_q_prod_ws(ws, q_prod, ctx_in);
    cc_size q_prod_nunits = ccn_n(q_prod_max_nunits, q_prod);
    cc_size q_bits = ccn_bitsof_n(q_prod_nunits);
    cc_size q_bytes = ccn_sizeof_n(q_prod_nunits);

    // create q modulus
    cczp_t q_zp = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(q_prod_nunits));
    CCZP_N(q_zp) = q_prod_nunits;
    ccn_set(q_prod_nunits, q_zp->ccn, q_prod);
    is(cczp_init_ws(ws, q_zp), CCERR_OK, "Error initializing q_zp");

    // x[i * ccn_nof(q_bits)] is the i'th coefficient in bigint form
    cc_unit *x = CC_ALLOC_WS(ws, dims_in.degree * ccn_nof(q_bits));
    struct ccrng_state *rng = global_test_rng;
    for (uint32_t coeff_idx = 0; coeff_idx < dims_in.degree; ++coeff_idx) {
        cc_unit *x_units = &x[coeff_idx * ccn_nof(q_bits)];
        // Sample almost uniform random element x from [0, q - 1]
        is(ccrng_generate(rng, q_bytes, x_units), CCERR_OK, "ccrng_generate != CCERR_OK");
        cczp_modn_ws(ws, q_zp, x_units, ccn_nof(q_bits), x_units);

        // Compute x mod q_i
        for (uint32_t rns_idx = 0; rns_idx < nmoduli_in; ++rns_idx) {
            cc_unit *poly_in_data = CCPOLYZP_PO2CYC_DATA(poly_in, rns_idx, coeff_idx);
            cczp_const_t q_i = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_in, rns_idx);
            cczp_modn_ws(ws, q_i, poly_in_data, ccn_nof(q_bits), x_units);
        }
    }

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "L_IN=%" PRIu32 " ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK",
       nmoduli_in);
    is(ccpolyzp_po2cyc_base_convert_poly_ws(ws, poly_out, poly_in, base_cvt),
       CCERR_OK,
       "L_IN=%" PRIu32 " ccpolyzp_po2cyc_base_convert_poly_ws != CCERR_OK",
       nmoduli_in);

    // poly_out_coeff = (x + a_x * q) mod t for a_x in [0, nmoduli_in - 1]
    // try to recover exact x
    bool recovered_all_x = true;
    for (uint32_t coeff_idx = 0; coeff_idx < dims_in.degree; ++coeff_idx) {
        const cc_unit *x_coeff = &x[coeff_idx * ccn_nof(q_bits)];
        const cc_unit *out_data = CCPOLYZP_PO2CYC_DATA_CONST(poly_out, 0, coeff_idx);
        ccrns_int poly_out_coeff = ccpolyzp_po2cyc_units_to_rns_int(out_data);
        cczp_const_t t = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_out, 0);

        bool recovered_x = false;
        for (uint32_t rns_idx = 0; rns_idx < nmoduli_in; ++rns_idx) {
            cc_size x_plus_ax_times_q_nunits = 2 * q_prod_nunits + 1;
            cc_unit x_plus_ax_times_q[x_plus_ax_times_q_nunits];
            ccn_clear(x_plus_ax_times_q_nunits, x_plus_ax_times_q);
            cc_unit big_ax[q_prod_nunits];
            ccn_seti(q_prod_nunits, big_ax, rns_idx);

            ccn_mul_ws(ws, q_prod_nunits, x_plus_ax_times_q, q_prod, big_ax);
            ccn_addn(x_plus_ax_times_q_nunits, x_plus_ax_times_q, x_plus_ax_times_q, ccn_nof(q_bits), x_coeff);

            cc_unit possible_x_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            cczp_modn_ws(ws, t, possible_x_units, x_plus_ax_times_q_nunits, x_plus_ax_times_q);

            ccrns_int possible_x = ccpolyzp_po2cyc_units_to_rns_int(possible_x_units);
            if (possible_x == poly_out_coeff) {
                recovered_x = true;
                break;
            }
        }
        if (!recovered_x) {
            recovered_all_x = false;
            break;
        }
    }
    is(recovered_all_x, true, "test_ccpolyzp_po2cyc_base_convert_poly_random %s failed to recover x", test_name);

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_poly_random(void)
{
    // 20-bit moduli
    {
        ccrns_int moduli_in[] = { 557057, 575489, 577537 };
        test_ccpolyzp_po2cyc_base_convert_poly_random_helper(3, moduli_in, 534529, "3 20-bit moduli");
    }
    // 40-bit moduli
    {
        ccrns_int moduli_in[] = { 549755873281ULL, 549755904001ULL, 549755932673ULL };
        test_ccpolyzp_po2cyc_base_convert_poly_random_helper(3, moduli_in, 549755860993ULL, "3 40-bit moduli");
    }
    // 60-bit moduli
    {
        ccrns_int moduli_in[] = { 576460752303439873ULL, 576460752303476737ULL };
        test_ccpolyzp_po2cyc_base_convert_poly_random_helper(2, moduli_in, 576460752303568897ULL, "2 60-bit moduli");
    }
    // 61-bit moduli
    {
        ccrns_int moduli_in[] = { 1152921504606902273ULL, 1152921504606965761ULL, 1152921504606904321ULL };
        test_ccpolyzp_po2cyc_base_convert_poly_random_helper(3, moduli_in, 1152921504606902273ULL, "3 61-bit moduli");
    }
    // mix of moduli
    {
        ccrns_int moduli_in[] = { 534529ULL, 549755860993ULL, 576460752303476737ULL, 575489ULL, 1152921504606904321ULL };
        test_ccpolyzp_po2cyc_base_convert_poly_random_helper(5, moduli_in, 1152921504606902273ULL, "5 mixed moduli");
    }
}

static void test_ccpolyzp_po2cyc_base_convert_exact_poly_errors(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    // nout_moduli > 1
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 3 };
        ccrns_int moduli_in[] = { 17, 23, 41 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_out[] = { 17, 23 };
        ccpolyzp_po2cyc_ctx_const_t ctx_in = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_in, moduli_in);
        ccpolyzp_po2cyc_ctx_const_t ctx_out = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_out, moduli_out);

        ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
        is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
           CCERR_OK,
           "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

        ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_in, moduli_in);
        ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_out, moduli_out);

        // Approximate base conversion ok
        is(ccpolyzp_po2cyc_base_convert_poly_ws(ws, poly_out, poly_in, base_cvt),
           CCERR_OK,
           "ccpolyzp_po2cyc_base_convert_poly_ws != CCERR_OK");

        is(ccpolyzp_po2cyc_base_convert_exact_poly_ws(ws, poly_out, poly_in, base_cvt),
           CCERR_PARAMETER,
           "ccpolyzp_po2cyc_base_convert_exact_poly_ws > 1 nout_moduli");
    }

    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli_in[] = { 17, 41 };
    struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 1 };
    ccrns_int moduli_out[] = { 17 };

    ccpolyzp_po2cyc_ctx_const_t ctx_in = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_out = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_out, moduli_out);

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_out, moduli_out);

    // okay
    {
        is(ccpolyzp_po2cyc_base_convert_exact_poly_ws(ws, poly_out, poly_in, base_cvt),
           CCERR_OK,
           "ccpolyzp_po2cyc_base_convert_exact_poly_ws != CCERR_OK");
    }
    // wrong input context
    {
        is(ccpolyzp_po2cyc_base_convert_exact_poly_ws(ws, poly_out, poly_out, base_cvt),
           CCERR_PARAMETER,
           "ccpolyzp_po2cyc_base_convert_exact_poly_ws wrong input context");
    }
    // wrong output context
    {
        is(ccpolyzp_po2cyc_base_convert_exact_poly_ws(ws, poly_in, poly_in, base_cvt),
           CCERR_PARAMETER,
           "ccpolyzp_po2cyc_base_convert_exact_poly_ws wrong output context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_exact_poly_helper(cc_ws_t ws,
                                                                ccpolyzp_po2cyc_dims_const_t dims_in,
                                                                const ccrns_int *moduli_in,
                                                                ccpolyzp_po2cyc_dims_const_t dims_out,
                                                                const ccrns_int *moduli_out,
                                                                const ccrns_int *data_in,
                                                                const ccrns_int *exp_data_out,
                                                                const char *test_name)
{
    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_helper(ws, dims_in, moduli_in, data_in);
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, dims_out, moduli_out);
    ccpolyzp_po2cyc_coeff_t exp_poly_out = ccpolyzp_po2cyc_coeff_init_helper(ws, dims_out, moduli_out, exp_data_out);

    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;
    ccpolyzp_po2cyc_ctx_const_t ctx_out = poly_out->context;
    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in->nmoduli, dims_out->nmoduli);

    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "%s ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK",
       test_name);

    is(ccpolyzp_po2cyc_base_convert_exact_poly_ws(ws, poly_out, poly_in, base_cvt),
       CCERR_OK,
       " %s ccpolyzp_po2cyc_base_convert_exact_poly_ws != CCERR_OK",
       test_name);

    is(ccpolyzp_po2cyc_coeff_eq(exp_poly_out, poly_out), true, "%s", test_name);
}

static void test_ccpolyzp_po2cyc_base_convert_exact_poly_simple(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    // 2 small moduli
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 19, 23 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 17 };
        ccrns_int x_data[] = { 4, 11, 18, 6, 8, 4, 20, 9 };
        ccrns_int exp_data[] = { 2, 3, 11, 16 };
        const char *test_name = "test_ccpolyzp_po2cyc_base_convert_exact_poly L=2 small";
        test_ccpolyzp_po2cyc_base_convert_exact_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, test_name);
    }
    // 2 40-bit moduli
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 8, .nmoduli = 2 };
        ccrns_int moduli_in[] = { 549755813927, 549755813933 };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 8, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 549755813911 };
        ccrns_int x_data[] = { 254214216418, 246569320229, 260953636675, 453771295098, 127369132888, 441500051754,
                               123180445633, 364769066626, 77369979215,  450885200634, 476413172159, 431365495836,
                               86947970415,  377088307954, 261683354562, 279442548348 };
        ccrns_int exp_data[] = { 359294972960, 434734724305, 419402627383, 513520093130,
                                 51906961571,  246760826064, 120343231155, 409054510613 };
        const char *test_name = "test_ccpolyzp_po2cyc_base_convert_exact_poly L=2 40-bit moduli";
        test_ccpolyzp_po2cyc_base_convert_exact_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, test_name);
    }
    // 5 60-bit moduli
    {
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 8, .nmoduli = 5 };
        ccrns_int moduli_in[] = {
            576460752303423649, 576460752303423733, 576460752303423737, 576460752303423749, 576460752303423761,
        };
        struct ccpolyzp_po2cyc_dims dims_out = { .degree = 8, .nmoduli = 1 };
        ccrns_int moduli_out[] = { 576460752303423619 };
        ccrns_int x_data[] = {
            388150169918110712, 143993161067869806, 372685006932667930, 111945855071753681, 84476119179875433,
            449202671174794531, 385140956973803306, 458757070902013285, 404011482664744722, 514573294025707366,
            499192517278062458, 115004338862697907, 40591184113895807,  201226157063677470, 101998303301802911,
            322231563704408055, 127443039608587519, 367576534619495029, 76795256238247195,  292605367185749641,
            106045776967268035, 11188534507554100,  45568018440814649,  554930950705390736, 565235847033248989,
            194533226207994559, 436947900554365039, 66565594430787482,  102062828367756639, 312965156892808264,
            36337769246748365,  211629456565995269, 428267938421086650, 330318959378965001, 230667688335018251,
            409701359330017843, 239444545159238835, 445501763962469518, 374588172385510914, 103032602631474165
        };
        ccrns_int exp_data[] = { 436092969443746065, 37122035620254089,  153252279769970594, 223230783088520399,
                                 364709159179958624, 170461817727078067, 129508808953860517, 267655049676720547 };
        const char *test_name = "test_ccpolyzp_po2cyc_base_convert_exact_poly L=5 60-bit moduli";
        test_ccpolyzp_po2cyc_base_convert_exact_poly_helper(
            ws, &dims_in, moduli_in, &dims_out, moduli_out, x_data, exp_data, test_name);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_exact_poly_random_helper(uint32_t nmoduli_in,
                                                                       const ccrns_int *cc_counted_by(nmoduli_in) moduli_in,
                                                                       ccrns_int modulus_out,
                                                                       const char *test_name)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 128, .nmoduli = nmoduli_in };
    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;

    struct ccpolyzp_po2cyc_dims dims_out = { .degree = dims_in.degree, .nmoduli = 1 };
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_out, &modulus_out);
    is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly_out, global_test_rng),
       CCERR_OK,
       "ccpolyzp_po2cyc_random_uniform_ws != CCERR_OK");

    ccpolyzp_po2cyc_ctx_const_t ctx_out = poly_out->context;

    // compute the entire product q
    cc_size q_prod_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(ctx_in->dims.nmoduli);
    cc_unit *q_prod = CC_ALLOC_WS(ws, q_prod_max_nunits);
    ccpolyzp_po2cyc_ctx_q_prod_ws(ws, q_prod, ctx_in);
    cc_size q_prod_nunits = ccn_n(q_prod_max_nunits, q_prod);
    cc_size q_bits = ccn_bitsof_n(q_prod_nunits);
    cc_size q_bytes = ccn_sizeof_n(q_prod_nunits);

    // create q modulus
    cczp_t q_zp = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(q_prod_nunits));
    CCZP_N(q_zp) = q_prod_nunits;
    ccn_set(q_prod_nunits, q_zp->ccn, q_prod);
    is(cczp_init_ws(ws, q_zp), CCERR_OK, "Error initializing q_zp");

    // x[i * ccn_nof(q_bits)] is the i'th coefficient in bigint form
    cc_unit *x = CC_ALLOC_WS(ws, dims_in.degree * ccn_nof(q_bits));
    struct ccrng_state *rng = global_test_rng;
    for (uint32_t coeff_idx = 0; coeff_idx < dims_in.degree; ++coeff_idx) {
        cc_unit *x_units = &x[coeff_idx * ccn_nof(q_bits)];
        // Sample almost uniform random element x from [0, q - 1]
        is(ccrng_generate(rng, q_bytes, x_units), CCERR_OK, "ccrng_generate != CCERR_OK");
        cczp_modn_ws(ws, q_zp, x_units, ccn_nof(q_bits), x_units);

        // Compute x mod q_i
        for (uint32_t rns_idx = 0; rns_idx < nmoduli_in; ++rns_idx) {
            cc_unit *poly_in_data = CCPOLYZP_PO2CYC_DATA(poly_in, rns_idx, coeff_idx);
            cczp_const_t q_i = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_in, rns_idx);
            cczp_modn_ws(ws, q_i, poly_in_data, ccn_nof(q_bits), x_units);
        }
    }

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "L_IN=%" PRIu32 " ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK",
       nmoduli_in);
    is(ccpolyzp_po2cyc_base_convert_exact_poly_ws(ws, poly_out, poly_in, base_cvt),
       CCERR_OK,
       "L_IN=%" PRIu32 " ccpolyzp_po2cyc_base_convert_exact_poly_ws != CCERR_OK",
       nmoduli_in);

    cc_unit q_half[ccn_nof(q_bits)]; // (q - 1) / 2
    ccn_sub1(ccn_nof(q_bits), q_half, q_zp->ccn, 1);
    ccn_shift_right(ccn_nof(q_bits), q_half, q_half, 1);

    cczp_const_t t = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_out, 0);

    // try to recover exact x
    bool recovered_all_x = true;
    for (uint32_t coeff_idx = 0; coeff_idx < dims_in.degree; ++coeff_idx) {
        cc_unit *x_coeff = &x[coeff_idx * ccn_nof(q_bits)];
        const cc_unit *out_data = CCPOLYZP_PO2CYC_DATA_CONST(poly_out, 0, coeff_idx);
        ccrns_int poly_out_coeff = ccpolyzp_po2cyc_units_to_rns_int(out_data);

        cc_unit expected_x_le_half[ccn_nof(q_bits)]; // x mod t
        cc_unit expected_x_gt_half[ccn_nof(q_bits)]; // (t - (q_in - x) % t) % t
        cc_unit expected[ccn_nof(q_bits)];
        cczp_modn_ws(ws, t, expected_x_le_half, ccn_nof(q_bits), x_coeff);

        ccn_sub_ws(ws, ccn_nof(q_bits), expected_x_gt_half, q_zp->ccn, x_coeff);      // q_in - x
        cczp_modn_ws(ws, t, expected_x_gt_half, ccn_nof(q_bits), expected_x_gt_half); // (q_in - x) % t
        cczp_sub_ws(ws, t, expected_x_gt_half, t->ccn, expected_x_gt_half);           // (t - (q_in - x) % t) % t

        cc_unit x_gt_half = (ccn_cmp(ccn_nof(q_bits), x_coeff, q_half) == 1);
        ccn_mux(ccn_nof(q_bits), x_gt_half, expected, expected_x_gt_half, expected_x_le_half);
        ccrns_int expected_int = ccpolyzp_po2cyc_units_to_rns_int(expected);
        if (poly_out_coeff != expected_int) {
            recovered_all_x = false;
            break;
        }
    }
    is(recovered_all_x, true, "test_ccpolyzp_po2cyc_base_convert_exact_poly_random %s failed to recover x", test_name);

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_exact_poly_random(void)
{
    // 20-bit moduli
    {
        ccrns_int moduli_in[] = { 557057, 575489, 577537 };
        test_ccpolyzp_po2cyc_base_convert_exact_poly_random_helper(3, moduli_in, 534529, "3 20-bit moduli");
    }
    // 40-bit moduli
    {
        ccrns_int moduli_in[] = { 549755873281ULL, 549755904001ULL, 549755932673ULL };
        test_ccpolyzp_po2cyc_base_convert_exact_poly_random_helper(3, moduli_in, 549755860993ULL, "3 40-bit moduli");
    }
    // 60-bit moduli
    {
        ccrns_int moduli_in[] = { 576460752303439873ULL, 576460752303476737ULL };
        test_ccpolyzp_po2cyc_base_convert_exact_poly_random_helper(2, moduli_in, 576460752303568897ULL, "2 60-bit moduli");
    }
    // 61-bit moduli
    {
        ccrns_int moduli_in[] = { 1152921504606902273ULL, 1152921504606965761ULL, 1152921504606904321ULL };
        test_ccpolyzp_po2cyc_base_convert_exact_poly_random_helper(3, moduli_in, 1152921504606902273ULL, "3 61-bit moduli");
    }
    // mix of moduli
    {
        ccrns_int moduli_in[] = { 534529ULL, 549755860993ULL, 576460752303476737ULL, 575489ULL, 1152921504606904321ULL };
        test_ccpolyzp_po2cyc_base_convert_exact_poly_random_helper(5, moduli_in, 1152921504606902273ULL, "5 mixed moduli");
    }
}

static void test_ccpolyzp_po2cyc_base_convert_divide_and_round_errors(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccrns_int moduli_in[] = { 5, 7 };
    ccrns_int data_in[] = { 4, 0, 1, 2 };
    ccrns_int modulus_out = 3;
    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 2, .nmoduli = 2 };
    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_in, moduli_in, data_in);
    struct ccpolyzp_po2cyc_dims dims_out = { .degree = dims_in.degree, .nmoduli = 1 };
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_out, &modulus_out);
    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;
    struct ccpolyzp_po2cyc_dims dims_t_gamma = { .degree = dims_in.degree, .nmoduli = 2 };
    ccrns_int moduli_t_gamma[] = { modulus_out, CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA };
    ccpolyzp_po2cyc_ctx_const_t ctx_t_gamma = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_t_gamma, moduli_t_gamma);

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_t_gamma.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_t_gamma),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

    // okay
    {
        is(ccpolyzp_po2cyc_base_convert_divide_and_round_ws(ws, poly_out, poly_in, base_cvt),
           CCERR_OK,
           "ccpolyzp_po2cyc_base_convert_divide_and_round_ws != CCERR_OK");
    }
    // input context doens't match base_cvt->input_context
    {
        is(ccpolyzp_po2cyc_base_convert_divide_and_round_ws(ws, poly_out, poly_out, base_cvt),
           CCERR_PARAMETER,
           "input context doens't match base_cvt->input_context");
    }
    // output context too many moduli
    {
        is(ccpolyzp_po2cyc_base_convert_divide_and_round_ws(ws, poly_in, poly_in, base_cvt),
           CCERR_PARAMETER,
           "ccpolyzp_po2cyc_base_convert_divide_and_round_ws != CCERR_PARAMETER");
    }
    // base_convert context doesn't have gamma as second component
    {
        ccrns_int moduli_t_not_gamma[] = { modulus_out, 68719230977 };
        ccpolyzp_po2cyc_ctx_const_t ctx_t_not_gamma = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_t_gamma, moduli_t_not_gamma);

        ccpolyzp_po2cyc_base_convert_t base_cvt_not_gamma =
            CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_t_gamma.nmoduli);
        is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt_not_gamma, ctx_in, ctx_t_not_gamma),
           CCERR_OK,
           "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

        is(ccpolyzp_po2cyc_base_convert_divide_and_round_ws(ws, poly_out, poly_in, base_cvt_not_gamma),
           CCERR_PARAMETER,
           "ccpolyzp_po2cyc_base_convert_divide_and_round_ws != CCERR_PARAMETER");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_divide_and_round_helper(ccpolyzp_po2cyc_dims_const_t dims_in,
                                                                      const ccrns_int *moduli_in,
                                                                      ccrns_int modulus_out,
                                                                      ccrns_int *data_in,
                                                                      ccrns_int *exp_data_out,
                                                                      const char *test_name)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_helper(ws, dims_in, moduli_in, data_in);

    struct ccpolyzp_po2cyc_dims dims_out = { .degree = dims_in->degree, .nmoduli = 1 };
    ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_out, &modulus_out);
    is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly_out, global_test_rng),
       CCERR_OK,
       "ccpolyzp_po2cyc_random_uniform_ws != CCERR_OK");
    ccpolyzp_po2cyc_coeff_t exp_poly_out = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims_out, &modulus_out, exp_data_out);

    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;

    struct ccpolyzp_po2cyc_dims dims_t_gamma = { .degree = dims_in->degree, .nmoduli = 2 };
    ccrns_int moduli_t_gamma[] = { modulus_out, CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA };
    ccpolyzp_po2cyc_ctx_const_t ctx_t_gamma = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_t_gamma, moduli_t_gamma);

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in->nmoduli, dims_t_gamma.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_t_gamma),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

    is(ccpolyzp_po2cyc_base_convert_divide_and_round_ws(ws, poly_out, poly_in, base_cvt),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_divide_and_round_ws != CCERR_OK");

    is(ccpolyzp_po2cyc_coeff_eq(poly_out, exp_poly_out),
       true,
       "test_ccpolyzp_po2cyc_base_convert_divide_and_round incorrect %s",
       test_name);

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_divide_and_round(void)
{
    {
        // 29 % 5 = 4, 30 % 5 = 0, 29 % 7 = 1, 30 % 7 = 2
        ccrns_int moduli_in[] = { 5, 7 };
        ccrns_int data_in[] = { 4, 0, 1, 2 };
        // round(29 * 3 / 35) % 3  = round(2.48) % 3 = 2
        // round(30 * 3 / 35) % 3  = round(2.57) % 3 = 0
        ccrns_int modulus_out = 3;
        ccrns_int exp_data_out[] = { 2, 0 };
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 2, .nmoduli = 2 };
        test_ccpolyzp_po2cyc_base_convert_divide_and_round_helper(&dims_in, moduli_in, modulus_out, data_in, exp_data_out, "N=1");
    }
    {
        // (408 % 17 = 0, 491 % 29 = 15, 408 % 29 = 2, 491 % 29 = 27)
        ccrns_int moduli_in[] = { 17, 29 };
        ccrns_int data_in[] = { 0, 15, 2, 27 };
        // round(408 * 5 / (17 * 29)) % 5 = round(4.13) % 5 = 4 % 5 = 4
        // round(491 * 5 / (17 * 29)) % 5 = round(4.97) % 5 = 5 % 5 = 0
        ccrns_int modulus_out = 5;
        ccrns_int exp_data_out[] = { 4, 0 };
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 2, .nmoduli = 2 };
        test_ccpolyzp_po2cyc_base_convert_divide_and_round_helper(&dims_in, moduli_in, modulus_out, data_in, exp_data_out, "N=2");
    }
    {
        ccrns_int q0 = (1ULL << 60) - 93;
        ccrns_int q1 = (1ULL << 60) - 173;
        ccrns_int q2 = (1ULL << 30) - 35;

        // x = np.array([i * 2**150 for i in range(16)])
        /* clang-format off */
        ccrns_int data_in[] = {
            // x % (2**60 - 93)
            0,                  9286793035776ULL,   18573586071552ULL,  27860379107328ULL,
            37147172143104ULL,  46433965178880ULL,  55720758214656ULL,  65007551250432ULL,
            74294344286208ULL,  83581137321984ULL,  92867930357760ULL,  102154723393536ULL,
            111441516429312ULL, 120728309465088ULL, 130015102500864ULL, 139301895536640ULL,
            // x % (2**60 - 173)
            0ULL,               32136019050496ULL,  64272038100992ULL,  96408057151488ULL,
            128544076201984ULL, 160680095252480ULL, 192816114302976ULL, 224952133353472ULL,
            257088152403968ULL, 289224171454464ULL, 321360190504960ULL, 353496209555456ULL,
            385632228605952ULL, 417768247656448ULL, 449904266706944ULL, 482040285757440,
            // x % (2**30 - 35)
            0ULL,         52521875ULL,  105043750ULL, 157565625ULL,
            210087500ULL, 262609375ULL, 315131250ULL, 367653125ULL,
            420175000ULL, 472696875ULL, 525218750ULL, 577740625ULL,
            630262500ULL, 682784375ULL, 735306250ULL, 787828125ULL
        };
        /* clang-format on */

        ccrns_int moduli_in[] = { q0, q1, q2 };
        ccrns_int modulus_out = 549755860993ULL;
        ccrns_int exp_data_out[] = { 0,      17920,  35840,  53760,  71680,  89600,  107520, 125440,
                                     143360, 161280, 179200, 197120, 215040, 232960, 250880, 268800 };
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 16, .nmoduli = 3 };
        test_ccpolyzp_po2cyc_base_convert_divide_and_round_helper(
            &dims_in, moduli_in, modulus_out, data_in, exp_data_out, "big moduli");
    }
}

static void test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_errors(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli_in[] = { 17, 41 };
    struct ccpolyzp_po2cyc_dims dims_out = { .degree = 4, .nmoduli = 1 };
    ccrns_int moduli_out[] = { 17 };

    ccpolyzp_po2cyc_ctx_const_t ctx_in = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_out = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_out, moduli_out);

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

    ccpolyzp_po2cyc_eval_t poly_in = ccpolyzp_po2cyc_eval_init_zero_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_eval_t poly_out = ccpolyzp_po2cyc_eval_init_zero_helper(ws, &dims_out, moduli_out);

    // okay
    {
        is(ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws(ws, poly_in, base_cvt),
           CCERR_OK,
           "ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws != CCERR_OK");
    }
    // wrong input context
    {
        is(ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws(ws, poly_out, base_cvt),
           CCERR_PARAMETER,
           "ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws wrong input context");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_helper(ccpolyzp_po2cyc_dims_const_t dims_in,
                                                                                   const ccrns_int *moduli_in,
                                                                                   ccrns_int modulus_out,
                                                                                   ccrns_int *data_in,
                                                                                   ccrns_int *exp_data_out,
                                                                                   const char *test_name)
{
    CC_DECL_WORKSPACE_TEST(ws);

    ccpolyzp_po2cyc_eval_t poly_in = ccpolyzp_po2cyc_eval_init_helper(ws, dims_in, moduli_in, data_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;
    ccpolyzp_po2cyc_ctx_const_t ctx_out = ctx_in->next;

    ccpolyzp_po2cyc_eval_t exp_poly_out = ccpolyzp_po2cyc_eval_init_helper(ws, &ctx_out->dims, moduli_in, exp_data_out);

    struct ccpolyzp_po2cyc_dims dims_t_gamma = { .degree = dims_in->degree, .nmoduli = 2 };
    ccrns_int moduli_t_gamma[] = { modulus_out, CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA };
    ccpolyzp_po2cyc_ctx_const_t ctx_t_gamma = ccpolyzp_po2cyc_ctx_init_helper(ws, &dims_t_gamma, moduli_t_gamma);

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in->nmoduli, dims_t_gamma.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_t_gamma),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK");

    is(ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws(ws, poly_in, base_cvt),
       CCERR_OK,
       "ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws != CCERR_OK");

    is(ccpolyzp_po2cyc_eval_eq(poly_in, exp_poly_out),
       true,
       "ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws incorrect %s",
       test_name);

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_simple(void)
{
    {
        ccrns_int moduli[] = { 97, 113 };
        ccrns_int data_in[] = { 53, 22, 55, 21, 9,  20, 3, 28, //
                                11, 88, 6,  71, 98, 45, 2, 56 };
        ccrns_int t = 37;
        ccrns_int exp_data_out[] = { 46, 56, 85, 86, 8, 71, 64, 80 };
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 8, .nmoduli = 2 };
        test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_helper(
            &dims_in, moduli, t, data_in, exp_data_out, "L=2 N=8");
    }
    {
        ccrns_int moduli[] = {
            524353,
            524369,
            524497,
        };
        ccrns_int data_in[] = {
            502464, 519788, 441547, 288790, 178249, 304710, 21755,  48615,  //
            180087, 456565, 185690, 168218, 323902, 404893, 373911, 138842, //
            88145,  377681, 109611, 56457,  13640,  194152, 241864, 225563, //
        };
        ccrns_int t = 262147;
        ccrns_int exp_data_out[] = {
            65938,  147368, 420508, 331282, 171286, 247367, 4135,   150728, //
            176452, 463419, 181198, 32145,  504602, 319995, 411533, 234856  //
        };
        struct ccpolyzp_po2cyc_dims dims_in = { .degree = 8, .nmoduli = 3 };
        test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_helper(
            &dims_in, moduli, t, data_in, exp_data_out, "L=3 N=8");
    }
}

static void
test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random_helper(uint32_t nmoduli_in,
                                                                              const ccrns_int *cc_counted_by(nmoduli_in)
                                                                                  moduli_in,
                                                                              ccrns_int modulus_out,
                                                                              const char *inv_q_last_mod_q_new_hex,
                                                                              const char *test_name)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims_in = { .degree = 128, .nmoduli = nmoduli_in };
    ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims_in, moduli_in);
    ccpolyzp_po2cyc_ctx_const_t ctx_in = poly_in->context;

    ccnBuffer inv_q_last_mod_q_new = hexStringToCcn(inv_q_last_mod_q_new_hex);

    // compute q / q_last
    cc_size q_div_q_last_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(ctx_in->next->dims.nmoduli);
    cc_unit *q_div_q_last = CC_ALLOC_WS(ws, q_div_q_last_max_nunits);
    ccpolyzp_po2cyc_ctx_q_prod_ws(ws, q_div_q_last, ctx_in->next);

    // create q / q_last modulus
    cc_size q_div_q_last_nunits = ccn_n(q_div_q_last_max_nunits, q_div_q_last);
    cczp_t q_div_q_last_zp = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(q_div_q_last_nunits));
    CCZP_N(q_div_q_last_zp) = q_div_q_last_nunits;
    ccn_set(q_div_q_last_nunits, q_div_q_last_zp->ccn, q_div_q_last);
    is(cczp_init_ws(ws, q_div_q_last_zp), CCERR_OK, "Error initializing q_div_q_last_zp");

    // compute the entire product q
    cc_size q_prod_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(ctx_in->dims.nmoduli);
    cc_unit *q_prod = CC_ALLOC_WS(ws, q_prod_max_nunits);
    ccpolyzp_po2cyc_ctx_q_prod_ws(ws, q_prod, ctx_in);
    cc_size q_prod_nunits = ccn_n(q_prod_max_nunits, q_prod);
    cc_size q_bits = ccn_bitsof_n(q_prod_nunits);
    cc_size q_bytes = ccn_sizeof_n(q_prod_nunits);

    // create q modulus
    cczp_t q_zp = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(q_prod_nunits));
    CCZP_N(q_zp) = q_prod_nunits;
    ccn_set(q_prod_nunits, q_zp->ccn, q_prod);
    is(cczp_init_ws(ws, q_zp), CCERR_OK, "Error initializing q_zp");

    // q_last
    ccrns_int q_last = moduli_in[nmoduli_in - 1];
    cc_unit *q_last_units = CC_ALLOC_WS(ws, ccn_nof(q_bits));
    ccn_clear(ccn_nof(q_bits), q_last_units);
    ccpolyzp_po2cyc_rns_int_to_units(q_last_units, q_last);

    // x[i * ccn_nof(q_bits)] is the i'th coefficient in bigint form
    cc_unit *x = CC_ALLOC_WS(ws, dims_in.degree * ccn_nof(q_bits));
    struct ccrng_state *rng = global_test_rng;
    for (uint32_t coeff_idx = 0; coeff_idx < dims_in.degree; ++coeff_idx) {
        cc_unit *x_units = &x[coeff_idx * ccn_nof(q_bits)];
        // Sample almost uniform random element x from [0, q - 1]
        is(ccrng_generate(rng, q_bytes, x_units), CCERR_OK, "ccrng_generate != CCERR_OK");
        cczp_modn_ws(ws, q_zp, x_units, ccn_nof(q_bits), x_units);

        // Compute x mod q_i
        for (uint32_t rns_idx = 0; rns_idx < nmoduli_in; ++rns_idx) {
            cc_unit *poly_in_data = CCPOLYZP_PO2CYC_DATA(poly_in, rns_idx, coeff_idx);
            cczp_const_t q_i = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_in, rns_idx);
            cczp_modn_ws(ws, q_i, poly_in_data, ccn_nof(q_bits), x_units);
        }
    }

    is(ccpolyzp_po2cyc_fwd_ntt(poly_in), CCERR_OK, "ccpolyzp_po2cyc_fwd_ntt != CCERR_OK");

    ccpolyzp_po2cyc_ctx_t ctx_out = (ccpolyzp_po2cyc_ctx_t)CCPOLYZP_PO2CYC_CTX_ALLOC_WS(ws, dims_in.degree);
    struct ccpolyzp_po2cyc_dims dims_out = { .degree = dims_in.degree, .nmoduli = 1 };
    is(ccpolyzp_po2cyc_ctx_init_ws(ws, ctx_out, &dims_out, &modulus_out, NULL),
       CCERR_OK,
       "ccpolyzp_po2cyc_ctx_init_ws != CCER_OK");

    ccpolyzp_po2cyc_base_convert_t base_cvt = CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, dims_in.nmoduli, dims_out.nmoduli);
    is(ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctx_in, ctx_out),
       CCERR_OK,
       "L_IN=%" PRIu32 " ccpolyzp_po2cyc_base_convert_init_ws != CCERR_OK",
       nmoduli_in);
    is(ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws(ws, (ccpolyzp_po2cyc_eval_t)poly_in, base_cvt),
       CCERR_OK,
       "L_IN=%" PRIu32 " ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws != CCERR_OK",
       nmoduli_in);

    ccpolyzp_po2cyc_eval_t poly_out = (ccpolyzp_po2cyc_eval_t)poly_in;

    // Expected values computed in coefficient format
    is(ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)poly_out), CCERR_OK, "ccpolyzp_po2cyc_inv_ntt != CCERR_OK");

    cczp_const_t t_zp = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_out, 0);
    ccrns_modulus_const_t t = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx_out, 0);
    ccrns_mul_modulus_const_t inv_q_last_mod_t = &base_cvt->inv_q_last_mod_t;

    cczp_const_t q_last_zp = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_in, nmoduli_in - 1);
    bool recovered_all_x = true;
    for (uint32_t coeff_idx = 0; coeff_idx < dims_in.degree; ++coeff_idx) {
        // let Q := q_0 * ... * q_{L-1} be the input modulus,
        // q := Q / q_last be the new modulus
        // R := q_last
        // v: Z -> Z_q via natural mapping: v(x) = x mod q
        // v': Z_Q -> Z_q via natural mapping: v(x mod Q) = x mod q
        // a := round(q / Q * x)
        // rounding error b := q * x - Q * a
        // b' := b / q = R * a - x
        // Then, expected values are computed for each coefficient x as
        // (v(x) - v(b' + R * d)) * [R^-1 mod q]

        cc_unit *x_coeff = &x[coeff_idx * ccn_nof(q_bits)];

        // v'(x) = x mod q
        cc_unit v_prime_x[ccn_nof(q_bits)];
        ccn_clear(ccn_nof(q_bits), v_prime_x);
        cczp_modn_ws(ws, q_div_q_last_zp, v_prime_x, ccn_nof(q_bits), x_coeff);

        // x mod R
        cc_unit x_mod_q_last[ccn_nof(q_bits)];
        ccn_clear(ccn_nof(q_bits), x_mod_q_last);
        cczp_modn_ws(ws, q_last_zp, x_mod_q_last, ccn_nof(q_bits), x_coeff);

        // b' = x_mod_R % t
        cc_unit b_prime[ccn_nof(q_bits)];
        ccn_clear(ccn_nof(q_bits), b_prime);
        cczp_modn_ws(ws, t_zp, b_prime, ccn_nof(q_bits), x_mod_q_last);
        ccrns_int b_prime_int = ccpolyzp_po2cyc_units_to_rns_int(b_prime);

        // d = -R^{-1} % t
        ccrns_int d_int = ccpolyzp_po2cyc_scalar_shoup_mul_mod(b_prime_int, inv_q_last_mod_t);
        d_int = ccpolyzp_po2cyc_scalar_negate_mod(d_int, t->value) % q_last;
        cc_unit d[ccn_nof(q_bits)];
        ccn_clear(ccn_nof(q_bits), d);
        ccpolyzp_po2cyc_rns_int_to_units(d, d_int);

        // v(b' + R * d)
        cc_unit v_b_prime_plus_rd[ccn_nof(q_bits)];
        ccn_clear(ccn_nof(q_bits), v_b_prime_plus_rd);
        cc_unit q_last_mod_q_div_q_last[ccn_nof(q_bits)];
        ccn_clear(ccn_nof(q_bits), q_last_mod_q_div_q_last);
        cczp_modn_ws(ws, q_div_q_last_zp, q_last_mod_q_div_q_last, ccn_nof(q_bits), q_last_units);
        cczp_mul_ws(ws, q_div_q_last_zp, v_b_prime_plus_rd, q_last_mod_q_div_q_last, d);
        cczp_add_ws(ws, q_div_q_last_zp, v_b_prime_plus_rd, v_b_prime_plus_rd, x_mod_q_last);

        // expected = (v(x) - v(b' + R * d)) * [R^{-1} mod q]
        cc_unit v_diff[ccn_nof(q_bits)];
        ccn_clear(ccn_nof(q_bits), v_diff);
        cczp_sub_ws(ws, q_div_q_last_zp, v_diff, v_prime_x, v_b_prime_plus_rd);
        cczp_mul_ws(ws, q_div_q_last_zp, v_diff, v_diff, inv_q_last_mod_q_new->units);

        for (uint32_t rns_idx = 0; rns_idx < nmoduli_in - 1; ++rns_idx) {
            cc_unit expected[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            cczp_const_t qi = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx_in, rns_idx);
            cczp_modn_ws(ws, qi, expected, ccn_nof(q_bits), v_diff);
            ccrns_int expected_int = ccpolyzp_po2cyc_units_to_rns_int(expected);
            ccrns_int got_int = ccpolyzp_po2cyc_eval_data_int(poly_out, rns_idx, coeff_idx);
            if (expected_int != got_int) {
                recovered_all_x = false;
                break;
            }
        }
    }
    is(recovered_all_x, true, "test_ccpolyzp_po2cyc_base_convert_exact_poly_random %s failed to recover x", test_name);

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random(void)
{
    // 20-bit moduli
    {
        ccrns_int moduli_in[] = { 557057, 575489, 577537 };
        const char *inv_q_last_div_q_new_hex = "de6813c24"; // hex(pow(577537, -1, 557057 * 575489))
        test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random_helper(
            3, moduli_in, 534529, inv_q_last_div_q_new_hex, "3 20-bit moduli");
    }
    // 40-bit moduli
    {
        ccrns_int moduli_in[] = { 549755873281ULL, 549755904001ULL, 549755932673ULL };
        const char *inv_q_last_div_q_new_hex = "55aeaa8d3c6b7e50f9e"; // hex(pow(549755932673, -1, 549755873281 * 549755904001))
        test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random_helper(
            3, moduli_in, 549755860993ULL, inv_q_last_div_q_new_hex, "3 40-bit moduli");
    }
    // 60-bit moduli
    {
        ccrns_int moduli_in[] = { 576460752303439873ULL, 576460752303476737ULL };
        const char *inv_q_last_div_q_new_hex = "7fff1c71c72071d"; // hex(pow(576460752303476737, -1, 576460752303439873ULL))
        test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random_helper(
            2, moduli_in, 576460752303568897, inv_q_last_div_q_new_hex, "2 60-bit moduli");
    }
    // 61-bit moduli
    {
        ccrns_int moduli_in[] = { 1152921504606902273ULL, 1152921504606965761ULL, 1152921504606904321ULL };
        // hex(pow(1152921504606904321, -1, 1152921504606902273 * 1152921504606965761))
        const char *inv_q_last_div_q_new_hex = "223fffdddde38d8220333145724bd7";
        test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random_helper(
            3, moduli_in, 1152921504606902273ULL, inv_q_last_div_q_new_hex, "3 61-bit moduli");
    }
    // mix of moduli
    {
        ccrns_int moduli_in[] = { 534529ULL, 549755860993ULL, 576460752303476737ULL, 575489ULL, 1152921504606904321ULL };
        // hex(pow(1152921504606904321, -1, 534529 * 549755860993 * 576460752303476737 * 575489))
        const char *inv_q_last_div_q_new_hex = "33c7c190cb4693f499f80ca215ab3dcc16";
        test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random_helper(
            5, moduli_in, 1152921504606902273ULL, inv_q_last_div_q_new_hex, "5 mixed moduli");
    }
}

void test_ccpolyzp_po2cyc_base_convert(void)
{
    test_ccpolyzp_po2cyc_base_convert_init_errors();
    test_ccpolyzp_po2cyc_base_convert_init();

    test_ccpolyzp_po2cyc_base_convert_poly_errors();
    test_ccpolyzp_po2cyc_base_convert_poly_simple();
    test_ccpolyzp_po2cyc_base_convert_poly_random();

    test_ccpolyzp_po2cyc_base_convert_exact_poly_simple();
    test_ccpolyzp_po2cyc_base_convert_exact_poly_errors();
    test_ccpolyzp_po2cyc_base_convert_exact_poly_random();

    test_ccpolyzp_po2cyc_base_convert_divide_and_round_errors();
    test_ccpolyzp_po2cyc_base_convert_divide_and_round();

    test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_errors();
    test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_simple();
    test_ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_random();
}
