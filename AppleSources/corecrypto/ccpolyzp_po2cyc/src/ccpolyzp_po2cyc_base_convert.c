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

#include "ccpolyzp_po2cyc_base_convert.h"
#include "ccn_internal.h"
#include "ccpolyzp_po2cyc_scalar.h"

static int ccpolyzp_po2cyc_base_convert_init_inv_punc_prod_ws(cc_ws_t ws, ccpolyzp_po2cyc_base_convert_t base_cvt)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_ctx_const_t input_ctx = base_cvt->input_ctx;
    uint32_t ninput_moduli = input_ctx->dims.nmoduli;

    // Compute inv_punc_prods[i] = (prod_{j=0; j != i}^{L-1} q_j^{-1} mod q_i) mod q_i
    for (uint32_t i = 0; i < ninput_moduli; ++i) {
        cczp_const_t q_i_cczp = ccpolyzp_po2cyc_ctx_cczp_modulus_const(input_ctx, i);
        ccrns_modulus_const_t q_i = ccpolyzp_po2cyc_ctx_ccrns_modulus(input_ctx, i);
        ccrns_int inv_punc_prod = 1;
        for (uint32_t j = 0; j < ninput_moduli; ++j) {
            if (j == i) {
                continue;
            }
            ccrns_int q_j = ccpolyzp_po2cyc_ctx_int_modulus(input_ctx, j);
            ccrns_int qj_mod_qi = ccpolyzp_po2cyc_scalar_mod1(q_j, q_i);
            inv_punc_prod = ccpolyzp_po2cyc_scalar_mul_mod(inv_punc_prod, qj_mod_qi, q_i);
        }
        cc_unit inv_punc_prod_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccpolyzp_po2cyc_rns_int_to_units(inv_punc_prod_units, inv_punc_prod);
        rv = cczp_inv_field_ws(ws, q_i_cczp, inv_punc_prod_units, inv_punc_prod_units);
        cc_require(rv == CCERR_OK, errOut);

        ccrns_mul_modulus_t mul_mod = ccpolyzp_po2cyc_base_convert_inv_punc_prod(base_cvt, i);
        // Input context is public, so variable time is acceptable
        rv = ccrns_mul_modulus_init_var_time_ws(ws, mul_mod, q_i->value, ccpolyzp_po2cyc_units_to_rns_int(inv_punc_prod_units));
        cc_require(rv == CCERR_OK, errOut);
    }

errOut:
    return rv;
}

cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_INIT_PUNC_PROD_WORKSPACE_N(cc_size nmoduli)
{
    return 2 * (ccpolyzp_po2cyc_ctx_q_prod_nof_n((uint32_t)nmoduli) + CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) +
           CCZP_MODN_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) +
           CCRNS_MUL_MODULUS_INIT_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);
    ;
}

static int ccpolyzp_po2cyc_base_convert_init_punc_prod_ws(cc_ws_t ws, ccpolyzp_po2cyc_base_convert_t base_cvt)
{
    int rv = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

    ccpolyzp_po2cyc_ctx_const_t input_ctx = base_cvt->input_ctx;
    ccpolyzp_po2cyc_ctx_const_t output_ctx = base_cvt->output_ctx;
    uint32_t ninput_moduli = input_ctx->dims.nmoduli;
    uint32_t noutput_moduli = output_ctx->dims.nmoduli;

    // Compute punctured products ((q_prod / q_i)) mod t_j, where the division is normal integer division, i.e. not modular.
    cc_size q_punc_prod_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(input_ctx->dims.nmoduli);
    // Allocate extra memory since we start the multiplication at 1.
    cc_unit *q_punc_prod = CC_ALLOC_WS(ws, q_punc_prod_max_nunits + CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);
    cc_unit *q_punc_prod_tmp = CC_ALLOC_WS(ws, q_punc_prod_max_nunits + CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);

    for (uint32_t rns_idx_in = 0; rns_idx_in < ninput_moduli; ++rns_idx_in) {
        // Compute punctured product (q_prod / q_{rns_idx_in})
        ccn_seti(q_punc_prod_max_nunits, q_punc_prod, 1);
        for (uint32_t i = 0; i < ninput_moduli; ++i) {
            if (i == rns_idx_in) {
                continue;
            }
            const cc_unit *q_i = CCZP_PRIME(ccpolyzp_po2cyc_ctx_cczp_modulus_const(input_ctx, i));
            cc_size nprod_units = (i + 1) * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
            ccn_muln(nprod_units, q_punc_prod_tmp, q_punc_prod, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_i);
            ccn_set(nprod_units, q_punc_prod, q_punc_prod_tmp);
        }
        for (uint32_t rns_idx_out = 0; rns_idx_out < noutput_moduli; ++rns_idx_out) {
            cczp_const_t cczp_t_rns_idx_out = ccpolyzp_po2cyc_ctx_cczp_modulus_const(output_ctx, rns_idx_out);
            ccrns_int t_rns_idx_out = ccpolyzp_po2cyc_ctx_int_modulus(output_ctx, rns_idx_out);
            ccrns_mul_modulus_t punc_prod_modulus = ccpolyzp_po2cyc_base_convert_punc_prod(base_cvt, rns_idx_in, rns_idx_out);
            cc_unit punc_prod[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] = { 0 };
            cczp_modn_ws(ws, cczp_t_rns_idx_out, punc_prod, q_punc_prod_max_nunits, q_punc_prod);
            ccrns_int punc_prod_int = ccpolyzp_po2cyc_units_to_rns_int(punc_prod);
            rv = ccrns_mul_modulus_init_ws(ws, punc_prod_modulus, t_rns_idx_out, punc_prod_int);
            cc_require(rv == CCERR_OK, errOut);
        }
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/// @brief Computes r = -(q % t_{rns_out_idx})^{-1} % t_{rns_out_idx}
/// @param ws Workspace
/// @param r The output
/// @param base_cvt Base converter
/// @param rns_out_idx Must be in [0, noutput_moduli - 1]
CC_NONNULL_ALL CC_WARN_RESULT static int
ccpolyzp_po2cyc_base_convert_neg_q_inv_mod_t_ws(cc_ws_t ws,
                                                cc_unit *cc_counted_by(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) r,
                                                ccpolyzp_po2cyc_base_convert_const_t base_cvt,
                                                uint32_t rns_out_idx)
{
    cc_assert(rns_out_idx < base_cvt->output_ctx->dims.nmoduli);
    int rv = CCERR_OK;

    ccpolyzp_po2cyc_ctx_const_t input_ctx = base_cvt->input_ctx;
    cczp_const_t t = ccpolyzp_po2cyc_ctx_cczp_modulus_const(base_cvt->output_ctx, rns_out_idx);
    ccn_seti(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, r, 1);
    for (uint32_t i = 0; i < input_ctx->dims.nmoduli; ++i) {
        cczp_const_t q_i = ccpolyzp_po2cyc_ctx_cczp_modulus_const(input_ctx, i);
        cc_unit inv_q_i_mod_t[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        cczp_modn_ws(ws, t, inv_q_i_mod_t, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, cczp_prime(q_i));
        cczp_mul_ws(ws, t, r, r, inv_q_i_mod_t);
    }
    cc_require((rv = cczp_inv_field_ws(ws, t, r, r)) == CCERR_OK, errOut);
    cczp_negate(t, r, r);

errOut:
    return rv;
}

/// @brief Initializes Q mod t_0 in the base converter
/// @param ws Workspace
/// @param base_cvt Base converter
CC_NONNULL_ALL CC_WARN_RESULT static int ccpolyzp_po2cyc_base_convert_init_q_mod_t0_ws(cc_ws_t ws,
                                                                                       ccpolyzp_po2cyc_base_convert_t base_cvt)
{
    ccrns_int q_mod_t0 = 1;
    ccrns_modulus_const_t t = ccpolyzp_po2cyc_ctx_ccrns_modulus(base_cvt->output_ctx, 0);
    for (uint32_t i = 0; i < base_cvt->input_ctx->dims.nmoduli; ++i) {
        ccrns_modulus_const_t qi = ccpolyzp_po2cyc_ctx_ccrns_modulus(base_cvt->input_ctx, i);
        q_mod_t0 = ccpolyzp_po2cyc_scalar_mul_mod(q_mod_t0, qi->value, t);
    }
    return ccrns_mul_modulus_init_ws(ws, &base_cvt->q_mod_t0, t->value, q_mod_t0);
}

cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_INIT_WORKSPACE_N(cc_size nmoduli)
{
    // clang-format off
    return CC_MAX_EVAL(CCPOLYZP_PO2CYC_BASE_CONVERT_INIT_PUNC_PROD_WORKSPACE_N(nmoduli),
           CC_MAX_EVAL(CCPOLYZP_PO2CYC_BASE_CONVERT_INIT_INV_PUNC_PROD_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
           CC_MAX_EVAL(CCZP_MODN_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
           CC_MAX_EVAL(CCZP_INV_FIELD_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
           CC_MAX_EVAL(CCRNS_MUL_MODULUS_INIT_VAR_TIME_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
                       CCN_MUL_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF))))));
    // clang-format on
}

int ccpolyzp_po2cyc_base_convert_init_ws(cc_ws_t ws,
                                         ccpolyzp_po2cyc_base_convert_t base_cvt,
                                         ccpolyzp_po2cyc_ctx_const_t input_ctx,
                                         ccpolyzp_po2cyc_ctx_const_t output_ctx)
{
    cc_require_or_return(input_ctx->dims.degree == output_ctx->dims.degree, CCERR_PARAMETER);

    base_cvt->input_ctx = input_ctx;
    base_cvt->output_ctx = output_ctx;

    ccpolyzp_po2cyc_base_convert_init_punc_prod_ws(ws, base_cvt);
    int rv = ccpolyzp_po2cyc_base_convert_init_inv_punc_prod_ws(ws, base_cvt);
    cc_require(rv == CCERR_OK, errOut);

    // Compute q_mod_t0
    rv = ccpolyzp_po2cyc_base_convert_init_q_mod_t0_ws(ws, base_cvt);
    cc_require(rv == CCERR_OK, errOut);

    // Check q is co-prime to gamma (we assume qi already prime)
    for (uint32_t i = 0; i < input_ctx->dims.nmoduli; ++i) {
        cc_require_or_return(ccpolyzp_po2cyc_ctx_int_modulus(input_ctx, i) != CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA,
                             CCERR_PARAMETER);
    }

    // Compute gamma_mod_t and gamma_inv_mod_t
    cc_unit gamma_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(gamma_units, CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA);
    cczp_const_t t0 = ccpolyzp_po2cyc_ctx_cczp_modulus_const(output_ctx, 0);
    cczp_modn_ws(ws, t0, base_cvt->gamma_mod_t, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, gamma_units);
    rv = cczp_inv_field_ws(ws, t0, base_cvt->gamma_inv_mod_t, base_cvt->gamma_mod_t);
    cc_require(rv == CCERR_OK, errOut);

    // Compute -((q % t)^{-1} % t)
    rv = ccpolyzp_po2cyc_base_convert_neg_q_inv_mod_t_ws(ws, base_cvt->neg_inv_q_mod_t, base_cvt, 0);
    cc_require(rv == CCERR_OK, errOut);

    // Compute -((q % gamma)^{-1} % gamma)
    if (output_ctx->dims.nmoduli > 1) {
        rv = ccpolyzp_po2cyc_base_convert_neg_q_inv_mod_t_ws(ws, base_cvt->neg_inv_q_mod_gamma, base_cvt, 1);
        cc_require(rv == CCERR_OK, errOut);
    }

    // Compute inv_q_last_mod_t
    const cc_unit *q_last = ccpolyzp_po2cyc_ctx_cczp_modulus_const(input_ctx, input_ctx->dims.nmoduli - 1)->ccn;
    cc_unit inv_q_last_mod_t[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cczp_modn_ws(ws, t0, inv_q_last_mod_t, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_last);
    rv = cczp_inv_field_ws(ws, t0, inv_q_last_mod_t, inv_q_last_mod_t);
    cc_require(rv == CCERR_OK, errOut);
    ccrns_int t0_int = ccpolyzp_po2cyc_modulus_to_rns_int(t0);
    rv = ccrns_mul_modulus_init_var_time_ws(
        ws, &base_cvt->inv_q_last_mod_t, t0_int, ccpolyzp_po2cyc_units_to_rns_int(inv_q_last_mod_t));
    cc_require(rv == CCERR_OK, errOut);

    // Compute q_last_mod_qi & inv_q_last_mod_qi
    ccrns_int q_last_int = ccpolyzp_po2cyc_ctx_int_modulus(input_ctx, input_ctx->dims.nmoduli - 1);
    for (uint32_t rns_idx = 0; rns_idx < input_ctx->dims.nmoduli - 1; ++rns_idx) {
        cczp_const_t qi_cczp = ccpolyzp_po2cyc_ctx_cczp_modulus_const(input_ctx, rns_idx);
        ccrns_modulus_const_t qi = ccpolyzp_po2cyc_ctx_ccrns_modulus(input_ctx, rns_idx);
        ccrns_mul_modulus_t q_last_mod_qi = ccpolyzp_po2cyc_base_convert_q_last_mod_qi(base_cvt, rns_idx);
        ccrns_int q_last_mod_qi_int = ccpolyzp_po2cyc_scalar_mod1(q_last_int, qi);
        rv = ccrns_mul_modulus_init_var_time_ws(ws, q_last_mod_qi, qi->value, q_last_mod_qi_int);
        cc_require(rv == CCERR_OK, errOut);

        cc_unit inv_q_last_mod_qi_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccpolyzp_po2cyc_rns_int_to_units(inv_q_last_mod_qi_units, q_last_mod_qi_int);
        rv = cczp_inv_field_ws(ws, qi_cczp, inv_q_last_mod_qi_units, inv_q_last_mod_qi_units);
        cc_require(rv == CCERR_OK, errOut);

        ccrns_int inv_q_last_mod_qi_int = ccpolyzp_po2cyc_units_to_rns_int(inv_q_last_mod_qi_units);
        ccrns_mul_modulus_t inv_q_last_mod_qi = ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi(base_cvt, rns_idx);
        rv = ccrns_mul_modulus_init_var_time_ws(ws, inv_q_last_mod_qi, qi->value, inv_q_last_mod_qi_int);
        cc_require(rv == CCERR_OK, errOut);
    }

    // Compute t_times_gamma_mod_qi
    cc_unit t_times_gamma[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_mul_ws(ws, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, t_times_gamma, CCZP_PRIME(t0), gamma_units);

    cc_unit t_times_gamma_mod_qi_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    for (uint32_t i = 0; i < input_ctx->dims.nmoduli; ++i) {
        cczp_const_t q_i = ccpolyzp_po2cyc_ctx_cczp_modulus_const(input_ctx, i);
        cczp_modn_ws(ws, q_i, t_times_gamma_mod_qi_units, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, t_times_gamma);
        *ccpolyzp_po2cyc_base_convert_t0_gamma_mod_qi(base_cvt, i) = ccpolyzp_po2cyc_units_to_rns_int(t_times_gamma_mod_qi_units);
    }

errOut:
    return rv;
}

int ccpolyzp_po2cyc_base_convert_poly_ws(cc_ws_t ws,
                                         ccpolyzp_po2cyc_coeff_t r,
                                         ccpolyzp_po2cyc_coeff_const_t x,
                                         ccpolyzp_po2cyc_base_convert_const_t base_cvt)
{
    ccpolyzp_po2cyc_ctx_const_t ctx_in = x->context;
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ctx_in, base_cvt->input_ctx), CCERR_PARAMETER);
    ccpolyzp_po2cyc_ctx_const_t ctx_out = r->context;
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ctx_out, base_cvt->output_ctx), CCERR_PARAMETER);

    for (uint32_t coeff_idx = 0; coeff_idx < ctx_in->dims.degree; ++coeff_idx) {
        for (uint32_t rns_idx_out = 0; rns_idx_out < ctx_out->dims.nmoduli; ++rns_idx_out) {
            ccrns_modulus_const_t t_j = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx_out, rns_idx_out);
            cc_unit sum[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] = { 0 };
            for (uint32_t rns_idx_in = 0; rns_idx_in < ctx_in->dims.nmoduli; ++rns_idx_in) {
                ccrns_mul_modulus_const_t q_punc =
                    ccpolyzp_po2cyc_base_convert_punc_prod_const(base_cvt, rns_idx_in, rns_idx_out);
                ccrns_int x_coeff = ccpolyzp_po2cyc_coeff_data_int(x, rns_idx_in, coeff_idx);
                ccrns_mul_modulus_const_t inv_q_punc = ccpolyzp_po2cyc_base_convert_inv_punc_prod_const(base_cvt, rns_idx_in);
                ccrns_int x_times_inv_q_punc = ccpolyzp_po2cyc_scalar_shoup_mul_mod(x_coeff, inv_q_punc);

                cc_unit x_times_inv_q_punc_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
                ccpolyzp_po2cyc_rns_int_to_units(x_times_inv_q_punc_units, x_times_inv_q_punc);

                cc_unit q_punc_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
                ccpolyzp_po2cyc_rns_int_to_units(q_punc_units, q_punc->multiplicand);

                cc_unit prod[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
                ccn_mul_ws(ws, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, prod, x_times_inv_q_punc_units, q_punc_units);

                // Ensure no overflow happens
                cc_unit carry = ccn_add_ws(ws, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, sum, sum, prod);
                cc_require_or_return(carry == 0, CCERR_INTERNAL);
            }
            ccrns_int r_int = ccpolyzp_po2cyc_scalar_mod2(sum, t_j);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r, rns_idx_out, coeff_idx), r_int);
        }
    }

    return CCERR_OK;
}

CC_PURE cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_EXACT_POLY_WORKSPACE_N(cc_size degree)
{
    return ccn_nof_size(degree * sizeof(double));
}

int ccpolyzp_po2cyc_base_convert_exact_poly_ws(cc_ws_t ws,
                                               ccpolyzp_po2cyc_coeff_t r,
                                               ccpolyzp_po2cyc_coeff_const_t x,
                                               ccpolyzp_po2cyc_base_convert_const_t base_cvt)
{
    ccpolyzp_po2cyc_ctx_const_t ctx_in = x->context;
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ctx_in, base_cvt->input_ctx), CCERR_PARAMETER);
    ccpolyzp_po2cyc_ctx_const_t ctx_out = r->context;
    ccpolyzp_po2cyc_ctx_const_t base_cvt_out_ctx = ccpolyzp_po2cyc_ctx_idx_const(base_cvt->output_ctx, 0);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ctx_out, base_cvt_out_ctx), CCERR_PARAMETER);
    ccrns_modulus_const_t t = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx_out, 0);

    CC_DECL_BP_WS(ws, bp);

    cc_size double_buffer_nunits = ccn_nof_size(ctx_in->dims.degree * sizeof(double));
    // Will store sum_{i=1}^L ([x_i * \tilde{q_i]}]_{q_i} / q_i),
    // where \tilde{q_i} is the inverse punctured product
    double *v_sum = (double *)CC_ALLOC_WS(ws, double_buffer_nunits);
    ccn_clear(double_buffer_nunits, (cc_unit *)v_sum);

    for (uint32_t rns_idx_in = 0; rns_idx_in < ctx_in->dims.nmoduli; ++rns_idx_in) {
        ccrns_modulus_const_t qi = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx_in, rns_idx_in);
        ccrns_mul_modulus_const_t qi_punc = ccpolyzp_po2cyc_base_convert_punc_prod_const(base_cvt, rns_idx_in, 0);
        ccrns_mul_modulus_const_t qi_inv_punc = ccpolyzp_po2cyc_base_convert_inv_punc_prod_const(base_cvt, rns_idx_in);
        for (uint32_t coeff_idx = 0; coeff_idx < ctx_in->dims.degree; ++coeff_idx) {
            ccrns_int x_coeff = ccpolyzp_po2cyc_coeff_data_int(x, rns_idx_in, coeff_idx);
            ccrns_int x_times_q_tilde_coeff = ccpolyzp_po2cyc_scalar_shoup_mul_mod(x_coeff, qi_inv_punc);
            // Note, use of double yields errors with absolute value |error| < 2^-53 per rns index.
            // This gives a small chance of base conversion error, < ninput_moduli * 2 * 2^-53.
            // In practice, a base conversion error would yield a small noise growth in a BFV/BGV ciphertext,
            // so it doesn't pose a practical concern.
            double v = (double)x_times_q_tilde_coeff / (double)(qi->value);
            v_sum[coeff_idx] += v;

            ccrns_int tmp = ccpolyzp_po2cyc_scalar_shoup_mul_mod(x_times_q_tilde_coeff, qi_punc);
            // re-use output buffer for intermediate computation of [x_i * \tilde{q_i}]_{q_i}
            ccrns_int r_coeff = rns_idx_in == 0 ? 0 : ccpolyzp_po2cyc_coeff_data_int(r, 0, coeff_idx);
            r_coeff = ccpolyzp_po2cyc_scalar_add_mod(r_coeff, tmp, t->value);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r, 0, coeff_idx), r_coeff);
        }
    }
    // [x]_t = [(sum_{i=1}^L y_i * [q_i^*]_t) - v * [q]_t]]_t
    // where q_i^* = \tilde{q_i}^{-1} mod q_i
    for (uint32_t coeff_idx = 0; coeff_idx < ctx_in->dims.degree; ++coeff_idx) {
        ccrns_int v_int = (ccrns_int)(v_sum[coeff_idx] + 0.5); // Rounding
        ccrns_int v_q_mod_t = ccpolyzp_po2cyc_scalar_shoup_mul_mod(v_int, &base_cvt->q_mod_t0);
        ccrns_int r_coeff = ccpolyzp_po2cyc_coeff_data_int(r, 0, coeff_idx);
        r_coeff = ccpolyzp_po2cyc_scalar_sub_mod(r_coeff, v_q_mod_t, t->value);
        ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r, 0, coeff_idx), r_coeff);
    }

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_DIVIDE_AND_ROUND_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    struct ccpolyzp_po2cyc_dims dims = { .degree = (uint32_t)degree, .nmoduli = (uint32_t)nmoduli };
    struct ccpolyzp_po2cyc_dims t_gamma_dims = { .degree = (uint32_t)degree, .nmoduli = 2 };
    return ccpolyzp_po2cyc_nof_n(&dims) + ccpolyzp_po2cyc_nof_n(&t_gamma_dims) +
           CCPOLYZP_PO2CYC_BASE_CONVERT_POLY_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) +
           3 * CCPOLYZP_PO2CYC_COEFF_SCALAR_MUL_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);
}

int ccpolyzp_po2cyc_base_convert_divide_and_round_ws(cc_ws_t ws,
                                                     ccpolyzp_po2cyc_coeff_t r,
                                                     ccpolyzp_po2cyc_coeff_const_t x,
                                                     ccpolyzp_po2cyc_base_convert_const_t base_cvt)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_ctx_const_t ctx_in = x->context;
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ctx_in, base_cvt->input_ctx), CCERR_PARAMETER);

    cc_require_or_return(r->context->dims.nmoduli == 1, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_int_modulus(r->context, 0) ==
                             ccpolyzp_po2cyc_ctx_int_modulus(base_cvt->output_ctx, 0),
                         CCERR_PARAMETER);
    cc_require_or_return(base_cvt->output_ctx->dims.nmoduli == 2, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_int_modulus(base_cvt->output_ctx, 0) != CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA,
                         CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_int_modulus(base_cvt->output_ctx, 1) == CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA,
                         CCERR_PARAMETER);
    CC_DECL_BP_WS(ws, bp);

    // compute |t * gamma| % q_i * x

    // x_times_t_gamma = |t * gamma| mod q_i * x
    ccrns_modulus_const_t t = ccpolyzp_po2cyc_ctx_ccrns_modulus(r->context, 0);
    ccpolyzp_po2cyc_coeff_t x_times_t_gamma = (ccpolyzp_po2cyc_coeff_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &x->context->dims);
    ccpolyzp_po2cyc_coeff_copy(x_times_t_gamma, x);
    ccpolyzp_po2cyc_coeff_scalar_mul_ws(ws, x_times_t_gamma, x, ccpolyzp_po2cyc_base_convert_t0_gamma_mod_qi_const(base_cvt, 0));

    struct ccpolyzp_po2cyc_dims t_gamma_dims = { .degree = x->context->dims.degree, .nmoduli = 2 };
    ccpolyzp_po2cyc_coeff_t temp_t_gamma = (ccpolyzp_po2cyc_coeff_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &t_gamma_dims);
    ccpolyzp_po2cyc_ctx_const_t t_gamma_ctx = base_cvt->output_ctx;
    ccpolyzp_po2cyc_init_zero((ccpolyzp_po2cyc_t)temp_t_gamma, t_gamma_ctx);

    cc_require((rv = ccpolyzp_po2cyc_base_convert_poly_ws(ws, temp_t_gamma, x_times_t_gamma, base_cvt)) == CCERR_OK, errOut);

    // Compute temp_t_gamma *=-((q % t)^{-1} % t)
    ccrns_int neg_inv_q_mod_t_gamma[2] = { ccpolyzp_po2cyc_units_to_rns_int(base_cvt->neg_inv_q_mod_t),
                                           ccpolyzp_po2cyc_units_to_rns_int(base_cvt->neg_inv_q_mod_gamma) };
    ccpolyzp_po2cyc_coeff_scalar_mul_ws(ws, temp_t_gamma, temp_t_gamma, neg_inv_q_mod_t_gamma);

    // Now, do mod gamma
    ccrns_int gamma_div_2 = CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA / 2;
    uint32_t degree = x->context->dims.degree;
    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        ccrns_int temp_t = ccpolyzp_po2cyc_coeff_data_int(temp_t_gamma, 0, coeff_idx);
        ccrns_int temp_gamma = ccpolyzp_po2cyc_coeff_data_int(temp_t_gamma, 1, coeff_idx);
        ccrns_int temp_mod_gamma_mod_t = ccpolyzp_po2cyc_scalar_mod1(temp_gamma, t);
        ccrns_int gamma_mod_t = ccpolyzp_po2cyc_units_to_rns_int(base_cvt->gamma_mod_t);

        // s_gamma = (temp_mod_gamma > gamma/2) ? (temp_mod_gamma_mod_t - gamma_mod_t) % t : temp_mod_gamma_mod_t
        ccrns_int adjust_down = ((temp_gamma - gamma_div_2) >> CCRNS_INT_NBITS_MINUS_1) ^ 1;
        ccrns_int temp_mod_gamma_shift = ccpolyzp_po2cyc_scalar_sub_mod(temp_mod_gamma_mod_t, gamma_mod_t, t->value);
        ccrns_int s_gamma;
        CC_MUXU(s_gamma, adjust_down, temp_mod_gamma_shift, temp_mod_gamma_mod_t);
        ccrns_int out = ccpolyzp_po2cyc_scalar_sub_mod(temp_t, s_gamma, t->value);
        ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r, 0, coeff_idx), out);
    }
    // r *= gamma_inv_mod_t
    ccrns_int gamma_inv_mod_t = ccpolyzp_po2cyc_units_to_rns_int(base_cvt->gamma_inv_mod_t);
    ccpolyzp_po2cyc_coeff_scalar_mul_ws(ws, r, r, &gamma_inv_mod_t);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

cc_size CCPOLYZP_PO2CYC_BASE_CONVERT_MOD_T_DIVIDE_AND_ROUND_Q_LAST_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    return CCPOLYZP_PO2CYC_WORKSPACE_N(degree, nmoduli - 1) + // delta_mod_qi
           CCPOLYZP_PO2CYC_WORKSPACE_N(degree, 1) +           // delta_mod_t
           CCPOLYZP_PO2CYC_CTX_WORKSPACE_N(degree) +          // q_last_ctx
           // initialize q_last_ctx / alloc x_last_slice
           CC_MAX_EVAL(CCPOLYZP_PO2CYC_CTX_INIT_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
                       CCPOLYZP_PO2CYC_WORKSPACE_N(degree, 1));
}

int ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws(cc_ws_t ws,
                                                                  ccpolyzp_po2cyc_eval_t x,
                                                                  ccpolyzp_po2cyc_base_convert_const_t base_cvt)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_ctx_const_t ctx_in = x->context;
    ccpolyzp_po2cyc_ctx_const_t ctx_out = x->context->next;
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ctx_in, base_cvt->input_ctx), CCERR_PARAMETER);
    cc_require_or_return(ctx_in->next != NULL, CCERR_PARAMETER);

    CC_DECL_BP_WS(ws, bp);

    // delta_mod_qi
    ccpolyzp_po2cyc_coeff_t delta_mod_qi = (ccpolyzp_po2cyc_coeff_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &ctx_out->dims);
    delta_mod_qi->context = ctx_out;

    // delta_mod_t
    ccrns_modulus_const_t t = ccpolyzp_po2cyc_ctx_ccrns_modulus(base_cvt->output_ctx, 0);
    struct ccpolyzp_po2cyc_dims one_modulus_dims = { .degree = ctx_in->dims.degree, .nmoduli = 1 };
    ccpolyzp_po2cyc_coeff_t delta_mod_t = (ccpolyzp_po2cyc_coeff_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &one_modulus_dims);

    // x_last_slice
    ccpolyzp_po2cyc_ctx_t q_last_ctx = (ccpolyzp_po2cyc_ctx_t)CCPOLYZP_PO2CYC_CTX_ALLOC_WS(ws, ctx_in->dims.degree);
    ccrns_int q_last = ctx_in->ccrns_q_last.value;
    cc_require((rv = ccpolyzp_po2cyc_ctx_init_ws(ws, q_last_ctx, &one_modulus_dims, &q_last, NULL)) == CCERR_OK, errOut);
    const ccrns_int *x_last_data = (const ccrns_int *)CCPOLYZP_PO2CYC_DATA_CONST(x, ctx_out->dims.nmoduli, 0);
    ccpolyzp_po2cyc_coeff_t x_last_slice = (ccpolyzp_po2cyc_coeff_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &one_modulus_dims);
    rv = ccpolyzp_po2cyc_init((ccpolyzp_po2cyc_t)x_last_slice, q_last_ctx, x_last_data);
    cc_require(rv == CCERR_OK, errOut);

    // b' = x % q_last
    rv = ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)x_last_slice);
    cc_require(rv == CCERR_OK, errOut);

    // Computes delta_mod_t, where delta = [-Q^{-1} b]_t
    ccpolyzp_po2cyc_coeff_copy(delta_mod_t, x_last_slice);
    for (uint32_t coeff_idx = 0; coeff_idx < one_modulus_dims.degree; ++coeff_idx) {
        ccrns_int x_coeff = ccpolyzp_po2cyc_coeff_data_int(delta_mod_t, 0, coeff_idx);
        ccrns_int x_mod_t = ccpolyzp_po2cyc_scalar_mod1(x_coeff, t);
        ccrns_int neg_x_mod_t = t->value - x_mod_t; // May exceed [0, t - 1]
        ccrns_int delta = ccpolyzp_po2cyc_scalar_shoup_mul_mod(neg_x_mod_t, &base_cvt->inv_q_last_mod_t);
        ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(delta_mod_t, 0, coeff_idx), delta);
    }

    for (uint32_t rns_idx = 0; rns_idx < ctx_out->dims.nmoduli; ++rns_idx) {
        ccrns_modulus_const_t qi = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx_in, rns_idx);
        ccrns_mul_modulus_const_t q_last_mod_qi = ccpolyzp_po2cyc_base_convert_q_last_mod_qi_const(base_cvt, rns_idx);
        for (uint32_t coeff_idx = 0; coeff_idx < ctx_out->dims.degree; ++coeff_idx) {
            ccrns_int delta_mod_t_coeff = ccpolyzp_po2cyc_coeff_data_int(delta_mod_t, 0, coeff_idx);
            ccrns_int delta_mod_qi_coeff = ccpolyzp_po2cyc_scalar_mod1(delta_mod_t_coeff, qi);
            delta_mod_qi_coeff = ccpolyzp_po2cyc_scalar_shoup_mul_mod(delta_mod_qi_coeff, q_last_mod_qi);

            ccrns_int x_last = ccpolyzp_po2cyc_coeff_data_int(x_last_slice, 0, coeff_idx);
            ccrns_int x_last_mod_qi = ccpolyzp_po2cyc_scalar_mod1(x_last, qi);
            x_last_mod_qi = ccpolyzp_po2cyc_scalar_add_mod(delta_mod_qi_coeff, x_last_mod_qi, qi->value);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(delta_mod_qi, rns_idx, coeff_idx), x_last_mod_qi);
        }
    }

    rv = ccpolyzp_po2cyc_fwd_ntt(delta_mod_qi);
    cc_require(rv == CCERR_OK, errOut);

    for (uint32_t rns_idx = 0; rns_idx < ctx_out->dims.nmoduli; ++rns_idx) {
        ccrns_mul_modulus_const_t inv_q_last_mod_qi = ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi_const(base_cvt, rns_idx);
        for (uint32_t coeff_idx = 0; coeff_idx < ctx_out->dims.degree; ++coeff_idx) {
            ccrns_int coeff = ccpolyzp_po2cyc_eval_data_int(x, rns_idx, coeff_idx);
            ccrns_int delta = ccpolyzp_po2cyc_coeff_data_int(delta_mod_qi, rns_idx, coeff_idx);

            coeff = ccpolyzp_po2cyc_scalar_sub_mod(coeff, delta, inv_q_last_mod_qi->modulus);
            coeff = ccpolyzp_po2cyc_scalar_shoup_mul_mod(coeff, inv_q_last_mod_qi);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(x, rns_idx, coeff_idx), coeff);
        }
    }
    x->context = x->context->next;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
