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

#include "cc_internal.h"
#include "ccpolyzp_po2cyc_ntt.h"
#include "ccpolyzp_po2cyc_scalar.h"
#include "cche_internal.h"
#include "cche_util.h"
#include "cche_cipher_plain_ctx.h"

bool cche_param_ctx_supports_simd_encoding(cche_param_ctx_const_t param_ctx)
{
    CC_ENSURE_DIT_ENABLED

    return (cche_param_ctx_plaintext_ctx_const(param_ctx))->ntt_friendly;
}

int cche_encode_poly_uint64(cche_plaintext_t ptext,
                            cche_param_ctx_const_t param_ctx,
                            uint32_t nvalues,
                            const uint64_t *cc_counted_by(nvalues) values)
{
    CC_ENSURE_DIT_ENABLED

    cche_plaintext_init(ptext, param_ctx);
    ccpolyzp_po2cyc_coeff_t poly = cche_plaintext_polynomial(ptext);
    cc_require_or_return(nvalues <= poly->context->dims.degree, CCERR_PARAMETER);
    ccrns_int plaintext_modulus = cche_param_ctx_plaintext_modulus(param_ctx);

    for (uint32_t i = 0; i < nvalues; ++i) {
        ccrns_int encode_value = (ccrns_int)values[i];
        cc_require_or_return(encode_value < plaintext_modulus, CCERR_PARAMETER);
        cc_unit *data = CCPOLYZP_PO2CYC_DATA(poly, 0, i);
        ccpolyzp_po2cyc_rns_int_to_units(data, encode_value);
    }
    for (uint32_t i = nvalues; i < poly->context->dims.degree; ++i) {
        cc_unit *data = CCPOLYZP_PO2CYC_DATA(poly, 0, i);
        ccn_seti(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, data, 0);
    }

    return CCERR_OK;
}

int cche_encode_simd_uint64(cche_plaintext_t ptext, cche_param_ctx_const_t param_ctx, uint32_t nvalues, const uint64_t *values)
{
    CC_ENSURE_DIT_ENABLED

    cche_plaintext_init(ptext, param_ctx);

    ccpolyzp_po2cyc_coeff_t poly = cche_plaintext_polynomial(ptext);
    cc_require_or_return(nvalues <= poly->context->dims.degree, CCERR_PARAMETER);
    ccrns_int plaintext_modulus = cche_param_ctx_plaintext_modulus(param_ctx);

    const uint32_t *indices = cche_param_ctx_encoding_indices_const(param_ctx);
    for (uint32_t i = 0; i < nvalues; ++i) {
        // Let f(x) = a_0 + a_1x + ... + a_{N-1}x^{N-1} in R_t be the degree N-1 polynomial we encode to,
        // represented by its coefficients, i.e. in coefficient format.
        // We interpret the input `values` as the vector of evaluations of f at powers of eta, a 2N'th primitive root of unity.
        // We map these vector of evaluations of f to the vector [f(eta), f(eta^3), ..., f(eta^{2N-1})].
        // The invNTT then maps [f(eta), f(eta^3), ..., f(eta^{2N-1})] to [a_0, ..., a_{N-1}], i.e., the coefficient
        // representation of f.
        cc_unit *data = CCPOLYZP_PO2CYC_DATA(poly, 0, indices[i]);
        ccpolyzp_po2cyc_rns_int_to_units(data, (ccrns_int)values[i]);
        cc_require_or_return((ccrns_int)values[i] < plaintext_modulus, CCERR_PARAMETER);
    }
    for (uint32_t i = nvalues; i < poly->context->dims.degree; ++i) {
        cc_unit *data = CCPOLYZP_PO2CYC_DATA(poly, 0, indices[i]);
        ccn_seti(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, data, 0);
    }
    // Encoding indices are stored in bit-reversed order, so the inv_ntt restores to standard ordering
    return ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)poly);
}

int cche_encode_simd_int64(cche_plaintext_t ptext, cche_param_ctx_const_t param_ctx, uint32_t nvalues, const int64_t *values)
{
    CC_ENSURE_DIT_ENABLED

    cche_plaintext_init(ptext, param_ctx);

    ccpolyzp_po2cyc_coeff_t poly = cche_plaintext_polynomial(ptext);
    cc_require_or_return(nvalues <= poly->context->dims.degree, CCERR_PARAMETER);

    ccrns_int ptext_modulus = cche_plaintext_modulus(ptext);
    int64_t t = (int64_t)ptext_modulus;

    const uint32_t *indices = cche_param_ctx_encoding_indices_const(param_ctx);
    for (uint32_t i = 0; i < nvalues; ++i) {
        // Check decoded values are in expected range
        cc_require_or_return(values[i] <= (t - 1) >> 1, CCERR_PARAMETER);
        cc_require_or_return(values[i] >= -(t >> 1), CCERR_PARAMETER);
        ccrns_int value = ccpolyzp_po2cyc_centered_to_rem(values[i], ptext_modulus);
        cc_unit *data = CCPOLYZP_PO2CYC_DATA(poly, 0, indices[i]);
        ccpolyzp_po2cyc_rns_int_to_units(data, value);
    }
    for (uint32_t i = nvalues; i < poly->context->dims.degree; ++i) {
        cc_unit *data = CCPOLYZP_PO2CYC_DATA(poly, 0, indices[i]);
        ccn_seti(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, data, 0);
    }
    // Encoding indices are stored in bit-reversed order, so the inv_ntt restores to standard ordering
    return ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)poly);
}

int cche_decode_poly_uint64(uint32_t nvalues, uint64_t *cc_counted_by(nvalues) values, cche_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_coeff_const_t poly = cche_plaintext_polynomial_const(ptext);
    cc_require_or_return(nvalues <= poly->context->dims.degree, CCERR_PARAMETER);
    ccrns_int plaintext_modulus = cche_plaintext_modulus(ptext);

    for (uint32_t i = 0; i < nvalues; ++i) {
        ccrns_int coeff = ccpolyzp_po2cyc_coeff_data_int(poly, 0, i);
        cc_require_or_return(coeff < plaintext_modulus, CCERR_INTERNAL);
        values[i] = (uint64_t)coeff;
    }
    return CCERR_OK;
}

cc_size CCHE_DECODE_SIMD_UINT64_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    struct ccpolyzp_po2cyc_dims dims = { .degree = (uint32_t)degree, .nmoduli = (uint32_t)nmoduli };
    return cche_plaintext_nof_n(&dims);
}

int cche_decode_simd_uint64_ws(cc_ws_t ws,
                               cche_param_ctx_const_t param_ctx,
                               uint32_t nvalues,
                               uint64_t *values,
                               cche_plaintext_const_t ptext)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_coeff_const_t poly = cche_plaintext_polynomial_const(ptext);
    cc_require_or_return(nvalues <= poly->context->dims.degree, CCERR_PARAMETER);
    CC_DECL_BP_WS(ws, bp);

    cche_plaintext_t ptext_copy = CCHE_PLAINTEXT_ALLOC_WS(ws, poly->context);
    cche_plaintext_copy(ptext_copy, ptext);
    ccpolyzp_po2cyc_coeff_t poly_copy = cche_plaintext_polynomial(ptext_copy);
    cc_require((rv = ccpolyzp_po2cyc_fwd_ntt(poly_copy)) == CCERR_OK, errOut);
    ccrns_int plaintext_modulus = cche_plaintext_modulus(ptext);

    const uint32_t *indices = cche_param_ctx_encoding_indices_const(param_ctx);
    for (uint32_t i = 0; i < nvalues; ++i) {
        const cc_unit *data = CCPOLYZP_PO2CYC_DATA_CONST(poly_copy, 0, indices[i]);
        ccrns_int coeff = ccpolyzp_po2cyc_units_to_rns_int(data);
        // Check decoded values are in expected range
        cc_require_action(coeff < plaintext_modulus, errOut, rv = CCERR_INTERNAL);
        values[i] = coeff;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cche_decode_simd_uint64(cche_param_ctx_const_t param_ctx,
                            uint32_t nvalues,
                            uint64_t *cc_counted_by(nvalues) values,
                            cche_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_dims_const_t dims = &cche_plaintext_ctx(ptext)->dims;

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_DECODE_SIMD_UINT64_WORKSPACE_N(dims->degree, dims->nmoduli));
    int rv = cche_decode_simd_uint64_ws(ws, param_ctx, nvalues, values, ptext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

cc_size CCHE_DECODE_SIMD_INT64_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    return CCHE_DECODE_SIMD_UINT64_WORKSPACE_N(degree, nmoduli);
}

int cche_decode_simd_int64_ws(cc_ws_t ws,
                              cche_param_ctx_const_t param_ctx,
                              uint32_t nvalues,
                              int64_t *values,
                              cche_plaintext_const_t ptext)
{
    int rv = CCERR_OK;
    // First, decode values as unsigned
    cc_require((rv = cche_decode_simd_uint64_ws(ws, param_ctx, nvalues, (uint64_t *)values, ptext)) == CCERR_OK, errOut);

    // Then, map unsigned values to signed values
    ccrns_int ptext_modulus = cche_plaintext_modulus(ptext);
    int64_t t = (int64_t)ptext_modulus;

    for (uint32_t i = 0; i < nvalues; ++i) {
        int64_t coeff = ccpolyzp_po2cyc_rem_to_centered((ccrns_int)values[i], ptext_modulus);
        // Check decoded values are in expected range
        cc_require_or_return(coeff <= (t - 1) >> 1, CCERR_INTERNAL);
        cc_require_or_return(coeff >= -(t >> 1), CCERR_INTERNAL);
        values[i] = coeff;
    }

errOut:
    return rv;
}

int cche_decode_simd_int64(cche_param_ctx_const_t param_ctx,
                           uint32_t nvalues,
                           int64_t *cc_counted_by(nvalues) values,
                           cche_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_dims_const_t dims = &cche_plaintext_ctx(ptext)->dims;

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_DECODE_SIMD_INT64_WORKSPACE_N(dims->degree, dims->nmoduli));
    int rv = cche_decode_simd_int64_ws(ws, param_ctx, nvalues, values, ptext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cche_dcrt_plaintext_encode_ws(cc_ws_t ws,
                                  cche_dcrt_plaintext_t r,
                                  cche_plaintext_const_t ptext,
                                  cche_cipher_plain_ctx_const_t cipher_plain_ctx)
{
    int rv = CCERR_OK;
    uint32_t nmoduli = cipher_plain_ctx->cipher_ctx->dims.nmoduli;
    uint32_t degree = cipher_plain_ctx->cipher_ctx->dims.degree;

    ccpolyzp_po2cyc_coeff_const_t pt_poly = cche_plaintext_polynomial_const(ptext);
    ccpolyzp_po2cyc_eval_t r_poly = cche_dcrt_plaintext_polynomial(r);

    r_poly->context = cipher_plain_ctx->cipher_ctx;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        const cc_unit *increment =
            CCHE_CIPHER_PLAIN_CTX_PLAIN_INCREMENT(cipher_plain_ctx) + rns_idx * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        const cc_unit *val = CCPOLYZP_PO2CYC_DATA_CONST(pt_poly, 0, 0);
        cc_unit *result = CCPOLYZP_PO2CYC_DATA(r_poly, rns_idx, 0);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            cc_unit pt_plus_increment[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            // set the borrow
            cc_unit borrow = ccn_sub_ws(ws, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, pt_plus_increment, val, cipher_plain_ctx->t_half);
            ccn_add_ws(ws, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, pt_plus_increment, val, increment);
            ccn_mux(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, borrow, result, val, pt_plus_increment);

            result += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
            val += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        }
    }

    rv = ccpolyzp_po2cyc_fwd_ntt((ccpolyzp_po2cyc_coeff_t)r_poly);
    return rv;
}

int cche_dcrt_plaintext_encode(cche_dcrt_plaintext_t r,
                               cche_plaintext_const_t ptext,
                               cche_param_ctx_const_t param_ctx,
                               uint32_t nmoduli)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(nmoduli <= cche_param_ctx_ciphertext_ctx_nmoduli(param_ctx), CCERR_PARAMETER);
    cche_cipher_plain_ctx_const_t cipher_plain_ctx = cche_param_ctx_cipher_plain_ctx_const(param_ctx, nmoduli);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_DCRT_PLAINTEXT_ENCODE_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF));
    int rv = cche_dcrt_plaintext_encode_ws(ws, r, ptext, cipher_plain_ctx);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
