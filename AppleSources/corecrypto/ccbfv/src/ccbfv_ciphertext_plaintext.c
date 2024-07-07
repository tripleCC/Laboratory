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

#include "ccbfv_internal.h"
#include "ccbfv_cipher_plain_ctx.h"
#include "ccpolyzp_po2cyc_internal.h"

cc_size CCBFV_CIPHERTEXT_PLAINTEXT_ADD_WORKSPACE_N(cc_size degree)
{
    struct ccpolyzp_po2cyc_dims plaintext_dims = { .degree = (uint32_t)degree, .nmoduli = 1 };
    return (ccpolyzp_po2cyc_nof_n(&plaintext_dims)) +
           CC_MAX_EVAL(CCN_ADD_WORKSPACE_N(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
                       CC_MAX_EVAL(CCN_MUL_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
                                   CCPOLYZP_PO2CYC_SCALAR_DIVMOD_WORKSPACE_N(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF)));
}

int ccbfv_ciphertext_plaintext_add_ws(cc_ws_t ws,
                                      ccbfv_ciphertext_coeff_t r,
                                      ccbfv_ciphertext_coeff_const_t ctext,
                                      ccbfv_plaintext_const_t ptext)
{
    int rv = CCERR_OK;
    cc_require_or_return(ctext->npolys == ccbfv_ciphertext_fresh_npolys(), CCERR_PARAMETER);
    cc_require_or_return(r->npolys == ccbfv_ciphertext_fresh_npolys(), CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_ciphertext_coeff_ctx(ctext), ccbfv_ciphertext_coeff_ctx(r)),
                         CCERR_PARAMETER);

    CC_DECL_BP_WS(ws, bp);

    ccbfv_param_ctx_const_t param_ctx = ptext->param_ctx;
    uint32_t degree = ccbfv_param_ctx_polynomial_degree(ctext->param_ctx);
    uint32_t nmoduli = ccbfv_ciphertext_coeff_ctx(ctext)->dims.nmoduli;
    ccbfv_cipher_plain_ctx_const_t cipher_plain_ctx = ccbfv_param_ctx_cipher_plain_ctx_const(param_ctx, nmoduli);
    ccpolyzp_po2cyc_ctx_const_t ctext_ctx = ccbfv_ciphertext_coeff_ctx(r);
    ccpolyzp_po2cyc_coeff_t r_poly0 = ccbfv_ciphertext_coeff_polynomial(r, 0);
    ccpolyzp_po2cyc_coeff_const_t ctext_poly0 = ccbfv_ciphertext_coeff_polynomial_const(ctext, 0);

    struct ccpolyzp_po2cyc_dims plaintext_dims = { .degree = degree, .nmoduli = 1 };
    ccpolyzp_po2cyc_coeff_const_t ptext_poly = ccbfv_plaintext_polynomial_const(ptext);
    ccrns_modulus_const_t t = &ccbfv_param_ctx_plaintext_context(param_ctx)->ccrns_q_last;

    // Will store floor(([q]_t * plain[i] + floor((t+1)/2)) / t)
    ccpolyzp_po2cyc_coeff_t adjust = (ccpolyzp_po2cyc_coeff_t)CCPOLYZP_PO2CYC_ALLOC_WS(ws, &plaintext_dims);
    adjust->context = ptext_poly->context;
    cc_unit t_half[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_setn(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, t_half, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, cipher_plain_ctx->t_half);
    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        cc_unit prod[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        cc_unit sum[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccn_mul_ws(ws,
                   CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                   prod,
                   cipher_plain_ctx->q_mod_t,
                   CCPOLYZP_PO2CYC_DATA_CONST(ptext_poly, 0, coeff_idx));
        cc_unit carry = ccn_add_ws(ws, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, sum, prod, t_half);
        cc_require_action(carry == 0, errOut, rv = CCERR_INTERNAL);
        ccpolyzp_po2cyc_scalar_divmod_ws(ws, CCPOLYZP_PO2CYC_DATA(adjust, 0, coeff_idx), sum, t);
    }

    const cc_unit *delta = CCBFV_CIPHER_PLAIN_CTX_DELTA_CONST(cipher_plain_ctx);
    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_modulus_const_t q_i = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctext_ctx, rns_idx);
        ccrns_int delta_int = ccpolyzp_po2cyc_units_to_rns_int(delta);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            ccrns_int ptext_coeff = ccpolyzp_po2cyc_coeff_data_int(ptext_poly, 0, coeff_idx);
            ccrns_int prod = ccpolyzp_po2cyc_scalar_mul_mod(ptext_coeff, delta_int, q_i);
            ccrns_int sum =
                ccpolyzp_po2cyc_scalar_add_mod(prod, ccpolyzp_po2cyc_coeff_data_int(adjust, 0, coeff_idx), q_i->value);
            ccrns_int r_int =
                ccpolyzp_po2cyc_scalar_add_mod(sum, ccpolyzp_po2cyc_coeff_data_int(ctext_poly0, rns_idx, coeff_idx), q_i->value);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r_poly0, rns_idx, coeff_idx), r_int);
        }
        delta += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    }
    ccpolyzp_po2cyc_coeff_t r_poly1 = ccbfv_ciphertext_coeff_polynomial(r, 1);
    ccpolyzp_po2cyc_coeff_const_t ctext_poly1 = ccbfv_ciphertext_coeff_polynomial_const(ctext, 1);
    ccpolyzp_po2cyc_coeff_copy(r_poly1, ctext_poly1);
errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccbfv_ciphertext_plaintext_add(ccbfv_ciphertext_coeff_t r,
                                   ccbfv_ciphertext_coeff_const_t ctext,
                                   ccbfv_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws,
                              CCBFV_CIPHERTEXT_PLAINTEXT_ADD_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(ctext->param_ctx)));
    int rv = ccbfv_ciphertext_plaintext_add_ws(ws, r, ctext, ptext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

cc_size CCBFV_CIPHERTEXT_COEFF_PLAINTEXT_MUL_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    struct ccpolyzp_po2cyc_dims dcrt_plaintext_dims = { .degree = (uint32_t)degree, .nmoduli = (uint32_t)nmoduli };
    return ccbfv_dcrt_plaintext_nof_n(&dcrt_plaintext_dims);
}

int ccbfv_ciphertext_coeff_plaintext_mul_ws(cc_ws_t ws,
                                            ccbfv_ciphertext_coeff_t r,
                                            ccbfv_ciphertext_coeff_const_t ctext,
                                            ccbfv_plaintext_const_t ptext)
{
    int rv = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

    cc_require_or_return(r->npolys == ctext->npolys, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_ciphertext_coeff_ctx(r), ccbfv_ciphertext_coeff_ctx(ctext)),
                         CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_plaintext_ctx(ptext), ccbfv_param_ctx_plaintext_context(ctext->param_ctx)),
                         CCERR_PARAMETER);

    ccbfv_dcrt_plaintext_t dcrt_plaintext = CCBFV_DCRT_PLAINTEXT_ALLOC_WS(ws, ccbfv_ciphertext_coeff_ctx(ctext));
    ccbfv_cipher_plain_ctx_const_t cipher_plain_ctx =
        ccbfv_param_ctx_cipher_plain_ctx_const(ptext->param_ctx, ccbfv_ciphertext_coeff_ctx(ctext)->dims.nmoduli);

    rv = ccbfv_dcrt_plaintext_encode_ws(ws, dcrt_plaintext, ptext, cipher_plain_ctx);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccbfv_ciphertext_coeff_dcrt_plaintext_mul(r, ctext, dcrt_plaintext);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccbfv_ciphertext_coeff_plaintext_mul(ccbfv_ciphertext_coeff_t r,
                                         ccbfv_ciphertext_coeff_const_t ctext,
                                         ccbfv_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_dims_const_t dims = &ccbfv_ciphertext_coeff_ctx(ctext)->dims;
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCBFV_CIPHERTEXT_COEFF_PLAINTEXT_MUL_WORKSPACE_N(dims->degree, dims->nmoduli));
    int rv = ccbfv_ciphertext_coeff_plaintext_mul_ws(ws, r, ctext, ptext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_ciphertext_coeff_dcrt_plaintext_mul(ccbfv_ciphertext_coeff_t r,
                                              ccbfv_ciphertext_coeff_const_t ctext,
                                              ccbfv_dcrt_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED
    int rv = CCERR_OK;

    cc_require_or_return(r->npolys == ctext->npolys, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_ciphertext_coeff_ctx(r), ccbfv_ciphertext_coeff_ctx(ctext)),
                         CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_dcrt_plaintext_ctx(ptext), ccbfv_ciphertext_coeff_ctx(ctext)),
                         CCERR_PARAMETER);

    uint32_t npolys = ctext->npolys;
    ccpolyzp_po2cyc_eval_const_t ptext_poly = ccbfv_dcrt_plaintext_polynomial_const(ptext);

    if (r != ctext) {
        ccbfv_ciphertext_coeff_copy(r, ctext);
    }

    cc_require((rv = ccbfv_ciphertext_fwd_ntt(r)) == CCERR_OK, errOut);
    ccbfv_ciphertext_eval_t r_eval = (ccbfv_ciphertext_eval_t)r;

    for (uint32_t poly_idx = 0; poly_idx < npolys; ++poly_idx) {
        ccpolyzp_po2cyc_eval_t r_eval_poly = ccbfv_ciphertext_eval_polynomial(r_eval, poly_idx);
        ccpolyzp_po2cyc_eval_mul(r_eval_poly, r_eval_poly, ptext_poly);
    }

    cc_require((rv = ccbfv_ciphertext_inv_ntt(r_eval)) == CCERR_OK, errOut);

errOut:
    return rv;
}

cc_size CCBFV_CIPHERTEXT_EVAL_PLAINTEXT_MUL_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    struct ccpolyzp_po2cyc_dims dcrt_plaintext_dims = { .degree = (uint32_t)degree, .nmoduli = (uint32_t)nmoduli };
    return ccbfv_dcrt_plaintext_nof_n(&dcrt_plaintext_dims);
}

int ccbfv_ciphertext_eval_plaintext_mul_ws(cc_ws_t ws,
                                           ccbfv_ciphertext_eval_t r,
                                           ccbfv_ciphertext_eval_const_t ctext,
                                           ccbfv_plaintext_const_t ptext)
{
    int rv = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

    cc_require_or_return(r->npolys == ctext->npolys, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_ciphertext_eval_ctx(r), ccbfv_ciphertext_eval_ctx(ctext)), CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_plaintext_ctx(ptext), ccbfv_param_ctx_plaintext_context(ctext->param_ctx)),
                         CCERR_PARAMETER);

    ccbfv_dcrt_plaintext_t dcrt_plaintext = CCBFV_DCRT_PLAINTEXT_ALLOC_WS(ws, ccbfv_ciphertext_eval_ctx(ctext));
    ccbfv_cipher_plain_ctx_const_t cipher_plain_ctx =
        ccbfv_param_ctx_cipher_plain_ctx_const(ptext->param_ctx, ccbfv_ciphertext_eval_ctx(ctext)->dims.nmoduli);

    rv = ccbfv_dcrt_plaintext_encode_ws(ws, dcrt_plaintext, ptext, cipher_plain_ctx);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccbfv_ciphertext_eval_dcrt_plaintext_mul(r, ctext, dcrt_plaintext);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccbfv_ciphertext_eval_plaintext_mul(ccbfv_ciphertext_eval_t r,
                                        ccbfv_ciphertext_eval_const_t ctext,
                                        ccbfv_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_dims_const_t dims = &ccbfv_ciphertext_eval_ctx(ctext)->dims;
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCBFV_CIPHERTEXT_COEFF_PLAINTEXT_MUL_WORKSPACE_N(dims->degree, dims->nmoduli));
    int rv = ccbfv_ciphertext_eval_plaintext_mul_ws(ws, r, ctext, ptext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_ciphertext_eval_dcrt_plaintext_mul(ccbfv_ciphertext_eval_t r,
                                             ccbfv_ciphertext_eval_const_t ctext,
                                             ccbfv_dcrt_plaintext_const_t ptext)
{
    CC_ENSURE_DIT_ENABLED
    cc_require_or_return(r->npolys == ctext->npolys, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_ciphertext_eval_ctx(r), ccbfv_ciphertext_eval_ctx(ctext)), CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(ccbfv_dcrt_plaintext_ctx(ptext), ccbfv_ciphertext_eval_ctx(ctext)),
                         CCERR_PARAMETER);

    uint32_t npolys = ctext->npolys;

    ccpolyzp_po2cyc_eval_const_t ptext_poly = ccbfv_dcrt_plaintext_polynomial_const(ptext);
    for (uint32_t poly_idx = 0; poly_idx < npolys; ++poly_idx) {
        ccpolyzp_po2cyc_eval_t r_poly = ccbfv_ciphertext_eval_polynomial(r, poly_idx);
        ccpolyzp_po2cyc_eval_const_t ctext_poly = ccbfv_ciphertext_eval_polynomial_const(ctext, poly_idx);
        ccpolyzp_po2cyc_eval_mul(r_poly, ctext_poly, ptext_poly);
    }

    return CCERR_OK;
}
