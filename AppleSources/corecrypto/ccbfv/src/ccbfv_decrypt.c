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
#include "ccbfv_util.h"
#include "ccbfv_decrypt_ctx.h"
#include "ccpolyzp_po2cyc_base_convert.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"

cc_size ccbfv_decrypt_ctx_nof_n(ccpolyzp_po2cyc_dims_const_t dims)
{
    // struct storage, rounded up to nearest number of cc_units
    cc_size rv = ccn_nof_size(sizeof_struct_ccbfv_decrypt_ctx());

    struct ccpolyzp_po2cyc_dims t_gamma_dims = { .degree = dims->degree, .nmoduli = 2 };
    rv += ccpolyzp_po2cyc_ctx_chain_nof_n(&t_gamma_dims); // storage for [t, gamma] context chain

    // storage for base converters for each number of moduli
    uint32_t nmoduli = CC_MAX_EVAL(1, dims->nmoduli);
    for (uint32_t i = 1; i <= nmoduli; ++i) {
        rv += ccpolyzp_po2cyc_base_convert_nof_n(i, t_gamma_dims.nmoduli);
    }

    return rv;
}

cc_size CCBFV_DECRYPT_CTX_INIT_WORKSPACE_N(cc_size nmoduli)
{
    return CC_MAX_EVAL(CCPOLYZP_PO2CYC_CTX_INIT_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
                       CCPOLYZP_PO2CYC_BASE_CONVERT_INIT_WORKSPACE_N(nmoduli));
}

int ccbfv_decrypt_ctx_init_ws(cc_ws_t ws, ccbfv_decrypt_ctx_t decrypt_ctx, ccbfv_param_ctx_const_t param_ctx)
{
    int rv = CCERR_OK;

    decrypt_ctx->param_ctx = param_ctx;
    ccpolyzp_po2cyc_ctx_chain_t t_gamma_ctx_chain = CCBFV_DECRYPT_CTX_T_GAMMA_CTX_CHAIN(decrypt_ctx);
    uint32_t degree = ccbfv_param_ctx_polynomial_degree(param_ctx);

    // t_gamma context chain
    struct ccpolyzp_po2cyc_dims dims_t_gamma = { .degree = degree, .nmoduli = 2 };
    ccrns_int moduli_t_gamma[] = { ccbfv_param_ctx_plaintext_modulus(param_ctx), CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA };
    rv = ccpolyzp_po2cyc_ctx_chain_init_ws(ws, t_gamma_ctx_chain, &dims_t_gamma, moduli_t_gamma);
    cc_require(rv == CCERR_OK, errOut);
    ccpolyzp_po2cyc_ctx_const_t t_gamma_ctx = ccpolyzp_po2cyc_ctx_chain_context_const(t_gamma_ctx_chain, dims_t_gamma.nmoduli);

    // base converter contexts
    ccpolyzp_po2cyc_ctx_const_t ctext_ctx = ccbfv_param_ctx_ciphertext_context(decrypt_ctx->param_ctx);
    while (ctext_ctx != NULL) {
        uint32_t nmoduli = ctext_ctx->dims.nmoduli;
        ccpolyzp_po2cyc_base_convert_t base_cvt = ccbfv_decrypt_ctx_base_convert(decrypt_ctx, nmoduli);
        cc_require((rv = ccpolyzp_po2cyc_base_convert_init_ws(ws, base_cvt, ctext_ctx, t_gamma_ctx)) == CCERR_OK, errOut);
        ctext_ctx = ctext_ctx->next;
    }

errOut:
    return rv;
}

CC_PURE cc_size CCBFV_DECRYPT_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    struct ccpolyzp_po2cyc_dims dims = { .degree = (uint32_t)degree, .nmoduli = (uint32_t)nmoduli };
    return ccbfv_ciphertext_nof_n(&dims, ccbfv_ciphertext_fresh_npolys()) +
           CCPOLYZP_PO2CYC_BASE_CONVERT_DIVIDE_AND_ROUND_WORKSPACE_N(degree, nmoduli);
}

int ccbfv_decrypt_ws(cc_ws_t ws,
                     ccbfv_plaintext_t ptext,
                     ccbfv_param_ctx_const_t param_ctx,
                     ccbfv_ciphertext_coeff_const_t ctext,
                     ccbfv_secret_key_const_t secret_key)
{
    int rv = CCERR_OK;
    cc_require_or_return(ctext->npolys == ccbfv_ciphertext_fresh_npolys(), CCERR_PARAMETER);
    cc_require_or_return(ccbfv_param_ctx_eq(ctext->param_ctx, param_ctx), CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(secret_key->context, ccbfv_param_ctx_encrypt_key_context(param_ctx)),
                         CCERR_PARAMETER);

    CC_DECL_BP_WS(ws, bp);
    ccbfv_plaintext_init(ptext, param_ctx);

    ccbfv_ciphertext_coeff_t ctext_copy = CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_ciphertext_coeff_ctx(ctext), ctext->npolys);
    ccbfv_ciphertext_coeff_copy(ctext_copy, ctext);

    ccpolyzp_po2cyc_coeff_t c0 = ccbfv_ciphertext_coeff_polynomial(ctext_copy, 0);
    ccpolyzp_po2cyc_coeff_t c1 = ccbfv_ciphertext_coeff_polynomial(ctext_copy, 1);

    // c1 := c0 + c1 * s
    cc_require((rv = ccpolyzp_po2cyc_fwd_ntt(c1)) == CCERR_OK, errOut);
    ccbfv_mul_poly_sk((ccpolyzp_po2cyc_eval_t)c1, (ccpolyzp_po2cyc_eval_const_t)c1, secret_key);
    cc_require((rv = ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)c1)) == CCERR_OK, errOut);
    ccpolyzp_po2cyc_coeff_add(c1, c0, c1);

    // divide and scale and round c1
    ccbfv_decrypt_ctx_const_t decrypt_ctx = ccbfv_param_ctx_decrypt_ctx_const(param_ctx);
    ccpolyzp_po2cyc_base_convert_const_t base_cvt = ccbfv_decrypt_ctx_base_convert_const(decrypt_ctx, c1->context->dims.nmoduli);
    ccpolyzp_po2cyc_coeff_t ptext_poly = ccbfv_plaintext_polynomial(ptext);
    cc_require((rv = ccpolyzp_po2cyc_base_convert_divide_and_round_ws(ws, ptext_poly, c1, base_cvt)) == CCERR_OK, errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int ccbfv_decrypt(ccbfv_plaintext_t ptext,
                  ccbfv_param_ctx_const_t param_ctx,
                  ccbfv_ciphertext_coeff_const_t ctext,
                  ccbfv_secret_key_const_t secret_key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(
        ws,
        CCBFV_DECRYPT_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(param_ctx), ccbfv_ciphertext_coeff_ctx(ctext)->dims.nmoduli));
    int rv = ccbfv_decrypt_ws(ws, ptext, param_ctx, ctext, secret_key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
