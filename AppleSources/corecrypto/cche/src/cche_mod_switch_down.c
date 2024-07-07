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

#include "cche_internal.h"

cc_size CCHE_CIPHERTEXT_MOD_SWITCH_DOWN_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    return CC_MAX_EVAL(CCPOLYZP_PO2CYC_DIVIDE_AND_ROUND_Q_LAST_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
                       CCPOLYZP_PO2CYC_BASE_CONVERT_MOD_T_DIVIDE_AND_ROUND_Q_LAST_WORKSPACE_N(degree, nmoduli));
}

int cche_ciphertext_mod_switch_down_ws(cc_ws_t ws, cche_ciphertext_coeff_t ctext)
{
    int rv = CCERR_OK;

    cc_size poly_size = ccpolyzp_po2cyc_nof_n(&cche_ciphertext_coeff_ctx(ctext)->dims);
    ccpolyzp_po2cyc_coeff_t ctext_poly = (ccpolyzp_po2cyc_coeff_t)cche_ciphertext_coeff_polynomial(ctext, 0);
    cche_scheme_t he_scheme = cche_param_ctx_encrypt_params_const(ctext->param_ctx)->he_scheme;
    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        switch (he_scheme) {
        case CCHE_SCHEME_BFV: {
            rv = ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, ctext_poly);
            cc_require(rv == CCERR_OK, errOut);
            break;
        }
        case CCHE_SCHEME_BGV: {
            cche_decrypt_ctx_const_t decrypt_ctx = cche_param_ctx_decrypt_ctx_const(ctext->param_ctx);
            ccpolyzp_po2cyc_base_convert_const_t base_cvt =
                cche_decrypt_ctx_base_convert_const(decrypt_ctx, ctext_poly->context->dims.nmoduli);

            rv = ccpolyzp_po2cyc_fwd_ntt(ctext_poly);
            cc_require(rv == CCERR_OK, errOut);

            rv = ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws(ws, (ccpolyzp_po2cyc_eval_t)ctext_poly, base_cvt);
            cc_require(rv == CCERR_OK, errOut);

            rv = ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)ctext_poly);
            cc_require(rv == CCERR_OK, errOut);

            if (poly_idx == 0) {
                ctext->correction_factor =
                    ccpolyzp_po2cyc_base_convert_scale_inv_q_last_mod_t(ctext->correction_factor, base_cvt);
            }
            break;
        }

        case CCHE_SCHEME_UNSPECIFIED: {
            rv = CCERR_PARAMETER;
            goto errOut;
        }
        }

        // Keep polynomials subsequent in memory
        if (poly_idx > 0) {
            ccpolyzp_po2cyc_coeff_copy((ccpolyzp_po2cyc_coeff_t)cche_ciphertext_coeff_polynomial(ctext, poly_idx), ctext_poly);
        }
        // Note, we can't use cche_ciphertext_coeff_polynomial(ctext, poly_idx) here since not all
        // polynomials have been switched to the smaller context
        ctext_poly = (ccpolyzp_po2cyc_coeff_t)((cc_unit *)ctext_poly + poly_size);
    }

errOut:
    return rv;
}

cc_size CCHE_CIPHERTEXT_MOD_SWITCH_DOWN_TO_SINGLE_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    // Assume CCHE_CIPHERTEXT_MOD_SWITCH_DOWN_WORKSPACE_N increases with nmoduli
    return CCHE_CIPHERTEXT_MOD_SWITCH_DOWN_WORKSPACE_N(degree, nmoduli);
}

int cche_ciphertext_mod_switch_down_to_single_ws(cc_ws_t ws, cche_ciphertext_coeff_t ctext)
{
    int rv = CCERR_OK;

    uint32_t nmoduli = cche_ciphertext_coeff_ctx(ctext)->dims.nmoduli;
    while (nmoduli > 1) {
        rv = cche_ciphertext_mod_switch_down_ws(ws, ctext);
        cc_require(rv == CCERR_OK, errOut);
        nmoduli--;
    }

errOut:
    return rv;
}
