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

#include "cche_util.h"

void cche_mul_poly_sk(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, cche_secret_key_const_t sk)
{
    const ccpolyzp_po2cyc_eval_const_t y = (ccpolyzp_po2cyc_eval_const_t)sk;
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, x->context));
    cc_assert(r->context->dims.nmoduli <= y->context->dims.nmoduli);
    cc_assert(ccpolyzp_po2cyc_ctx_is_parent(sk->context, r->context));
    uint32_t degree = x->context->dims.degree;
    uint32_t nmoduli = x->context->dims.nmoduli;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_modulus_const_t qi = ccpolyzp_po2cyc_ctx_ccrns_modulus(x->context, rns_idx);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, coeff_idx);
            const ccrns_int x_coeff = ccpolyzp_po2cyc_eval_data_int(x, rns_idx, coeff_idx);
            const ccrns_int y_coeff = ccpolyzp_po2cyc_eval_data_int((ccpolyzp_po2cyc_eval_const_t)sk, rns_idx, coeff_idx);
            const ccrns_int r_coeff = ccpolyzp_po2cyc_scalar_mul_mod(x_coeff, y_coeff, qi);
            ccpolyzp_po2cyc_rns_int_to_units(r_data, r_coeff);
        }
    }
}
