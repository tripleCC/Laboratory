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

int ccbfv_ciphertext_mod_switch_down_ws(cc_ws_t ws, ccbfv_ciphertext_coeff_t ctext)
{
    int rv = CCERR_OK;

    cc_size poly_size = ccpolyzp_po2cyc_nof_n(&ccbfv_ciphertext_coeff_ctx(ctext)->dims);
    ccpolyzp_po2cyc_coeff_t ctext_poly = (ccpolyzp_po2cyc_coeff_t)ccbfv_ciphertext_coeff_polynomial(ctext, 0);
    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        rv = ccpolyzp_po2cyc_divide_and_round_q_last_ws(ws, ctext_poly);
        cc_require(rv == CCERR_OK, errOut);
        // Keep polynomials subsequent in memory
        if (poly_idx > 0) {
            ccpolyzp_po2cyc_coeff_copy((ccpolyzp_po2cyc_coeff_t)ccbfv_ciphertext_coeff_polynomial(ctext, poly_idx), ctext_poly);
        }
        // Note, we can't use ccbfv_ciphertext_coeff_polynomial(ctext, poly_idx) here since not all
        // polynomials have been switched to the smaller context
        ctext_poly = (ccpolyzp_po2cyc_coeff_t)((cc_unit *)ctext_poly + poly_size);
    }

errOut:
    return rv;
}

int ccbfv_ciphertext_mod_switch_down_to_single_ws(cc_ws_t ws, ccbfv_ciphertext_coeff_t ctext)
{
    int rv = CCERR_OK;

    uint32_t nmoduli = ccbfv_ciphertext_coeff_ctx(ctext)->dims.nmoduli;
    while (nmoduli > 1) {
        rv = ccbfv_ciphertext_mod_switch_down_ws(ws, ctext);
        cc_require(rv == CCERR_OK, errOut);
        nmoduli--;
    }

errOut:
    return rv;
}
