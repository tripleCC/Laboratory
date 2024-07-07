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
#include "ccbfv_internal.h"
#include "ccpolyzp_po2cyc_internal.h"

uint32_t ccbfv_ciphertext_fresh_npolys(void)
{
    CC_ENSURE_DIT_ENABLED

    return CCBFV_CIPHERTEXT_FRESH_NPOLYS;
}

int ccbfv_ciphertext_fwd_ntt(ccbfv_ciphertext_coeff_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    int rv = CCERR_OK;
    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        ccpolyzp_po2cyc_coeff_t poly = ccbfv_ciphertext_coeff_polynomial(ctext, poly_idx);
        cc_require((rv = ccpolyzp_po2cyc_fwd_ntt(poly)) == CCERR_OK, errOut);
    }
errOut:
    return rv;
}

int ccbfv_ciphertext_inv_ntt(ccbfv_ciphertext_eval_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    int rv = CCERR_OK;
    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        ccpolyzp_po2cyc_eval_t poly = ccbfv_ciphertext_eval_polynomial(ctext, poly_idx);
        cc_require((rv = ccpolyzp_po2cyc_inv_ntt(poly)) == CCERR_OK, errOut);
    }
errOut:
    return rv;
}
