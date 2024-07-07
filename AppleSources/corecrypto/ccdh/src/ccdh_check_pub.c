/* Copyright (c) (2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdh_internal.h"

/* Check the validity of a public key with respect to the domain parameters */
int ccdh_check_pub_ws(cc_ws_t ws, ccdh_const_gp_t gp, ccdh_pub_ctx_t public_key)
{
    cc_size n = ccdh_gp_n(gp);

    /* verify keys are using the same prime */
    if (n != ccdh_ctx_n(public_key)) {
        return CCDH_DOMAIN_PARAMETER_MISMATCH;
    }
    if (ccn_cmp(n, ccdh_gp_prime(gp), ccdh_ctx_prime(public_key))) {
        return CCDH_DOMAIN_PARAMETER_MISMATCH;
    }
    /* Check that p is odd */
    if (ccn_bit(ccdh_gp_prime(gp), 0) == 0) {
        return CCDH_INVALID_DOMAIN_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    /* Check public key y */
    int result = CCDH_SAFETY_CHECK;
    /* 1) Check y < p - 1 */
    if (ccn_sub1(n, t, ccdh_gp_prime(gp), 1) != 0) { // Compute p-1, borrow not expected.
        goto errOut;
    }
    if (ccn_cmp(n, ccdh_ctx_y(public_key), t) >= 0) { // Error if y >= p-1
        goto errOut;
    }
    /* 2) Check 1 < y */
    if (ccn_is_zero_or_one(n, ccdh_ctx_y(public_key))) { // Error if y<=1
        goto errOut;
    }

    /* 3) Check order of y */
    if (ccdh_gp_order_bitlen(gp)) {
        /* Possible only if the order is set in the domain parameter */
        if (cczp_mm_power_fast_ws(ws, ccdh_gp_zp(gp), t, ccdh_ctx_y(public_key), ccdh_gp_order(gp))) {
            goto errOut;
        }
        /* y^q == 1 otherwise, y is not in the correct group, exposing to
         small subgroup attacks */
        if (!ccn_is_one(n, t)) {
            goto errOut;
        }
    }

    /* If we get here, it all good */
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}
