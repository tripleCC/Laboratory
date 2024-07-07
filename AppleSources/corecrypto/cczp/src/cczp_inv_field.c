/* Copyright (c) (2015-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cczp_internal.h"

int cczp_inv_field_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    int rv = CCERR_INTERNAL;
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *pm2 = CC_ALLOC_WS(ws, n);

    // Compute (p-2).
    if (ccn_sub1(n, pm2, cczp_prime(zp), 2) > 0) {
        goto out;
    }

    // Compute x^(p-2).
    rv = cczp_power_fast_ws(ws, zp, r, x, pm2);

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_WORKSPACE_OVERRIDE(cczp_inv_ws, cczp_inv_field_ws)
