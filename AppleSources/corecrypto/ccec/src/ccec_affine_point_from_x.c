/* Copyright (c) (2014-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccec_internal.h"
#include "cczp_internal.h"
#include "cc_workspaces.h"

int ccec_affine_point_from_x_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_affine_point_t r, const cc_unit *x)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t =  CC_ALLOC_WS(ws, n);
    cc_unit *u = CC_ALLOC_WS(ws, n);

    if (ccn_cmp(ccec_cp_n(cp), x, ccec_cp_p(cp)) >= 0) {
        CC_FREE_BP_WS(ws, bp);
        return CCERR_PARAMETER;
    }

    cczp_to_ws(ws, zp, ccec_point_x(r, cp), x);
    cczp_sqr_ws(ws, zp, t, ccec_point_x(r, cp));                      // t = sx^2
    cczp_mul_ws(ws, zp, t, t, ccec_point_x(r, cp));                   // t = sx^3
    cczp_add_ws(ws, zp, u, ccec_point_x(r, cp), ccec_point_x(r, cp)); // u = 2sx
    cczp_add_ws(ws, zp, u, u, ccec_point_x(r, cp));                   // u = 3sx
    cczp_sub_ws(ws, zp, t, t, u);                                     // t = sx^3 - 3sx
    cczp_add_ws(ws, zp, t, t, ccec_cp_b(cp));                         // t = sx^3 - 3sx + b

    // y might not be a quadratic residue if there's no point with the given x
    int rv = cczp_sqrt_ws(ws, zp, ccec_point_y(r, cp), t); // y' = sqrt (sx^3 - 3sx + b)
    if (rv) {
        CC_FREE_BP_WS(ws, bp);
        return rv;
    }

    cczp_from_ws(ws, zp, ccec_point_x(r, cp), ccec_point_x(r, cp));
    cczp_from_ws(ws, zp, ccec_point_y(r, cp), ccec_point_y(r, cp));
    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}
