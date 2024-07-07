/* Copyright (c) (2010,2011,2015-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "cczp_internal.h"
#include "cc_workspaces.h"

void ccec_full_sub_normalized_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_projective_point_t r,
                                 ccec_const_projective_point_t s,
                                 ccec_const_projective_point_t t)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));

    if (ccec_is_point_at_infinity(cp, s)) {
        // set r = -t
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(t, cp));
        cczp_negate(zp, ccec_point_y(r, cp), ccec_const_point_y(t, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(t, cp));
    } else {
        ccec_add_normalized_ws(ws, cp, r, s, t, true /* subtract */);
    }

    CC_FREE_BP_WS(ws, bp);
}

void ccec_full_sub_ws(cc_ws_t ws,
                      ccec_const_cp_t cp,
                      ccec_projective_point_t r,
                      ccec_const_projective_point_t s,
                      ccec_const_projective_point_t t)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *u = CCEC_ALLOC_POINT_WS(ws, n);

    // u := -t
    ccn_set(n, ccec_point_x(u, cp), ccec_const_point_x(t, cp));
    cczp_negate(zp, ccec_point_y(u, cp), ccec_const_point_y(t, cp));
    ccn_set(n, ccec_point_z(u, cp), ccec_const_point_z(t, cp));

    // r := s + u
    ccec_full_add_ws(ws, cp, r, s, u);

    CC_FREE_BP_WS(ws, bp);
}

int ccec_full_sub(ccec_const_cp_t cp,
                  ccec_projective_point_t r,
                  ccec_const_projective_point_t s,
                  ccec_const_projective_point_t t)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_FULL_SUB_WORKSPACE_N(ccec_cp_n(cp)));
    ccec_full_sub_ws(ws, cp, r, s, t);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
