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
#include "ccec_internal.h"
#include "cczp_internal.h"
#include "cc_workspaces.h"

bool ccec_is_point_projective_ws(cc_ws_t ws, ccec_const_cp_t cp,
                                 ccec_const_projective_point_t s)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n  = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);
    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *z4 = CC_ALLOC_WS(ws, n);

    /* For Jacobian representation */
    cczp_sqr_ws(ws, zp, u, ccec_const_point_z(s, cp));              // u = sz^2
    cczp_mul_ws(ws, zp, t, u, ccec_cp_b(cp));                       // t = b*sz^2
    cczp_sqr_ws(ws, zp, z4, u);                                     // z4 = sz^4
    cczp_add_ws(ws, zp, u, ccec_const_point_x(s, cp), ccec_const_point_x(s, cp));  // u = 2sx
    cczp_add_ws(ws, zp, u, u, ccec_const_point_x(s, cp));           // u = 3sx
    cczp_sub_ws(ws, zp, t, t, u);                                   // t = b*sz^2 - 3sx
    cczp_mul_ws(ws, zp, t, t, z4);                                  // t = b*sz^6 - 3sx*sz^4
    cczp_sqr_ws(ws, zp, u, ccec_const_point_x(s, cp));              // u = sx^2
    cczp_mul_ws(ws, zp, u, u, ccec_const_point_x(s, cp));           // u = sx^3
    cczp_add_ws(ws, zp, t, t, u);                                   // t = sx^3 + b*sz^6 - 3sx*sz^4
    cczp_sqr_ws(ws, zp, u, ccec_const_point_y(s, cp));              // u = sy^2

    bool is_point = (ccn_cmp(n, u, t) == 0);
    CC_FREE_BP_WS(ws, bp);
    return is_point;
}

bool ccec_is_point_ws(cc_ws_t ws, ccec_const_cp_t cp,
                      ccec_const_projective_point_t s)
{
    return ccec_is_point_projective_ws(ws, cp, s);
}

bool ccec_is_point(ccec_const_cp_t cp, ccec_const_projective_point_t s)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_IS_POINT_PROJECTIVE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_is_point_projective_ws(ws, cp, s);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

bool ccec_is_point_at_infinity(ccec_const_cp_t cp, ccec_const_projective_point_t s)
{
    cc_size n = ccec_cp_n(cp);
    return ccn_is_zero(n, ccec_point_z(s, cp));
}
