/* Copyright (c) (2010-2023) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "ccec_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

int ccec_affinify_jacobian_ws(cc_ws_t ws,
                              ccec_const_cp_t cp,
                              ccec_affine_point_t r,
                              ccec_const_projective_point_t s)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_t zp = ccec_cp_zp(cp);

    if (ccec_is_point_at_infinity(cp, s)) {
        return CCERR_PARAMETER;
    }

#if CCEC_DEBUG
    ccec_plprint(cp, "ccec_affinify input", s);
#endif

    CC_DECL_BP_WS(ws, bp);
    // Allows "in place" operation => the result can be set in any of the point coordinate.
    cc_unit *lambda = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    int status = cczp_inv_ws(ws, zp, lambda, ccec_const_point_z(s, cp));    // lambda = sz^-1
    cczp_sqr_ws(ws, zp, t, lambda);                                         // t = lambda^2
    cczp_mul_ws(ws, zp, ccec_point_x(r, cp), t, ccec_const_point_x(s, cp)); // rx = t * sx
    cczp_mul_ws(ws, zp, t, t, lambda);                                      // t = lambda^3
    cczp_mul_ws(ws, zp, ccec_point_y(r, cp), t, ccec_const_point_y(s, cp)); // ry = t * sy

    // Back from Montgomery
    cczp_from_ws(ws, zp, ccec_point_x(r, cp), ccec_point_x(r, cp));
    cczp_from_ws(ws, zp, ccec_point_y(r, cp), ccec_point_y(r, cp));

#if CCEC_DEBUG
    ccec_alprint(cp, "ccec_affinify output", r);
#endif

    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccec_affinify_homogeneous_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_affine_point_t r,
                                 ccec_const_projective_point_t s)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    const cc_unit *sx = ccec_const_point_x(s, cp);
    const cc_unit *sy = ccec_const_point_y(s, cp);
    const cc_unit *sz = ccec_const_point_z(s, cp);

    if (ccn_is_zero(n, sz)) {
        return CCERR_PARAMETER;
    }

    cc_unit *rx = ccec_point_x(r, cp);
    cc_unit *ry = ccec_point_y(r, cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *zi = CC_ALLOC_WS(ws, n);

    int rv = cczp_inv_ws(ws, zp, zi, sz);
    cc_require(rv == CCERR_OK, errOut);

    cczp_mul_ws(ws, zp, rx, sx, zi);
    cczp_mul_ws(ws, zp, ry, sy, zi);

    cczp_from_ws(ws, zp, rx, rx);
    cczp_from_ws(ws, zp, ry, ry);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_WORKSPACE_OVERRIDE(ccec_affinify_ws, ccec_affinify_jacobian_ws)
CC_WORKSPACE_OVERRIDE(ccec_affinify_ws, ccec_affinify_homogeneous_ws)

int ccec_affinify_ws(cc_ws_t ws,
                     ccec_const_cp_t cp,
                     ccec_affine_point_t r,
                     ccec_const_projective_point_t s)
{
    return CCEC_FUNCS_GET(cp, ccec_affinify)(ws, cp, r, s);
}

int ccec_affinify(ccec_const_cp_t cp, ccec_affine_point_t r, ccec_const_projective_point_t s)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_AFFINIFY_WORKSPACE_N(ccec_cp_n(cp)));
    int result = ccec_affinify_ws(ws, cp, r, s);
    CC_FREE_WORKSPACE(ws);
    return result;
}

int ccec_affinify_x_only_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *sx, ccec_const_projective_point_t s)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_t zp = ccec_cp_zp(cp);

    if (ccec_is_point_at_infinity(cp, s)) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    // Allows "in place" operation.
    cc_unit *lambda = CC_ALLOC_WS(ws, n);
    cczp_sqr_ws(ws, zp, lambda, ccec_const_point_z(s, cp)); // sz^2

    // lambda = sz^-2
    int status = cczp_inv_ws(ws, zp, lambda, lambda);
    cczp_mul_ws(ws, zp, sx, ccec_const_point_x(s, cp), lambda); // rx = sx * lambda^2
    cczp_from_ws(ws, zp, sx, sx);

    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccec_affinify_x_only(ccec_const_cp_t cp, cc_unit *sx, ccec_const_projective_point_t s)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_AFFINIFY_X_ONLY_WORKSPACE_N(ccec_cp_n(cp)));
    int result = ccec_affinify_x_only_ws(ws, cp, sx, s);
    CC_FREE_WORKSPACE(ws);
    return result;
}
