/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "ccec_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

CC_PURE cc_size CCEC_AFFINIFY_POINTS_WORKSPACE_N(cc_size n, cc_size npoints)
{
    return npoints * n + n + n +
           CC_MAX_EVAL(CC_MAX_EVAL(CCZP_MUL_WORKSPACE_N(n), CCZP_INV_WORKSPACE_N(n)),
                       CC_MAX_EVAL(CCZP_SQR_WORKSPACE_N(n), CCZP_FROM_WORKSPACE_N(n)));
}

int ccec_affinify_points_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_size npoints, ccec_affine_point_t *t, ccec_projective_point_t const *s)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_t zp = ccec_cp_zp(cp);

    // Make sure there is no point at infinity
    int status = CCERR_OK;
    for (size_t i = 0; i < npoints; i++) {
        if (ccec_is_point_at_infinity(cp, s[i])) {
            status |= CCERR_PARAMETER;
        }
    }
    cc_require_or_return(status == CCERR_OK, status);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *scratch = CC_ALLOC_WS(ws, n * npoints);
    // scratch[0] = z0
    // scratch[1] = z0 * z1
    // scratch[n-1] = z0 * z1 * ... * zn-1
    ccn_set(n, scratch + 0, ccec_point_z(s[0], cp));
    for (cc_size i = 1; i < npoints; i++) {
        cczp_mul_ws(ws, zp, scratch + i * n, scratch + (i - 1) * n, ccec_point_z(s[i], cp));
    }

    // q = 1 / scratch[n-1] = 1 / (z0 * z1 * ... * zn-1)
    cc_unit *q = CC_ALLOC_WS(ws, n);
    status = cczp_inv_ws(ws, zp, q, scratch + (npoints - 1) * n);
    cc_require(status == CCERR_OK, errOut);

    // Compute the correct (x,y) for s[n-1] down to s[1]
    cc_unit *z = CC_ALLOC_WS(ws, n);
    for (size_t i = npoints - 1; i > 0; i--) {
        // scratch[i] = scratch[i-1] * q = 1 / zi
        cczp_mul_ws(ws, zp, scratch + i * n, q, scratch + (i - 1) * n);

        // Update the inverse for the next iteration
        // q = q * zi = 1 / z1*...*zi-1
        cczp_mul_ws(ws, zp, q, q, ccec_point_z(s[i], cp));

        // Set t[i]_x as s[i]_x / z^2
        cczp_sqr_ws(ws, zp, z, scratch + i * n);
        cczp_mul_ws(ws, zp, ccec_point_x(t[i], cp), ccec_point_x(s[i], cp), z);

        // Set t[i]_y as s[i]_y / z^3
        cczp_mul_ws(ws, zp, z, z, scratch + i * n);
        cczp_mul_ws(ws, zp, ccec_point_y(t[i], cp), ccec_point_y(s[i], cp), z);

        // Convert back
        cczp_from_ws(ws, zp, ccec_point_x(t[i], cp), ccec_point_x(t[i], cp));
        cczp_from_ws(ws, zp, ccec_point_y(t[i], cp), ccec_point_y(t[i], cp));
    }

    // At this point, we have q = 1 / z0
    // Set t[i]_x as s[i]_x / z^2 and t[i]_y as s[i]_y / z^3 for s[0]
    cczp_sqr_ws(ws, zp, z, q);
    cczp_mul_ws(ws, zp, ccec_point_x(t[0], cp), ccec_point_x(s[0], cp), z);
    cczp_mul_ws(ws, zp, z, z, q);
    cczp_mul_ws(ws, zp, ccec_point_y(t[0], cp), ccec_point_y(s[0], cp), z);
    cczp_from_ws(ws, zp, ccec_point_x(t[0], cp), ccec_point_x(t[0], cp));
    cczp_from_ws(ws, zp, ccec_point_y(t[0], cp), ccec_point_y(t[0], cp));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}
