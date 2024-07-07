/* Copyright (c) (2022) Apple Inc. All rights reserved.
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
#include "cch2c_internal.h"
#include "cc_macros.h"
#include "cc_memory.h"
#include "cc_workspaces.h"
#include "cczp_internal.h"

#include <corecrypto/cch2c_priv.h>

// Returns inverse of x with the convention that the inverse of 0 is 0
// See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-4
static void cch2c_cczp_inv0_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = cczp_n(zp);
    cc_unit z = (cc_unit)ccn_is_zero(n, x);

    // r := (x == 0) ? 0 : x^-1
    cczp_inv_ws(ws, zp, r, x);
    ccn_cond_clear(n, z, r);

    CC_FREE_BP_WS(ws, bp);
}

// See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.2
int cch2c_map_to_curve_sswu_ws(cc_ws_t ws,
                               const struct cch2c_info *info,
                               const cc_unit *u,
                               ccec_pub_ctx_t q)
{
    ccec_const_cp_t cp = info->curve_params();
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    ccec_ctx_init(cp, q);

    cc_unit *x = ccec_ctx_x(q);
    cc_unit *y = ccec_ctx_y(q);
    cc_unit *z = ccec_ctx_z(q);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    cc_unit *t2 = CC_ALLOC_WS(ws, n);
    cc_unit *t3 = CC_ALLOC_WS(ws, n);

    cc_unit u_parity = ccn_bit(u, 0);
    cc_unit e;

    // compute c2 = -1 / Z
    ccn_seti(n, z, info->z);
    cczp_to_ws(ws, zp, z, z);
    cczp_inv_ws(ws, zp, t3, z);

    // compute Z
    cczp_negate(zp, z, z);

    // compute c1 = -B / A
    ccn_seti(n, y, 3);
    cczp_to_ws(ws, zp, y, y);
    cczp_inv_ws(ws, zp, t0, y);
    cczp_mul_ws(ws, zp, t0, t0, ccec_cp_b(cp));

    // compute A
    cczp_negate(zp, y, y);

    // 1.   t1 = Z * u^2
    cczp_to_ws(ws, zp, t1, u);
    cczp_sqr_ws(ws, zp, t1, t1);
    cczp_mul_ws(ws, zp, t1, t1, z);

    // 2.   t2 = t1^2
    cczp_sqr_ws(ws, zp, z, t1);

    // 3.   x1 = t1 + t2
    cczp_add_ws(ws, zp, t2, t1, z);

    // 4.   x1 = inv0(x1)
    cch2c_cczp_inv0_ws(ws, zp, t2, t2);

    // 5.   e1 = x1 == 0
    e = ccn_is_zero(n, t2);

    // 6.   x1 = x1 + 1
    ccn_seti(n, x, 1);
    cczp_to_ws(ws, zp, x, x);
    cczp_add_ws(ws, zp, t2, t2, x);

    // 7.   x1 = CMOV(x1, c2, e1)
    //      If (t1 + t2) == 0, set x1 = -1 / Z
    ccn_mux(n, e, t2, t3, t2);

    // 8.   x1 = x1 * c1
    //      x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    cczp_mul_ws(ws, zp, t2, t2, t0);

    // 9.  gx1 = x1^2
    cczp_sqr_ws(ws, zp, t0, t2);

    // 10. gx1 = gx1 + A
    cczp_add_ws(ws, zp, t0, t0, y);

    // 11. gx1 = gx1 * x1
    cczp_mul_ws(ws, zp, t0, t0, t2);

    // 12. gx1 = gx1 + B
    //     gx1 = g(x1) = x1^3 + A * x1 + B
    cczp_add_ws(ws, zp, t0, t0, ccec_cp_b(cp));

    // 13.  x2 = t1 * x1             // x2 = Z * u^2 * x1
    cczp_mul_ws(ws, zp, x, t1, t2);

    // 14.  t2 = t1 * t2
    cczp_mul_ws(ws, zp, z, t1, z);

    // 15. gx2 = gx1 * t2
    //     gx2 = (Z * u^2)^3 * gx1
    cczp_mul_ws(ws, zp, z, t0, z);

    // 16.  e2 = is_square(gx1)
    e = (cc_unit)cczp_is_quadratic_residue_ws(ws, zp, t0);

    // 17.   x = CMOV(x2, x1, e2)
    //       If is_square(gx1), x = x1, else x = x2
    ccn_mux(n, e, x, t2, x);
    cczp_from_ws(ws, zp, x, x);

    // 18.  y2 = CMOV(gx2, gx1, e2)
    //      If is_square(gx1), y2 = gx1, else y2 = gx2
    ccn_mux(n, e, z, t0, z);

    // 19.   y = sqrt(y2)
    cczp_sqrt_ws(ws, zp, y, z);
    cczp_from_ws(ws, zp, y, y);

    // 20.  e3 = sgn0(u) == sgn0(y)
    //      Fix sign of y
    e = u_parity ^ ccn_bit(y, 0) ^ 1;

    // 21.   y = CMOV(-y, y, e3)
    cczp_cond_negate(zp, e ^ 1, y, y);

    // 22. return (x, y)
    ccn_seti(n, z, 1);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int map_to_curve_sswu(const struct cch2c_info *info,
                      const cc_unit *u,
                      ccec_pub_ctx_t q)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = info->curve_params();
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCH2C_MAP_TO_CURVE_SSWU_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = cch2c_map_to_curve_sswu_ws(ws, info, u, q);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_WORKSPACE_OVERRIDE(cch2c_map_to_curve_ws, cch2c_map_to_curve_sswu_ws)

int cch2c_map_to_curve_ws(cc_ws_t ws,
                          const struct cch2c_info *info,
                          const cc_unit *u,
                          ccec_pub_ctx_t q)
{
    return info->map_to_curve(ws, info, u, q);
}
