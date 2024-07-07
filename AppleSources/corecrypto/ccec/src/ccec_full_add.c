/* Copyright (c) (2010,2011,2014-2023) Apple Inc. All rights reserved.
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

void ccec_add_normalized_ws(cc_ws_t ws,
                            ccec_const_cp_t cp,
                            ccec_projective_point_t r,
                            ccec_const_projective_point_t s,
                            ccec_const_projective_point_t t,
                            bool negate_t)
{
    cc_assert(r != t);

    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_unit *t1 = ccec_point_x(r, cp);
    cc_unit *t2 = ccec_point_y(r, cp);
    cc_unit *t3 = ccec_point_z(r, cp);

    const cc_unit *X1 = ccec_const_point_x(s, cp);
    const cc_unit *Y1 = ccec_const_point_y(s, cp);
    const cc_unit *Z1 = ccec_const_point_z(s, cp);

    const cc_unit *X2 = ccec_const_point_x(t, cp);
    const cc_unit *Y2 = ccec_const_point_y(t, cp);

    CC_DECL_BP_WS(ws, bp);
    cc_size n = ccec_cp_n(cp);
    cc_unit *t4 = CC_ALLOC_WS(ws, n);
    cc_unit *t5 = CC_ALLOC_WS(ws, n);
    cc_unit *t6 = CC_ALLOC_WS(ws, n);

    cczp_sqr_ws(ws, zp, t6, Z1);           // t6 = Sz^2
    cczp_mul_ws(ws, zp, t4, X2, t6);       // t4 = TxSz^2
    cczp_mul_ws(ws, zp, t6, Z1, t6);       // t6 = Sz^3
    cczp_mul_ws(ws, zp, t5, Y2, t6);       // t5 = TySz^3
    cczp_sub_ws(ws, zp, t4, X1, t4);       // t4 = SxTz^2 - TxSz^2

    if (negate_t) {
        cczp_add_ws(ws, zp, t5, Y1, t5);   // t5 = SyTz^3 + TySz^3
    } else {
        cczp_sub_ws(ws, zp, t5, Y1, t5);   // t5 = SyTz^3 - TySz^3
    }

    // If S == T, double and return.
    if (ccn_is_zero(n, t4) && ccn_is_zero(n, t5)) {
        ccec_double_ws(ws, cp, r, t);
        CC_FREE_BP_WS(ws, bp);
        return;
    }

    // If S == -T, the result is the point at infinity (1 : 1 : 0).
    if (ccn_is_zero(n, t4) && !ccn_is_zero(n, t5)) {
        ccn_seti(n, t1, 1);
        cczp_to_ws(ws, zp, t1, t1);
        ccn_set(n, t2, t1);
        ccn_clear(n, t3);
        CC_FREE_BP_WS(ws, bp);
        return;
    }

    cczp_add_ws(ws, zp, t1, X1, X1);
    cczp_sub_ws(ws, zp, t1, t1, t4);         // t1 = SxTz^2 + TxSz^2

    cczp_add_ws(ws, zp, t2, Y1, Y1);
    cczp_sub_ws(ws, zp, t2, t2, t5);         // t2 = SyTz^3 + TySz^3
    cczp_mul_ws(ws, zp, t3, Z1, t4);         // t3 = SxSzTz^3 - TxTzSz^3
    cczp_sqr_ws(ws, zp, t6, t4);             // t6 = (SxTz^2 - TxSz^2)^2
    cczp_mul_ws(ws, zp, t4, t4, t6);         // t4 = (SxTz^2 - TxSz^2)^3
    cczp_mul_ws(ws, zp, t6, t1, t6);         // t6 = (SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2
    cczp_sqr_ws(ws, zp, t1, t5);             // t1 = (SyTz^3 - TySz^3)^2
    cczp_sub_ws(ws, zp, t1, t1, t6);         // t1 = (SyTz^3 - TySz^3)^2 - (SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2
    cczp_sub_ws(ws, zp, t6, t6, t1);
    cczp_sub_ws(ws, zp, t6, t6, t1);         // t6 = 3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2
    cczp_mul_ws(ws, zp, t5, t5, t6);         // t5 = SyTz^3 - TySz^3(3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2)
    cczp_mul_ws(ws, zp, t4, t2, t4);         // t4 = (SyTz^3 + TySz^3)(SxTz^2 - TxSz^2)^3
    cczp_sub_ws(ws, zp, t2, t5, t4);         // t2 = SyTz^3 - TySz^3(3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2) - (SyTz^3 + TySz^3)(SxTz^2 - TxSz^2)^3
    // Rx = (SyTz^3 - TySz^3)^2
    cczp_div2_ws(ws, zp, t2, t2);            // Ry = (SyTz^3 - TySz^3(3(SxTz^2 + TxSz^2)(SxTz^2 - TxSz^2)^2 - 2(SyTz^3 - TySz^3)^2) - (SyTz^3 + TySz^3)(SxTz^2 - TxSz^2)^3) / 2
    // Rz = SxSzTz^3 - TxTzSz^3

    // Result point is {t1,t2,t3}
    CC_FREE_BP_WS(ws, bp);
}

void ccec_full_add_normalized_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_projective_point_t r,
                                 ccec_const_projective_point_t s,
                                 ccec_const_projective_point_t t)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccec_cp_n(cp);

    if (ccec_is_point_at_infinity(cp, s)) {
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(t, cp));
        ccn_set(n, ccec_point_y(r, cp), ccec_const_point_y(t, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(t, cp));
    } else {
        ccec_add_normalized_ws(ws, cp, r, s, t, false /* add */);
    }

    CC_FREE_BP_WS(ws, bp);
}

/*
 @function   ccec_map_to_homogeneous_ws
 @abstract   Maps from Jacobian coordinates (XZ^2, YZ^3, Z)
             to homogeneous coordinates (XZ, YZ, Z).

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      p        Point to map
 @param      x        Output x-coordinate (X/Z)
 @param      z        Output z-coordinate
 */
CC_NONNULL_ALL
static void ccec_map_to_homogeneous_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       ccec_const_projective_point_t p,
                                       cc_unit *x,
                                       cc_unit *z)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    cczp_mul_ws(ws, zp, x, ccec_const_point_x(p, cp), ccec_const_point_z(p, cp));
    cczp_sqr_ws(ws, zp, t, ccec_const_point_z(p, cp));
    cczp_mul_ws(ws, zp, z, ccec_const_point_z(p, cp), t);

    CC_FREE_BP_WS(ws, bp);
}

/*
 @function   ccec_map_to_jacobian_ws
 @abstract   Maps from homogeneous coordinates (XZ, YZ, Z)
             to Jacobian coordinates (XZ^2, YZ^3, Z).

 @discussion Special care is taken to securely map the point
             at infinity from (0 : 1 : 0) to (1 : 1 : 0).

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      r        Point to map
 */
CC_NONNULL_ALL
static void ccec_map_to_jacobian_ws(cc_ws_t ws,
                                    ccec_const_cp_t cp,
                                    ccec_projective_point_t r)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = cczp_n(zp);

    cc_unit *X3 = ccec_point_x(r, cp);
    cc_unit *Y3 = ccec_point_y(r, cp);
    cc_unit *Z3 = ccec_point_z(r, cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);

    ccn_set(n, t0, Y3);
    cczp_from_ws(ws, zp, t1, Y3);

    // Check for point at infinity (0 : 1 : 0).
    cc_unit is_point_at_inf = ccn_is_one(n, t1);
    is_point_at_inf &= ccn_is_zero(n, X3);
    is_point_at_inf &= ccn_is_zero(n, Z3);

    // To Jacobian coordinates.
    cczp_mul_ws(ws, zp, X3, X3, Z3);
    cczp_sqr_ws(ws, zp, t1, Z3);
    cczp_mul_ws(ws, zp, Y3, Y3, t1);

    // The point at infinity is wrongly mapped to (0 : 0 : 0).
    // If needed, set r := (1 : 1 : 0).
    ccn_mux(n, is_point_at_inf, X3, t0, X3);
    ccn_mux(n, is_point_at_inf, Y3, t0, Y3);

    CC_FREE_BP_WS(ws, bp);
}

/*
 @function   ccec_full_add_default_ws
 @abstract   Computes R := S + T, with no constraints on either S or T.

 @discussion Uses complete, projective (homogeneous) point addition formulas for
             prime-order short Weierstrass curves (a=-3) with 12M + 2mb + 29a.

             Converting back and forth between Jacobian and standard projective
             coordinates takes an additional 6M + 3S.

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      r        Projective output point
 @param      s        First projective input point
 @param      t        Second projective input point
 */
void ccec_full_add_default_ws(cc_ws_t ws,
                              ccec_const_cp_t cp,
                              ccec_projective_point_t r,
                              ccec_const_projective_point_t s,
                              ccec_const_projective_point_t t)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    const cc_unit *b = ccec_cp_b(cp);

    const cc_unit *Y1 = ccec_const_point_y(s, cp);
    const cc_unit *Y2 = ccec_const_point_y(t, cp);

    cc_unit *X3 = ccec_point_x(r, cp);
    cc_unit *Y3 = ccec_point_y(r, cp);
    cc_unit *Z3 = ccec_point_z(r, cp);

    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    cc_unit *t2 = CC_ALLOC_WS(ws, n);
    cc_unit *t3 = CC_ALLOC_WS(ws, n);
    cc_unit *t4 = CC_ALLOC_WS(ws, n);

    cc_unit *X1 = CC_ALLOC_WS(ws, n);
    cc_unit *Z1 = CC_ALLOC_WS(ws, n);

    cc_unit *X2 = CC_ALLOC_WS(ws, n);
    cc_unit *Z2 = CC_ALLOC_WS(ws, n);

    // Map to standard projective (homogeneous) coordinates.
    ccec_map_to_homogeneous_ws(ws, cp, s, X1, Z1);
    ccec_map_to_homogeneous_ws(ws, cp, t, X2, Z2);

    cczp_mul_ws(ws, zp, t0, X1, X2);
    cczp_mul_ws(ws, zp, t1, Y1, Y2);
    cczp_mul_ws(ws, zp, t2, Z1, Z2);

    cczp_add_ws(ws, zp, t3, X1, Y1);
    cczp_add_ws(ws, zp, t4, X2, Y2);
    cczp_mul_ws(ws, zp, t3, t3, t4);

    cczp_add_ws(ws, zp, t4, t0, t1);
    cczp_sub_ws(ws, zp, t3, t3, t4);
    cczp_add_ws(ws, zp, t4, Y1, Z1);

    cczp_add_ws(ws, zp, X3, Y2, Z2);
    cczp_mul_ws(ws, zp, t4, t4, X3);
    cczp_add_ws(ws, zp, X3, t1, t2);

    cczp_sub_ws(ws, zp, t4, t4, X3);
    cczp_add_ws(ws, zp, X3, X1, Z1);
    cczp_add_ws(ws, zp, Y3, X2, Z2);

    cczp_mul_ws(ws, zp, X3, X3, Y3);
    cczp_add_ws(ws, zp, Y3, t0, t2);
    cczp_sub_ws(ws, zp, Y3, X3, Y3);

    cczp_mul_ws(ws, zp, Z3,  b, t2);
    cczp_sub_ws(ws, zp, X3, Y3, Z3);
    cczp_add_ws(ws, zp, Z3, X3, X3);

    cczp_add_ws(ws, zp, X3, X3, Z3);
    cczp_sub_ws(ws, zp, Z3, t1, X3);
    cczp_add_ws(ws, zp, X3, t1, X3);

    cczp_mul_ws(ws, zp, Y3,  b, Y3);
    cczp_add_ws(ws, zp, t1, t2, t2);
    cczp_add_ws(ws, zp, t2, t1, t2);

    cczp_sub_ws(ws, zp, Y3, Y3, t2);
    cczp_sub_ws(ws, zp, Y3, Y3, t0);
    cczp_add_ws(ws, zp, t1, Y3, Y3);

    cczp_add_ws(ws, zp, Y3, t1, Y3);
    cczp_add_ws(ws, zp, t1, t0, t0);
    cczp_add_ws(ws, zp, t0, t1, t0);

    cczp_sub_ws(ws, zp, t0, t0, t2);
    cczp_mul_ws(ws, zp, t1, t4, Y3);
    cczp_mul_ws(ws, zp, t2, t0, Y3);

    cczp_mul_ws(ws, zp, Y3, X3, Z3);
    cczp_add_ws(ws, zp, Y3, Y3, t2);
    cczp_mul_ws(ws, zp, X3, t3, X3);

    cczp_sub_ws(ws, zp, X3, X3, t1);
    cczp_mul_ws(ws, zp, Z3, t4, Z3);
    cczp_mul_ws(ws, zp, t1, t3, t0);
    cczp_add_ws(ws, zp, Z3, Z3, t1);

    // Map back to Jacobian projective coordinates.
    ccec_map_to_jacobian_ws(ws, cp, r);

    CC_FREE_BP_WS(ws, bp);
}

CC_WORKSPACE_OVERRIDE(ccec_full_add_ws, ccec_full_add_default_ws)

void ccec_full_add_ws(cc_ws_t ws,
                      ccec_const_cp_t cp,
                      ccec_projective_point_t r,
                      ccec_const_projective_point_t s,
                      ccec_const_projective_point_t t)
{
    CCEC_FUNCS_GET(cp, ccec_full_add)(ws, cp, r, s, t);
}

int ccec_full_add(ccec_const_cp_t cp,
                  ccec_projective_point_t r,
                  ccec_const_projective_point_t s,
                  ccec_const_projective_point_t t)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_FULL_ADD_WORKSPACE_N(ccec_cp_n(cp)));
    ccec_full_add_ws(ws, cp, r, s, t);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
