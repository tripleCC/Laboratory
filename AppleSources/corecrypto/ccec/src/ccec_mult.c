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
#include "ccec_internal.h"
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"
#include "cc_debug.h"

#if !CCEC_VERIFY_ONLY

// Configuration
#define EC_CURVE_SUPPORT_ONLY_A_MINUS_3

// Conditionally swap contents of two points in constant time.
#define cond_swap_points(_n_, ...) ccn_cond_swap(_n_ * 2, __VA_ARGS__)

// Conditionally copy point Q to P, if s=1.
#define cond_mov_point(_n_, _s_, _p_, _q_, _cp_) \
    ccn_mux(_n_ * 3, _s_, ccec_point_x(_p_, _cp_), ccec_const_point_x(_q_, _cp_), ccec_const_point_x(_p_, _cp_));

/*!
 @function   ccec_mult_XYCZadd_ws
 @abstract   (X,Y)-only co-Z addition with update

 @param      ws       Workspace for internal computations
                        To be cleaned up by the caller.
 @param      cp       Curve parameters.

 @param      P        Input: X:Y Jacobian coordinate for P
                        Output: X:Y Jacobian coordinate for (P + Q)
 @param      Q        Input: X:Y Jacobian coordinate for Q
                        Output: X:Y Jacobian coordinate for P'
 @discussion
            Given the twos points P and Q and a curve cp,
            Compute P' and P+Q where
            P' ~= P (same point in the equivalence class)
            P' and (P+Q) have the same Z coordinate
            Z coordinate omitted in output
 */
static void ccec_mult_XYCZadd_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *P, cc_unit *Q)
{
    cc_size n = ccec_cp_n(cp);
    cc_unit *t1 = &P[0], *t2 = &P[n], *t3 = &Q[0], *t4 = &Q[n];

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t5 = CC_ALLOC_WS(ws, n);
    cc_unit *t6 = CC_ALLOC_WS(ws, n);

    /*
       Algo 18
       modified to have input and output in same buffer
       use more RAM but less than ccec_mult_XYCZaddC_ws so that it does not matter
       Cost: 2S + 4M + 7sub
    */
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cczp_sub_ws(ws, zp, t5, t3, t1); //  X2-X1
    cczp_sqr_ws(ws, zp, t5, t5);     // (X2-X1)^2=A
    cczp_mul_ws(ws, zp, t6, t3, t5); // X2.A=C
    cczp_mul_ws(ws, zp, t3, t1, t5); // X1.A=B
    cczp_sub_ws(ws, zp, t5, t4, t2); // Y2-Y1
    cczp_sqr_ws(ws, zp, t1, t5);     // (Y2-Y1)^2 = D
    cczp_sub_ws(ws, zp, t1, t1, t3); // D - B

    cczp_sub_ws(ws, zp, t1, t1, t6); // X3
    cczp_sub_ws(ws, zp, t6, t6, t3); // C - B
    cczp_mul_ws(ws, zp, t4, t2, t6); // Y1 (C - B)
    cczp_sub_ws(ws, zp, t2, t3, t1); // B - X3
    cczp_mul_ws(ws, zp, t2, t5, t2); // (Y2-Y1) (B - X3)
    cczp_sub_ws(ws, zp, t2, t2, t4); // (Y2-Y1)(B - X3) - Y1 (C - B)

    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function   ccec_mult_XYCZaddC_ws
 @abstract   (X,Y)-only co-Z conjugate addition with update

 @param      ws       Workspace for internal computations
                        To be cleaned up by the caller.
 @param      cp       Curve parameters.

 @param      P        Input: X:Y Jacobian coordinate for P
                        Output: X:Y Jacobian coordinate for (P+Q)
 @param      Q        Input: X:Y Jacobian coordinate for Q
                        Output: X:Y Jacobian coordinate for (P-Q)
 @discussion
             Given the twos points P and Q and a curve cp,
             Compute P' and P+Q where
             P' ~= P (same point in the equivalence class)
             (P-Q) and (P+Q) have the same Z coordinate
             Z coordinate omitted in output
 */
static void ccec_mult_XYCZaddC_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *P, cc_unit *Q)
{
    cc_size n = ccec_cp_n(cp);
    cc_unit *t1 = &P[0], *t2 = &P[n], *t3 = &Q[0], *t4 = &Q[n];

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t5 = CC_ALLOC_WS(ws, n);
    cc_unit *t6 = CC_ALLOC_WS(ws, n);
    cc_unit *t7 = CC_ALLOC_WS(ws, n);

    /*
     Algo 19
     Modified to have same input and output buffers
     Cost: 3S + 5M + 11add/sub
     */
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cczp_sub_ws(ws, zp, t5, t3, t1); //  X2-X1
    cczp_sqr_ws(ws, zp, t5, t5);     // (X2-X1)^2=A
    cczp_mul_ws(ws, zp, t6, t1, t5); // X1 * A = B
    cczp_mul_ws(ws, zp, t1, t3, t5); // X2 * A = C
    cczp_add_ws(ws, zp, t5, t4, t2); // Y2+Y1
    cczp_sub_ws(ws, zp, t4, t4, t2); // Y2-Y1
    cczp_sub_ws(ws, zp, t3, t1, t6); // C - B
    cczp_mul_ws(ws, zp, t7, t2, t3); // Y1 * (C-B)
    cczp_add_ws(ws, zp, t3, t1, t6); // C + B

    cczp_sqr_ws(ws, zp, t1, t4);     // (Y2-Y1)^2
    cczp_sub_ws(ws, zp, t1, t1, t3); // X3 = (Y2-Y1)^2 - (C+B)
    cczp_sub_ws(ws, zp, t2, t6, t1); // B - X3
    cczp_mul_ws(ws, zp, t2, t4, t2); // (Y2-Y1) * (B-X3)

    cczp_sub_ws(ws, zp, t2, t2, t7); // Y3 = (Y2-Y1)*(B-X3) - Y1*(C-B)
    cczp_sqr_ws(ws, zp, t4, t5);     // F = (Y2+Y1)^2
    cczp_sub_ws(ws, zp, t3, t4, t3); // X3' = F - (C+B)
    cczp_sub_ws(ws, zp, t4, t3, t6); // X3' - B
    cczp_mul_ws(ws, zp, t4, t4, t5); // (X3'-B) * (Y2+Y1)
    cczp_sub_ws(ws, zp, t4, t4, t7); // Y3' = (X3'-B)*(Y2+Y1) - Y1*(C-B)

    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function   ccec_mult_XYCZdblJac_ws
 @abstract   Point Doubling in Jacobian with Co-Z output

 @param      ws        Workspace for internal computations
                       To be cleaned up by the caller.
 @param      cp        Curve parameters.
 @param      twoP      Output: X:Y Jacobian coordinate for 2P
 @param      P         Output: X:Y Jacobian coordinate for P'
 @param      p         Input: P in Jacobian coordinates
 @discussion
            Given a point P and a curve cp,
            Compute 2P and P' where
            P' ~= P (same point in the equivalence class)
            2P and P' have the same Z coordinate
            Z coordinate omitted in output
 */
static void ccec_mult_XYCZdblJac_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *twoP, cc_unit *P, ccec_const_projective_point_t p)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cc_size n = ccec_cp_n(cp);
    cc_unit *t1 = &twoP[0], *t2 = &twoP[n], *t3 = &P[0], *t4 = &P[n];

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t5 = CC_ALLOC_WS(ws, n);
    cc_unit *t6 = CC_ALLOC_WS(ws, n);
    cc_unit *t7 = CC_ALLOC_WS(ws, n);

    /*
    Cost (a=-3)     : 6S + 2M + 12add/sub
    Cost (generic)  : 6S + 3M + 10add/sub
     */

    cczp_sqr_ws(ws, zp, t7, ccec_const_point_x(p, cp)); //  X1^2
    cczp_add_ws(ws, zp, t4, t7, t7);                    //  2*X1^2
    cczp_add_ws(ws, zp, t7, t7, t4);                    //  3*X1^2
    cczp_sqr_ws(ws, zp, t3, ccec_const_point_z(p, cp)); //  Z1^2
    cczp_sqr_ws(ws, zp, t3, t3);                        //  Z1^4

#ifdef EC_CURVE_SUPPORT_ONLY_A_MINUS_3
    cczp_add_ws(ws, zp, t5, t3, t3); //  2*Z1^4
    cczp_add_ws(ws, zp, t5, t5, t3); //  3*Z1^4
    cczp_sub_ws(ws, zp, t7, t7, t5); //  B = 3*X1^2 - 3.Z1^4
#else
    cczp_mul_ws(ws, zp, t5, ccec_cp_a(cp), t3); //  a.Z1^4
    cczp_add_ws(ws, zp, t7, t7, t5);            //  B = 3*X1^2 + a.Z1^4
#endif
    cczp_sqr_ws(ws, zp, t4, ccec_const_point_y(p, cp));     //  Y1^2
    cczp_add_ws(ws, zp, t4, t4, t4);                        //  2Y1^2
    cczp_add_ws(ws, zp, t5, t4, t4);                        //  4Y1^2
    cczp_mul_ws(ws, zp, t3, t5, ccec_const_point_x(p, cp)); //  A = 4Y1^2.X1
    cczp_sqr_ws(ws, zp, t6, t7);                            //  B^2

    cczp_sub_ws(ws, zp, t6, t6, t3); //  B^2 - A
    cczp_sub_ws(ws, zp, t1, t6, t3); //  X2 = B^2 - 2.A
    cczp_sub_ws(ws, zp, t6, t3, t1); //  A - X2

    cczp_mul_ws(ws, zp, t6, t6, t7); //  (A - X2)*B
    cczp_sqr_ws(ws, zp, t4, t4);     //  (2Y1^2)^2
    cczp_add_ws(ws, zp, t4, t4, t4); //  8.Y1^4 = Y1'
    cczp_sub_ws(ws, zp, t2, t6, t4); //  Y2 = (A - X2)*B - 8.Y1^4

    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function   ccec_mult_XYCZrecoverCoeffJac_ws
 @abstract   Recover Z and lambdaX, lambdaY coefficients for the result point
    if b=0 => R1 - R0 = -P
    if b=1 => R1 - R0 = P

 @param      ws         Workspace for internal computations
                          To be cleaned up by the caller.
 @param      cp         Curve parameters.
 @param      lambdaX    Output: Correcting coefficient for X
 @param      lambdaY    Output: Correcting coefficient for Y
 @param      Z          Output: Z coordinate
 @param      R0         Input: X:Y Jacobian coordinates for P
 @param      R1         Input: X:Y Jacobian coordinates for Q
 @param      Rb         Input: X:Y Jacobian coordinates for P or Q
 @param      p          Input: input point to the scalar multiplication
 @discussion
    {lambaX, lambdaY, Z} so that the result point is recovered from R0
    after the last iteration.
 */
static void ccec_mult_XYCZrecoverCoeffJac_ws(cc_ws_t ws,
                                             ccec_const_cp_t cp,
                                             cc_unit *lambdaX,
                                             cc_unit *lambdaY,
                                             cc_unit *Z,
                                             const cc_unit *R0,
                                             const cc_unit *R1,
                                             const cc_unit *Rb,
                                             ccec_const_projective_point_t p)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t1 = lambdaX, *t2 = lambdaY, *t3 = Z;

    cczp_sub_ws(ws, zp, t3, R0, R1);                        // X_R0 - X_R1
    cczp_mul_ws(ws, zp, t3, &Rb[n], t3);                    // Yb * (X_R0-X_R1)
    cczp_mul_ws(ws, zp, t3, ccec_const_point_x(p, cp), t3); // XP * Yb*(X_R0-X_R1)
    cczp_mul_ws(ws, zp, t3, ccec_const_point_z(p, cp), t3); // ZP * XP*Yb*(X_R0-X_R1)

    cczp_mul_ws(ws, zp, t2, Rb, ccec_const_point_y(p, cp)); // Xb*YP
    cczp_sqr_ws(ws, zp, t1, t2);                            // (Xb*YP)^2
    cczp_mul_ws(ws, zp, t2, t2, t1);                        // (Xb*YP)^3

    // {T1,T2,T3}
    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function    ccec_mult_inner_ws
 @abstract    Scalar multiplication on the curve cp. Computes r := d * S.

 @discussion  Assumes that x(S) ≠ 0 and bitlen(d) <= bitlen(q).
              S can be the point at infinity.

              Handles edge cases d ∈ {0, 1, q-1, q} in constant time.

 @param       ws          Workspace
 @param       cp          Curve parameter
 @param       r           Output point d * S
 @param       d           Scalar d
 @param       dbitlen     Bit length of scalar d
 @param       s           Input point S
 */
CC_NONNULL_ALL CC_WARN_RESULT
static int ccec_mult_inner_ws(cc_ws_t ws,
                              ccec_const_cp_t cp,
                              ccec_projective_point_t r,
                              const cc_unit *d,
                              size_t dbitlen,
                              ccec_const_projective_point_t s)
{
    cc_assert(r != s);

    // We require bitlen(d) <= bitlen(q).
    if (dbitlen > ccec_cp_order_bitlen(cp)) {
        return CCERR_PARAMETER;
    }

    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));

    // As required by the EC formulas.
    if (ccn_is_zero(n, ccec_point_x(s, cp))) {
        return CCERR_INTERNAL;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *R0 = CC_ALLOC_WS(ws, 2 * n); // R0,R1,Rb are full points:
    cc_unit *R1 = CC_ALLOC_WS(ws, 2 * n); // X in [0..n-1] and Y in [n..2n-1]
    cc_unit *Rb = CC_ALLOC_WS(ws, 2 * n);

    // R0 := 2R, R1 := R
    ccec_mult_XYCZdblJac_ws(ws, cp, R0, R1, s);

    // The main loop below will set R1 := -R and swap (R0, R1).

    // Until we hit the MSB of the scalar we run the following:
    //
    // A.1) R0 = -R, R1 =  2R <----------\
    // A.2) R0 =  R, R1 = -3R (ADDC)     |
    // A.3) R0 =  R, R1 = -2R (ADD) --\  |
    //                                |  |
    // B.1) R0 =  R, R1 = -2R <-------/  |
    // B.2) R0 = -R, R1 =  3R (ADDC)     |
    // B.3) R0 = -R, R1 =  2R (ADD) -----/
    //
    // Where:
    //  ADDC(P, Q) := (P+Q, P-Q)
    //  ADD(P, Q) := (P+Q, P)
    //
    // While the significant bits in the scalar are zero, we cycle between
    // A and B, or (R0=R, R1=-2R) and (R0=-R, R1=2R).
    //
    // As soon as we hit the MSB, the cycle is interrupted by negating R0 once
    // more and we start the actual computation from (R0=R, R1=2R) or
    // (R0=-R, R1=-2R).

    // Tracks whether R0,R1 need to be swapped.
    cc_unit dbit = ccn_bit(d, dbitlen - 1);

    // Negate R1 if the leading bit is zero.
    cc_unit negate = dbit ^ 1;

    // Did we see the MSB yet?
    cc_unit seen_msb = dbit;

    for (size_t i = dbitlen - 2; i > 0; --i) {
        cc_unit di = ccn_bit(d, i);

        // Conditionally negate R1.
        cczp_cond_negate(zp, negate, R1 + n, R1 + n);

        // Conditionally swap (R0,R1).
        cond_swap_points(n, (seen_msb ^ 1) | (dbit ^ di), R0, R1);

        // R0 := R0 + R1, R1 := R0 - R1
        ccec_mult_XYCZaddC_ws(ws, cp, R0, R1);

        // R0 := R0 + R1, R1 := R0
        ccec_mult_XYCZadd_ws(ws, cp, R0, R1);

        // Negate R1 once more when we hit the MSB.
        negate = (seen_msb ^ 1) & di;

        // Did we hit the MSB yet?
        seen_msb |= di;

        // Invariably, R1 - R0 = P (except in the initial A/B cycle).
        dbit = di;
    }

    // Conditionally negate R1.
    cczp_cond_negate(zp, negate, R1 + n, R1 + n);

    // Last iteration
    dbit ^= ccn_bit(d, 0);

    cond_swap_points(n, dbit, R0, R1);
    ccec_mult_XYCZaddC_ws(ws, cp, R0, R1);

    // Save current Rb.
    ccn_set(2 * n, Rb, R1);

    // Restore dbit, R0, R1.
    dbit = ccn_bit(d, 0);
    cond_swap_points(n, dbit, R0, R1);

    // If d0 =      0           1
    //          R1-R0=-P     R1-R0=P
    // Therefore we can reconstruct the Z coordinate
    // To save an inversion and keep the result in Jacobian projective coordinates,
    //  we compute coefficient for X and Y.
    ccec_mult_XYCZrecoverCoeffJac_ws(ws, cp, ccec_point_x(r, cp), ccec_point_y(r, cp), ccec_point_z(r, cp), R0, R1, Rb, s);

    cond_swap_points(n, dbit, R0, R1);
    ccec_mult_XYCZadd_ws(ws, cp, R0, R1);
    ccn_mux(n * 2, dbit, R0, R1, R0);

    // Apply coefficients to get final X,Y
    cczp_mul_ws(ws, zp, ccec_point_x(r, cp), ccec_point_x(r, cp), &R0[0]); // X0 * lambdaX
    cczp_mul_ws(ws, zp, ccec_point_y(r, cp), ccec_point_y(r, cp), &R0[n]); // Y0 * lambdaY

    // Set r := s, if (d = 1) or (d = q-1) or (s = point at infinity).
    (void)ccn_sub1(n, Rb, cczp_prime(ccec_cp_zq(cp)), 1);
    cc_unit d_eq_qm1 = ((cc_unit)ccn_cmpn(ccn_nof(dbitlen), d, n, Rb) & 1) ^ 1;
    cc_unit s_at_inf = (cc_unit)ccec_is_point_at_infinity(cp, s);
    cond_mov_point(n, (seen_msb ^ 1) | d_eq_qm1 | s_at_inf, r, s, cp);

    // Invert y(s) if d = q-1, so that r = -s.
    cczp_cond_negate(zp, d_eq_qm1, ccec_point_y(r, cp), ccec_point_y(r, cp));

    // Set r := (1 : 1 : 0), the point at infinity, if d=0.
    cc_unit r_at_inf = (seen_msb ^ 1) & (ccn_bit(d, 0) ^ 1);
    ccn_cond_clear(n, r_at_inf, ccec_point_z(r, cp));

    ccn_seti(n, R0, 1);
    cczp_to_ws(ws, zp, R0, R0);
    ccn_mux(n, r_at_inf, ccec_point_x(r, cp), R0, ccec_const_point_x(r, cp));
    ccn_mux(n, r_at_inf, ccec_point_y(r, cp), R0, ccec_const_point_y(r, cp));

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int ccec_mult_default_ws(cc_ws_t ws,
                         ccec_const_cp_t cp,
                         ccec_projective_point_t r,
                         const cc_unit *d,
                         size_t dbitlen,
                         ccec_const_projective_point_t s)
{
    cc_assert(r != s);

    // We require bitlen(d) <= bitlen(q).
    if (dbitlen > ccec_cp_order_bitlen(cp)) {
        return CCERR_PARAMETER;
    }

    cc_size n = ccec_cp_n(cp);
    cc_size nd = ccn_nof(dbitlen);

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *t = CCEC_ALLOC_POINT_WS(ws, n);
    cc_unit *dt = CC_ALLOC_WS(ws, n);

    // x(S) = 0 is not supported by our formulas.
    // Double the point and adjust the scalar, if needed.
    cc_unit dbl_s = (cc_unit)ccn_is_zero(n, ccec_point_x(s, cp));

    // dt := d,     T := S     [if x(S) ≠ 0]
    // dt := d / 2, T := 2 * S [if x(S) = 0]
    ccn_setn(n, dt, nd, d);
    dt[nd - 1] &= CCN_UNIT_MASK >> (-dbitlen % CCN_UNIT_BITS);
    ccn_shift_right(nd, dt, dt, (size_t)dbl_s);

    ccec_double_ws(ws, cp, t, s);
    cond_mov_point(n, dbl_s ^ 1, t, s, cp);

    // If x(S) = 0, then x(2 * S) ≠ 0.
    int rv = CCERR_INTERNAL;
    cc_require(!ccn_is_zero(n, ccec_point_x(t, cp)), errOut);

    // Perform the scalar multiplication.
    rv = ccec_mult_inner_ws(ws, cp, r, dt, dbitlen, t);
    cc_require(rv == CCERR_OK, errOut);

    // R += S [if x(S) = 0 and LSB(d) = 1]
    ccec_full_add_ws(ws, cp, t, r, s);
    cond_mov_point(n, d[0] & dbl_s, r, t, cp);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_WORKSPACE_OVERRIDE(ccec_mult_ws, ccec_mult_default_ws)

int ccec_mult_ws(cc_ws_t ws,
                 ccec_const_cp_t cp,
                 ccec_projective_point_t r,
                 const cc_unit *d,
                 size_t dbitlen,
                 ccec_const_projective_point_t s)
{
    return CCEC_FUNCS_GET(cp, ccec_mult)(ws, cp, r, d, dbitlen, s);
}

#endif  // !CCEC_VERIFY_ONLY
