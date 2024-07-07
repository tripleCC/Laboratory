/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_memory.h"
#include "ccn_internal.h"
#include "ccec_internal.h"
#include "ccrng_internal.h"
#include "ccec448_internal.h"

// Conditionally swap contents of two points in constant time.
#define cond_swap_points(...) ccn_cond_swap(CCN448_N * 4, __VA_ARGS__)

// Precomputed multiples of the base point (B, 3B, 5B, 7B, 9B, 11B, 13B, 15B).
// Coordinates are (X,Y,d*XY), with Z=1 (omitted).
static const cc_unit CCED448_PRECOMPUTED_BASES[8][3 * CCN448_N] = {
 #include "cced448_base.inc"
};

/*! @function cced448_point_to_cached_ws
 @abstract Precomputes T := d * T for a given point.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param P     A projective (ext. twisted Edwards coordinate) point P.
*/
CC_NONNULL_ALL
static void cced448_point_to_cached_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       cced448_point P)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    cc_unit *T = &P[2 * n];

    CC_DECL_BP_WS(ws, bp);
    cczp_mul_ws(ws, zp, T, T, kNegative39081);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cced448_add_points_unified_cached_ws
 @abstract Computes R = P + Q, with coordinate Q_t already multiplied by d.
           Unified addition with no constraints on P or Q.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param R     The resulting point R = P + Q.
 @param P     A projective (ext. twisted Edwards coordinate) point P.
 @param Q     A projective (ext. twisted Edwards coordinate) point Q, with T = d*XY.
 @param flags Flags to speed up the computation or turn addition into subtraction.
*/
CC_NONNULL_ALL
static void cced448_add_points_unified_cached_ws(cc_ws_t ws,
                                                 ccec_const_cp_t cp,
                                                 cced448_point R,
                                                 cced448_const_point P,
                                                 cced448_const_point Q,
                                                 cced448_add_points_flags_t flags)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    const cc_unit *X1 = &P[0 * n];
    const cc_unit *Y1 = &P[1 * n];
    const cc_unit *T1 = &P[2 * n];
    const cc_unit *Z1 = &P[3 * n];

    const cc_unit *X2 = &Q[0 * n];
    const cc_unit *Y2 = &Q[1 * n];
    const cc_unit *T2 = &Q[2 * n];
    const cc_unit *Z2 = &Q[3 * n];

    cc_unit *X3 = &R[0 * n];
    cc_unit *Y3 = &R[1 * n];
    cc_unit *T3 = &R[2 * n];
    cc_unit *Z3 = &R[3 * n];

    CC_DECL_BP_WS(ws, bp);
    cc_unit *A = CC_ALLOC_WS(ws, n);
    cc_unit *B = CC_ALLOC_WS(ws, n);

    bool negate_q = flags & CCED448_ADD_POINTS_FLAG_NEGATE_Q;
    bool z_eq_one = flags & CCED448_ADD_POINTS_FLAG_Z_EQ_ONE;
    bool compute_t = !(flags & CCED448_ADD_POINTS_FLAG_SKIP_T);

    cczp_mul_ws(ws, zp, T3, T1, T2);

    if (z_eq_one) {
        ccn_set(n, Z3, Z1);
    } else {
        cczp_mul_ws(ws, zp, Z3, Z1, Z2);
    }

    cczp_mul_ws(ws, zp, A, X1, X2);
    cczp_add_ws(ws, zp, B, X1, Y1);
    if (negate_q) {
        cczp_sub_ws(ws, zp, X3, Y2, X2);
    } else {
        cczp_add_ws(ws, zp, X3, Y2, X2);
    }
    cczp_mul_ws(ws, zp, Y3, Y1, Y2);

    cczp_mul_ws(ws, zp, B, B, X3);
    if (negate_q) {
        cczp_add_ws(ws, zp, B, B, A);
    } else {
        cczp_sub_ws(ws, zp, B, B, A);
    }
    cczp_sub_ws(ws, zp, B, B, Y3);

    if (negate_q) {
        cczp_add_ws(ws, zp, X3, Z3, T3);
        cczp_sub_ws(ws, zp, Z3, Z3, T3);
        cczp_add_ws(ws, zp, T3, Y3, A);
    } else {
        cczp_sub_ws(ws, zp, X3, Z3, T3);
        cczp_add_ws(ws, zp, Z3, Z3, T3);
        cczp_sub_ws(ws, zp, T3, Y3, A);
    }

    cczp_mul_ws(ws, zp, Y3, Z3, T3);
    if (compute_t) {
        cczp_mul_ws(ws, zp, T3, T3, B);
    }
    cczp_mul_ws(ws, zp, Z3, Z3, X3);
    cczp_mul_ws(ws, zp, X3, X3, B);

    CC_FREE_BP_WS(ws, bp);
}

void cced448_add_points_unified_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   cced448_point R,
                                   cced448_const_point P,
                                   cced448_const_point Q,
                                   cced448_add_points_flags_t flags)
{
    cc_assert(R != P);

    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    ccn_set(4 * n, R, Q);

    cced448_point_to_cached_ws(ws, cp, R);
    cced448_add_points_unified_cached_ws(ws, cp, R, P, R, flags);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function cced448_add_points_ws
 @abstract Computes R = P + Q. P must be ≠ Q.

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting point R = P + Q.
 @param P  A projective (ext. twisted Edwards coordinate) point P.
 @param Q  A projective (ext. twisted Edwards coordinate) point Q.
*/
CC_NONNULL_ALL
static void cced448_add_points_ws(cc_ws_t ws, ccec_const_cp_t cp, cced448_point R, cced448_const_point P, cced448_const_point Q)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    const cc_unit *X1 = &P[0 * n];
    const cc_unit *Y1 = &P[1 * n];
    const cc_unit *T1 = &P[2 * n];
    const cc_unit *Z1 = &P[3 * n];

    const cc_unit *X2 = &Q[0 * n];
    const cc_unit *Y2 = &Q[1 * n];
    const cc_unit *T2 = &Q[2 * n];
    const cc_unit *Z2 = &Q[3 * n];

    cc_unit *X3 = &R[0 * n];
    cc_unit *Y3 = &R[1 * n];
    cc_unit *T3 = &R[2 * n];
    cc_unit *Z3 = &R[3 * n];

    CC_DECL_BP_WS(ws, bp);
    cc_unit *A = CC_ALLOC_WS(ws, n);
    cc_unit *B = CC_ALLOC_WS(ws, n);

    cczp_mul_ws(ws, zp, A, Z1, T2);
    cczp_mul_ws(ws, zp, B, T1, Z2);

    cczp_sub_ws(ws, zp, Z3, X1, Y1);
    cczp_add_ws(ws, zp, T3, X2, Y2);

    cczp_mul_ws(ws, zp, X3, X1, X2);
    cczp_mul_ws(ws, zp, Y3, Y1, Y2);

    cczp_mul_ws(ws, zp, Z3, Z3, T3);
    cczp_add_ws(ws, zp, Z3, Z3, Y3);
    cczp_sub_ws(ws, zp, Z3, Z3, X3);
    cczp_add_ws(ws, zp, Y3, Y3, X3);

    cczp_sub_ws(ws, zp, T3, B, A);
    cczp_add_ws(ws, zp, B, B, A);

    cczp_mul_ws(ws, zp, X3, B, Z3);
    cczp_mul_ws(ws, zp, Z3, Z3, Y3);
    cczp_mul_ws(ws, zp, Y3, Y3, T3);
    cczp_mul_ws(ws, zp, T3, T3, B);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function cced448_dbl_point_ws
 @abstract Computes R = 2 * P.

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting point R = 2 * P.
 @param P  A projective (ext. twisted Edwards coordinate) point P.
*/
CC_NONNULL_ALL
static void cced448_dbl_point_ws(cc_ws_t ws, ccec_const_cp_t cp, cced448_point R, cced448_const_point P)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    const cc_unit *X1 = &P[0 * n];
    const cc_unit *Y1 = &P[1 * n];
    const cc_unit *Z1 = &P[3 * n];

    cc_unit *X3 = &R[0 * n];
    cc_unit *Y3 = &R[1 * n];
    cc_unit *T3 = &R[2 * n];
    cc_unit *Z3 = &R[3 * n];

    CC_DECL_BP_WS(ws, bp);
    cc_unit *A = CC_ALLOC_WS(ws, n);
    cc_unit *B = CC_ALLOC_WS(ws, n);

    cczp_sqr_ws(ws, zp, A, X1);
    cczp_sqr_ws(ws, zp, B, Y1);
    cczp_sqr_ws(ws, zp, Z3, Z1);
    cczp_add_ws(ws, zp, Z3, Z3, Z3);
    cczp_add_ws(ws, zp, T3, X1, Y1);
    cczp_sqr_ws(ws, zp, T3, T3);
    cczp_sub_ws(ws, zp, T3, T3, A);
    cczp_sub_ws(ws, zp, T3, T3, B);
    cczp_add_ws(ws, zp, Y3, A, B);
    cczp_sub_ws(ws, zp, Z3, Y3, Z3);
    cczp_sub_ws(ws, zp, A, A, B);

    cczp_mul_ws(ws, zp, X3, T3, Z3);
    cczp_mul_ws(ws, zp, T3, T3, A);
    cczp_mul_ws(ws, zp, Z3, Z3, Y3);
    cczp_mul_ws(ws, zp, Y3, Y3, A);

    CC_FREE_BP_WS(ws, bp);
}

int cced448_scalar_mult_ws(cc_ws_t ws,
                           ccec_const_cp_t cp,
                           ccec_projective_point_t R,
                           const cc_unit *s,
                           size_t sbitlen,
                           ccec_const_projective_point_t P)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    const cc_unit *Pz = ccec_const_point_z(P, cp);

    CC_DECL_BP_WS(ws, bp);
    cced448_point R0 = CC_ALLOC_WS(ws, 4 * n);
    cced448_point R1 = CC_ALLOC_WS(ws, 4 * n);

    cc_unit *R0_X = &R0[0 * n];
    cc_unit *R0_Y = &R0[1 * n];
    cc_unit *R0_T = &R0[2 * n];
    cc_unit *R0_Z = &R0[3 * n];

    // R0 = O
    ccn_clear(n, R0_X);
    ccn_clear(n, R0_T);
    ccn_set(n, R0_Y, Pz);
    ccn_set(n, R0_Z, Pz);

    // R1 = P
    cced448_to_ed448_point_ws(ws, cp, R1, P);

    cc_unit sbit = 0;

    for (size_t i = sbitlen; i > 0; --i) {
        cc_unit si = ccn_bit(s, i - 1);

        // Conditionally swap (R0,R1).
        cond_swap_points(sbit ^ si, R0, R1);

        // R1 := R0 + R1
        cced448_add_points_ws(ws, cp, R1, R0, R1);

        // R0 := 2 * R0
        cced448_dbl_point_ws(ws, cp, R0, R0);

        sbit = si;
    }

    ccn_mux(CCN448_N * 4, sbit, R0, R1, R0);
    cced448_from_ed448_point_ws(ws, cp, R, R0);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

CC_WORKSPACE_OVERRIDE(ccec_mult_ws, cced448_scalar_mult_ws)

int cced448_scalar_mult_base_masked_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       struct ccrng_state *rng,
                                       ccec_projective_point_t R,
                                       const cc_unit *s)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *B = CCEC_ALLOC_POINT_WS(ws, n);

    int rv = ccec_projectify_ws(ws, cp, B, ccec_cp_g(cp), rng);
    cc_require(rv == CCERR_OK, errOut);

    // Blinded scalar multiplication.
    rv = ccec_mult_blinded_ws(ws, cp, R, s, B, rng);
    cc_require(rv == CCERR_OK, errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/*! @function cced448_add_precomputed_point_ws
 @abstract Computes R += Q, where Q is a precomputed multiple of a base B.
           The multiple is chosen via the signed sliding window `ssw`.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param R     Resulting point R += Q.
 @param ssw   Signed sliding window.
 @param nc    Number of coordinates per precomputed point.
 @param pc    Table of precomputed points.
 @param flags Flags to pass to unified point addition function.
*/
CC_NONNULL_ALL
static void cced448_add_precomputed_point_ws(cc_ws_t ws,
                                             ccec_const_cp_t cp,
                                             cced448_point R,
                                             int8_t ssw,
                                             cc_size nc,
                                             const cc_unit *pc,
                                             cced448_add_points_flags_t flags)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    if (ssw < 0) {
        flags |= CCED448_ADD_POINTS_FLAG_NEGATE_Q;
        ssw = -ssw;
    }

    if (ssw > 0) {
        const cc_unit *pt = &pc[(unsigned)(ssw / 2) * (nc * n)];
        cced448_add_points_unified_cached_ws(ws, cp, R, R, pt, flags);
    }
}

void cced448_double_scalar_mult_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   ccec_projective_point_t R,
                                   const cc_unit *s,
                                   const cc_unit *t,
                                   ccec_const_projective_point_t Q)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cced448_point RR = CC_ALLOC_WS(ws, 4 * n);
    cced448_point QQ = CC_ALLOC_WS(ws, 8 * (4 * n));

    cced448_to_ed448_point_ws(ws, cp, QQ, Q);
    cced448_point_to_cached_ws(ws, cp, QQ);
    cced448_dbl_point_ws(ws, cp, RR, QQ);

    // Precompute 3Q, 5Q, ..., 13Q, 15Q.
    for (unsigned i = 1; i < 8; i += 1) {
        cced448_point prev = &QQ[(i - 1) * (4 * n)];
        cced448_point curr = &QQ[i * (4 * n)];

        cced448_add_points_unified_cached_ws(ws, cp, curr, RR, prev, 0);
        cced448_point_to_cached_ws(ws, cp, curr);
    }

    // RR = O
    ccn_clear(n, &RR[0 * n]);
    ccn_clear(n, &RR[2 * n]);
    ccn_seti(n, &RR[1 * n], 1);
    ccn_seti(n, &RR[3 * n], 1);

    // Recode scalars into signed sliding windows.
    int8_t ssw_s[448];
    ccn_recode_ssw(n, s, 4, ssw_s);

    int8_t ssw_t[448];
    ccn_recode_ssw(n, t, 4, ssw_t);

    // Count leading zero bits in both scalars.
    size_t lz = 0;
    while ((ssw_s[447 - lz] | ssw_t[447 - lz]) == 0) {
        lz += 1;
    }

    for (size_t k = 448 - lz; k > 0; k -= 1) {
        // R = 2 * R
        cced448_dbl_point_ws(ws, cp, RR, RR);

        // R += precomputed multiple of Q
        cced448_add_precomputed_point_ws(ws, cp, RR, ssw_t[k - 1], 4, QQ, 0);

        // Skip computing T, the point doubling formulas don't require it.
        cced448_add_points_flags_t flags =
            CCED448_ADD_POINTS_FLAG_Z_EQ_ONE | CCED448_ADD_POINTS_FLAG_SKIP_T;

        // R += precomputed multiple of B
        const cc_unit *pc = (const cc_unit *)CCED448_PRECOMPUTED_BASES;
        cced448_add_precomputed_point_ws(ws, cp, RR, ssw_s[k - 1], 3, pc, flags);
    }

    cced448_from_ed448_point_ws(ws, cp, R, RR);
    CC_FREE_BP_WS(ws, bp);
}
