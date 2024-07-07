/* Copyright (c) (2023) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "ccrng_internal.h"
#include "ccec25519_internal.h"

// Precomputed multiples of the base point (B, 3B, 5B, 7B, 9B, 11B, 13B, 15B).
// Coordinates are (X,Y,2d*XY), with Z=1 (omitted).
static const cc_unit CCED25519_PRECOMPUTED_BASES[8][3 * CCN256_N] = {
 #include "cced25519_base_verify.inc"
};

/*! @function cced25519_point_to_cached_ws
 @abstract Precomputes T := 2d * T for a given point.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param P     A projective (ext. twisted Edwards coordinate) point P.
*/
CC_NONNULL_ALL
static void cced25519_point_to_cached_ws(cc_ws_t ws,
                                         ccec_const_cp_t cp,
                                         cced25519_point P)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    cc_unit *T = &P[2 * n];

    CC_DECL_BP_WS(ws, bp);
    cczp_mul_ws(ws, zp, T, T, kLowerCaseD);
    cczp_add_ws(ws, zp, T, T, T);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cced25519_add_points_unified_cached_ws
 @abstract Computes R = P + Q, with coordinate Q_t already multiplied by 2d.
           Unified addition with no constraints on P or Q.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param R     The resulting point R = P + Q.
 @param P     A projective (ext. twisted Edwards coordinate) point P.
 @param Q     A projective (ext. twisted Edwards coordinate) point Q, with T = 2d*XY.
 @param flags Flags to speed up the computation or turn addition into subtraction.
*/
CC_NONNULL_ALL
static void cced25519_add_points_unified_cached_ws(cc_ws_t ws,
                                                   ccec_const_cp_t cp,
                                                   cced25519_point R,
                                                   cced25519_const_point P,
                                                   cced25519_const_point Q,
                                                   cced25519_add_points_flags_t flags)
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

    bool negate_q = flags & CCED25519_ADD_POINTS_FLAG_NEGATE_Q;
    bool z_eq_one = flags & CCED25519_ADD_POINTS_FLAG_Z_EQ_ONE;
    bool compute_t = !(flags & CCED25519_ADD_POINTS_FLAG_SKIP_T);

    if (z_eq_one) {
        ccn_set(n, Z3, Z1);
    } else {
        cczp_mul_ws(ws, zp, Z3, Z1, Z2);
    }

    cczp_sub_ws(ws, zp, A, Y1, X1);
    if (negate_q) {
        cczp_add_ws(ws, zp, B, Y2, X2);
    } else {
        cczp_sub_ws(ws, zp, B, Y2, X2);
    }
    cczp_mul_ws(ws, zp, A, A, B);

    cczp_add_ws(ws, zp, B, Y1, X1);
    if (negate_q) {
        cczp_sub_ws(ws, zp, X3, Y2, X2);
    } else {
        cczp_add_ws(ws, zp, X3, Y2, X2);
    }
    cczp_mul_ws(ws, zp, B, B, X3);
    cczp_sub_ws(ws, zp, X3, B, A);
    cczp_add_ws(ws, zp, Y3, B, A);

    cczp_mul_ws(ws, zp, T3, T1, T2);
    cczp_add_ws(ws, zp, Z3, Z3, Z3);

    if (negate_q) {
        cczp_add_ws(ws, zp, B, Z3, T3);
        cczp_sub_ws(ws, zp, Z3, Z3, T3);
    } else {
        cczp_sub_ws(ws, zp, B, Z3, T3);
        cczp_add_ws(ws, zp, Z3, Z3, T3);
    }

    if (compute_t) {
        cczp_mul_ws(ws, zp, T3, X3, Y3);
    }
    cczp_mul_ws(ws, zp, Y3, Y3, Z3);
    cczp_mul_ws(ws, zp, Z3, Z3, B);
    cczp_mul_ws(ws, zp, X3, X3, B);

    CC_FREE_BP_WS(ws, bp);
}

void cced25519_add_points_unified_ws(cc_ws_t ws,
                                     ccec_const_cp_t cp,
                                     cced25519_point R,
                                     cced25519_const_point P,
                                     cced25519_const_point Q,
                                     cced25519_add_points_flags_t flags)
{
    cc_assert(R != P);

    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    ccn_set(4 * n, R, Q);

    cced25519_point_to_cached_ws(ws, cp, R);
    cced25519_add_points_unified_cached_ws(ws, cp, R, P, R, flags);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function cced25519_dbl_point_ws
 @abstract Computes R = 2 * P.

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting point R = 2 * P.
 @param P  A projective (ext. twisted Edwards coordinate) point P.
*/
CC_NONNULL_ALL
static void cced25519_dbl_point_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   cced25519_point R,
                                   cced25519_const_point P)
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

    cczp_add_ws(ws, zp, A, X1, Y1);
    cczp_sqr_ws(ws, zp, A, A);

    cczp_sqr_ws(ws, zp, X3, X1);
    cczp_sqr_ws(ws, zp, Y3, Y1);
    cczp_sqr_ws(ws, zp, Z3, Z1);

    cczp_add_ws(ws, zp, B, X3, Y3);
    cczp_sub_ws(ws, zp, T3, B, A);
    cczp_sub_ws(ws, zp, A, X3, Y3);
    cczp_add_ws(ws, zp, Z3, Z3, Z3);
    cczp_add_ws(ws, zp, Z3, Z3, A);

    cczp_mul_ws(ws, zp, X3, Z3, T3);
    cczp_mul_ws(ws, zp, Y3, B, A);
    cczp_mul_ws(ws, zp, T3, T3, B);
    cczp_mul_ws(ws, zp, Z3, Z3, A);

    CC_FREE_BP_WS(ws, bp);
}

int cced25519_scalar_mult_ws(CC_UNUSED cc_ws_t ws,
                             CC_UNUSED ccec_const_cp_t cp,
                             CC_UNUSED ccec_projective_point_t R,
                             CC_UNUSED const cc_unit *s,
                             CC_UNUSED size_t sbitlen,
                             CC_UNUSED ccec_const_projective_point_t P)
{
    cc_try_abort("not implemented");
    return CCERR_INTERNAL;
}


/*! @function cced25519_add_precomputed_point_ws
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
static void cced25519_add_precomputed_point_ws(cc_ws_t ws,
                                               ccec_const_cp_t cp,
                                               cced25519_point R,
                                               int8_t ssw,
                                               cc_size nc,
                                               const cc_unit *pc,
                                               cced25519_add_points_flags_t flags)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    if (ssw < 0) {
        flags |= CCED25519_ADD_POINTS_FLAG_NEGATE_Q;
        ssw = -ssw;
    }

    if (ssw > 0) {
        const cc_unit *pt = &pc[(unsigned)(ssw / 2) * (nc * n)];
        cced25519_add_points_unified_cached_ws(ws, cp, R, R, pt, flags);
    }
}

void cced25519_double_scalar_mult_ws(cc_ws_t ws,
                                     ccec_const_cp_t cp,
                                     ccec_projective_point_t R,
                                     const cc_unit *s,
                                     const cc_unit *t,
                                     ccec_const_projective_point_t Q)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cced25519_point RR = CC_ALLOC_WS(ws, 4 * n);
    cced25519_point QQ = CC_ALLOC_WS(ws, 8 * (4 * n));

    cced25519_to_ed25519_point_ws(ws, cp, QQ, Q);
    cced25519_point_to_cached_ws(ws, cp, QQ);
    cced25519_dbl_point_ws(ws, cp, RR, QQ);

    // Precompute 3Q, 5Q, ..., 13Q, 15Q.
    for (unsigned i = 1; i < 8; i += 1) {
        cced25519_point prev = &QQ[(i - 1) * (4 * n)];
        cced25519_point curr = &QQ[i * (4 * n)];

        cced25519_add_points_unified_cached_ws(ws, cp, curr, RR, prev, 0);
        cced25519_point_to_cached_ws(ws, cp, curr);
    }

    // RR = O
    ccn_clear(n, &RR[0 * n]);
    ccn_clear(n, &RR[2 * n]);
    ccn_seti(n, &RR[1 * n], 1);
    ccn_seti(n, &RR[3 * n], 1);

    // Recode scalars into signed sliding windows.
    int8_t ssw_s[256];
    ccn_recode_ssw(n, s, 4, ssw_s);

    int8_t ssw_t[256];
    ccn_recode_ssw(n, t, 4, ssw_t);

    // Count leading zero bits in both scalars.
    size_t lz = 0;
    while ((ssw_s[255 - lz] | ssw_t[255 - lz]) == 0) {
        lz += 1;
    }

    for (size_t k = 256 - lz; k > 0; k -= 1) {
        // R = 2 * R
        cced25519_dbl_point_ws(ws, cp, RR, RR);

        // R += precomputed multiple of Q
        cced25519_add_precomputed_point_ws(ws, cp, RR, ssw_t[k - 1], 4, QQ, 0);

        // Skip computing T, the point doubling formulas don't require it.
        cced25519_add_points_flags_t flags =
            CCED25519_ADD_POINTS_FLAG_Z_EQ_ONE | CCED25519_ADD_POINTS_FLAG_SKIP_T;

        // R += precomputed multiple of B
        const cc_unit *pc = (const cc_unit *)CCED25519_PRECOMPUTED_BASES;
        cced25519_add_precomputed_point_ws(ws, cp, RR, ssw_s[k - 1], 3, pc, flags);
    }

    cced25519_from_ed25519_point_ws(ws, cp, R, RR);
    CC_FREE_BP_WS(ws, bp);
}
