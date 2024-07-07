/* Copyright (c) (2010,2011,2014-2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccec_internal.h"

CC_NONNULL_ALL
static void ccec_twin_mult_normalize_ws(cc_ws_t ws, ccec_const_cp_t cp,
                                        ccec_projective_point_t r,
                                        ccec_const_projective_point_t s,
                                        const cc_unit *e, const cc_unit *b,
                                        const cc_unit *cd)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    cc_unit *lambda = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    cczp_mul_ws(ws, zp, t, b, cd);                                          // bcd = b * cd
    cczp_mul_ws(ws, zp, lambda, e, t);                                      // lambda = a^-1 = (abcd)^-1 * bcd
    cczp_sqr_ws(ws, zp, t, lambda);                                         // t = lambda^2
    cczp_mul_ws(ws, zp, ccec_point_x(r, cp), t, ccec_const_point_x(s, cp)); // rx = t * sx
    cczp_mul_ws(ws, zp, t, t, lambda);                                      // t = lambda^3
    cczp_mul_ws(ws, zp, ccec_point_y(r, cp), t, ccec_const_point_y(s, cp)); // ry = t * sy
    // Don't touch z here since it's still used by our caller.

    CC_FREE_BP_WS(ws, bp);
}

// s and t must be different points
int ccec_twin_mult_ws(cc_ws_t ws, ccec_const_cp_t cp,
                      ccec_projective_point_t r,
                      const cc_unit *d0, ccec_const_projective_point_t s,
                      const cc_unit *d1, ccec_const_projective_point_t t)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    cc_unit *st = CC_ALLOC_WS(ws, n);
    cc_unit *sptsmt = CC_ALLOC_WS(ws, n);
    cc_unit *stsptsmt_1 = CC_ALLOC_WS(ws, n);

    cc_unit *points = CC_ALLOC_WS(ws, 4 * ccec_point_ws(n));
    ccec_projective_point *ns  = (ccec_projective_point *)&points[0 * ccec_point_ws(n)];
    ccec_projective_point *nt  = (ccec_projective_point *)&points[1 * ccec_point_ws(n)];
    ccec_projective_point *spt = (ccec_projective_point *)&points[2 * ccec_point_ws(n)];
    ccec_projective_point *smt = (ccec_projective_point *)&points[3 * ccec_point_ws(n)];

    ccec_full_add_ws(ws, cp, spt, s, t); // spt = S + T
    ccec_full_sub_ws(ws, cp, smt, s, t); // smt = S - T
    cczp_mul_ws(ws, zp, st, ccec_const_point_z(s, cp), ccec_const_point_z(t, cp));
    cczp_mul_ws(ws, zp, sptsmt, ccec_const_point_z(spt, cp), ccec_const_point_z(smt, cp));
    cczp_mul_ws(ws, zp, stsptsmt_1, st, sptsmt);

    int rv = cczp_inv_ws(ws, zp, stsptsmt_1, stsptsmt_1); // Inverse: (z(s)*z(t)*z(spt)*z(smt))^-1 mod p
    if (rv) {
        goto out;
    }

    ccec_twin_mult_normalize_ws(ws, cp, ns,  s,   stsptsmt_1, ccec_const_point_z(t, cp), sptsmt);
    ccec_twin_mult_normalize_ws(ws, cp, nt,  t,   stsptsmt_1, ccec_const_point_z(s, cp), sptsmt);
    ccec_twin_mult_normalize_ws(ws, cp, spt, spt, stsptsmt_1, st,   ccec_const_point_z(smt, cp));
    ccec_twin_mult_normalize_ws(ws, cp, smt, smt, stsptsmt_1, st,   ccec_const_point_z(spt, cp));

    ccn_seti(n, stsptsmt_1, 1);
    cczp_to_ws(ws, zp, ccec_point_z(ns, cp), stsptsmt_1);
    ccn_set(n, ccec_point_z(nt, cp),  ccec_point_z(ns, cp));
    ccn_set(n, ccec_point_z(spt, cp), ccec_point_z(ns, cp));
    ccn_set(n, ccec_point_z(smt, cp), ccec_point_z(ns, cp));

    size_t m0 = ccn_bitlen(n, d0);
    size_t m1 = ccn_bitlen(n, d1);
    size_t nbits = CC_MAX_EVAL(m0, m1);

    struct ccn_rjsf_state rjsf;
    ccn_recode_jsf_init(&rjsf, nbits, d0, d1);

    // Set r := (1 : 1 : 0), the point at infinity.
    ccn_set(n, ccec_point_x(r, cp), ccec_point_z(ns, cp));
    ccn_set(n, ccec_point_y(r, cp), ccec_point_z(ns, cp));
    ccn_clear(n, ccec_point_z(r, cp));

    for (size_t k = nbits + 1; k > 0; k -= 1) {
        ccec_double_ws(ws, cp, r, r);

        int c[2];
        ccn_recode_jsf_column(&rjsf, k - 1, c);

        if (c[0] == 0 && c[1] == 0) {
            continue;
        }

        size_t i = ccn_recode_jsf_index(c);
        const ccec_projective_point *pt = (ccec_projective_point *)&points[i * ccec_point_ws(n)];

        if (ccn_recode_jsf_direction(c) == 1) {
            ccec_full_add_normalized_ws(ws, cp, r, r, pt);
        } else {
            ccec_full_sub_normalized_ws(ws, cp, r, r, pt);
        }
    }

    cc_assert(ccec_is_point_projective_ws(ws, cp, r));

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

// s and t must be different
int ccec_twin_mult(ccec_const_cp_t cp, ccec_projective_point_t r,
                   const cc_unit *d0, ccec_const_projective_point_t s,
                   const cc_unit *d1, ccec_const_projective_point_t t)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_TWIN_MULT_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_twin_mult_ws(ws, cp, r, d0, s, d1, t);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
