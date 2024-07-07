/* Copyright (c) (2010-2022) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"
#include "cc_macros.h"
#include "cc_fault_canary_internal.h"

// The below helpers encode the scalar multiplications and combination
// in ECDSA.
//
// In the common configuration, we prefer to use ccec_twin_mult. Since
// this function does not support the edge case where the public point
// is the base point, we fall back to the naive implementation,
// i.e. separate multiplications followed by a single addition.
//
// If we are optimizing for small code (i.e. CC_SMALL_CODE is set), we
// typically will not use ccec_twin_mult. In this case, we resort
// directly to the naive implementation.
//
// The least-common configuration comes when CC_SMALL_CODE and
// CCEC_USE_TWIN_MULT are both set. This may happen if corecrypto is
// configured for verification only, i.e. CCEC_VERIFY_ONLY is
// set. (See the definition of CCEC_USE_TWIN_MULT in ccec_internal.h.)
// In this case, we try to use ccec_twin_mult. Since we have no
// fallback, we fail in the edge case noted above.

CC_UNUSED
static int ccec_verify_singlemults_ws(cc_ws_t ws,
                                      ccec_const_cp_t cp,
                                      ccec_projective_point_t r,
                                      const cc_unit *d0,
                                      ccec_const_projective_point_t s,
                                      const cc_unit *d1,
                                      ccec_const_projective_point_t t)
{
    int result = CCERR_INTERNAL;

    cc_size n = ccec_cp_n(cp);
    cczp_const_t zq = ccec_cp_zq(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *tp = CCEC_ALLOC_POINT_WS(ws, n);

    cc_require(ccec_mult_ws(ws, cp, tp, d0, cczp_bitlen(zq), s) == CCERR_OK, errOut);
    cc_require(ccec_mult_ws(ws, cp, r, d1, cczp_bitlen(zq), t) == CCERR_OK, errOut);
    ccec_full_add_ws(ws, cp, r, r, tp);

    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

CC_UNUSED
static int ccec_verify_twinmult_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   ccec_projective_point_t r,
                                   const cc_unit *d0,
                                   ccec_const_projective_point_t s,
                                   const cc_unit *d1,
                                   ccec_const_projective_point_t t,
                                   const cc_unit *xaffine)
{
    cc_size n = ccec_cp_n(cp);

    // Can't use ccec_twin_mult() when P = +/- G.
    if (ccn_cmp(n, ccec_const_point_x(ccec_cp_g(cp), cp), xaffine) == 0) {
#if CC_SMALL_CODE
        return CCERR_PARAMETER;
#else
        return ccec_verify_singlemults_ws(ws, cp, r, d0, s, d1, t);
#endif
    }

    return ccec_twin_mult_ws(ws, cp, r, d0, s, d1, t);
}

// Override workspace definitions so they're correct for CC_SMALL_CODE=0 and =1.
CC_WORKSPACE_OVERRIDE(ccec_verify_twinmult_ws, ccec_verify_singlemults_ws)
CC_WORKSPACE_OVERRIDE(ccec_verify_twinmult_ws, ccec_twin_mult_ws)

static int ccec_verify_computemults_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       ccec_projective_point_t r,
                                       const cc_unit *d0,
                                       ccec_const_projective_point_t s,
                                       const cc_unit *d1,
                                       ccec_const_projective_point_t t,
                                       CC_UNUSED const cc_unit *xaffine)
{
#if CCEC_USE_TWIN_MULT
    return ccec_verify_twinmult_ws(ws, cp, r, d0, s, d1, t, xaffine);
#else
    return ccec_verify_singlemults_ws(ws, cp, r, d0, s, d1, t);
#endif
}

// Override workspace definitions so they're correct for CCEC_USE_TWIN_MULT=0 and =1.
CC_WORKSPACE_OVERRIDE(ccec_verify_computemults_ws, ccec_verify_twinmult_ws)
CC_WORKSPACE_OVERRIDE(ccec_verify_computemults_ws, ccec_verify_singlemults_ws)

int ccec_verify_internal_with_base_ws(cc_ws_t ws,
                                      ccec_pub_ctx_t key,
                                      size_t digest_len,
                                      const uint8_t *digest,
                                      const cc_unit *r,
                                      const cc_unit *s,
                                      ccec_const_affine_point_t base,
                                      cc_fault_canary_t fault_canary_out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = ccec_cp_n(cp);
    int result = CCERR_INTERNAL;

    // Validate 0 < r < q
    // Validate 0 < s < q
    if (ccec_validate_scalar(cp, r) != CCERR_OK ||
        ccec_validate_scalar(cp, s) != CCERR_OK) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_unit *e = CC_ALLOC_WS(ws, n);
    cc_unit *w = CC_ALLOC_WS(ws, n);
    cc_unit *d0 = CC_ALLOC_WS(ws, n);
    cc_unit *d1 = CC_ALLOC_WS(ws, n);

    ccec_projective_point *mg = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *mk = CCEC_ALLOC_POINT_WS(ws, n);

    // For fault canary
    size_t rsize = ccec_signature_r_s_size(key);
    uint8_t *r_input = (uint8_t *)CC_ALLOC_WS(ws, n);
    cc_memset(r_input, 0xaa, rsize);
    uint8_t *r_computed = (uint8_t *)CC_ALLOC_WS(ws, n);
    cc_memset(r_computed, 0xff, rsize);

    size_t qbitlen = ccec_cp_order_bitlen(cp);

    // Convert digest to a field element
    size_t d_nbytes = CC_MIN_EVAL(digest_len, CC_BITLEN_TO_BYTELEN(qbitlen));
    cc_require(((result = ccn_read_uint(n, e, d_nbytes, digest)) >= 0), errOut);

    // Shift away low-order bits
    if (digest_len * 8 > qbitlen) {
        ccn_shift_right(n, e, e, -qbitlen % 8);
    }

    // e (mod q)
    if (ccn_sub_ws(ws, n, w, e, cczp_prime(zq)) == 0) {
        ccn_set(n, e, w);
    }

    // Recover scalars d0 and d1 with:
    //    w  = s^-1 mod q
    //    d0 = e.w  mod q
    //    d1 = r.w  mod q
    cc_require_action(cczp_inv_ws(ws, zq, w, s) == CCERR_OK, errOut, result = CCERR_PARAMETER);
    cczp_mul_ws(ws, zq, d0, e, w);
    cczp_mul_ws(ws, zq, d1, r, w);

    // We require the public key to be in affine representation
    ccec_projective_point_t pub_key_point = ccec_ctx_point(key);
    cc_require_action(ccn_is_one(n, ccec_const_point_z(pub_key_point, cp)), errOut, result = CCERR_PARAMETER);

    // Projectify both points and verify the public point is on the curve
    result = ccec_projectify_ws(ws, cp, mg, base, NULL);
    cc_require(result == CCERR_OK, errOut);
    result = ccec_projectify_ws(ws, cp, mk, (ccec_const_affine_point_t)pub_key_point, NULL);
    cc_require(result == CCERR_OK, errOut);
    cc_require_action(ccec_is_point_ws(ws, cp, mk), errOut, result = CCERR_PARAMETER);

    // Multiply the points by the scalars and combine; see the above helpers
    result = ccec_verify_computemults_ws(ws, cp, mg, d0, mg, d1, mk, ccec_const_point_x(pub_key_point, cp));
    cc_require(result == CCERR_OK, errOut);

    // Affinify and reduce x
    cc_require_action(ccec_affinify_x_only_ws(ws, cp, ccec_point_x(mg, cp), mg) == CCERR_OK, errOut, result = CCERR_PARAMETER);
    if (ccn_cmp(n, ccec_point_x(mg, cp), cczp_prime(zq)) >= 0) {
        ccn_sub_ws(ws, n, ccec_point_x(mg, cp), ccec_point_x(mg, cp), cczp_prime(zq));
    }

    // Verify x = r
    if (ccn_cmp(n, ccec_point_x(mg, cp), r) == 0) {
        result = CCERR_VALID_SIGNATURE;
    } else {
        result = CCERR_INVALID_SIGNATURE;
    }

    ccn_write_uint_padded_ct(n, r, rsize, r_input);
    ccn_write_uint_padded_ct(n, ccec_point_x(mg, cp), rsize, r_computed);

    cc_fault_canary_set(fault_canary_out, CCEC_FAULT_CANARY, rsize, r_input, r_computed);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_verify_internal_ws(cc_ws_t ws,
                            ccec_pub_ctx_t key,
                            size_t digest_len,
                            const uint8_t *digest,
                            const cc_unit *r,
                            const cc_unit *s,
                            cc_fault_canary_t fault_canary_out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    ccec_const_affine_point_t base = ccec_cp_g(cp);
    return ccec_verify_internal_with_base_ws(ws, key, digest_len, digest, r, s, base, fault_canary_out);
}
