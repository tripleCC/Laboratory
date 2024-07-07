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
#include "ccec_internal.h"

#if !CCEC_VERIFY_ONLY

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define SCA_MASK_MSBIT (CC_UNIT_C(1) << (SCA_MASK_BITSIZE - 1))
#define SCA_MASK_MASK ((SCA_MASK_MSBIT - 1) | SCA_MASK_MSBIT)

cc_static_assert(SCA_MASK_N == 1, "needs to fit in a word");

int ccec_mult_blinded_ws(cc_ws_t ws,
                         ccec_const_cp_t cp,
                         ccec_projective_point_t R,
                         const cc_unit *d,
                         ccec_const_projective_point_t S,
                         struct ccrng_state *rng)
{
    cc_assert(R != S);

    int status;
    cc_size n = ccec_cp_n(cp);

    // ccec_mult_ws() requires |d| <= |q|, but here we check that |d| <= |p|.
    //
    // For all NIST curves, |p| = |q|, so the checks are equivalent.
    //
    // Curve448 allows scalars up to |p| = |q| + 2. The largest scalar
    // a = ⌊d / mask⌋ will not exceed |q| as long as |p| - |mask| + 1 <= |q|.
    if (ccn_bitlen(n, d) > ccec_cp_prime_bitlen(cp)) {
        return CCERR_PARAMETER;
    }

    // Euclidean scalar splitting.
    cc_unit mask[1] = { 1 };
    if (rng) {
        status = ccn_random(SCA_MASK_N, mask, rng);
        cc_require_or_return(status == CCERR_OK, status);
    }

    mask[0] |= SCA_MASK_MSBIT;

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *Q = CCEC_ALLOC_POINT_WS(ws, n);
    cc_unit *a = CC_ALLOC_WS(ws, n);

    // (Re-)Seed the PRNG used for mask generation.
    ccn_mux_seed_mask(mask[0]);

    // Clamp the mask to the desired number of bits.
    mask[0] &= SCA_MASK_MASK;

    // Q := mask.S
    status = ccec_mult_ws(ws, cp, Q, mask, SCA_MASK_BITSIZE, S);
    cc_require(status == CCERR_OK, errOut);

    // d = ⌊d / mask⌋ * mask + (d mod mask) = a * mask + b
    cc_unit b[1];
    ccn_divmod_ws(ws, n, d, n, a, 1, b, mask);

    // R := a.Q = mask.a.S
    status = ccec_mult_ws(ws, cp, R, a, ccec_cp_prime_bitlen(cp) - SCA_MASK_BITSIZE + 1, Q);
    cc_require(status == CCERR_OK, errOut);

    // Q := b.S
    status = ccec_mult_ws(ws, cp, Q, b, SCA_MASK_BITSIZE, S);
    cc_require(status == CCERR_OK, errOut);

    // R += Q
    ccec_full_add_ws(ws, cp, R, R, Q);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccec_mult_blinded(ccec_const_cp_t cp,
                      ccec_projective_point_t R,
                      const cc_unit *d,
                      ccec_const_projective_point_t S,
                      struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_MULT_BLINDED_WORKSPACE_N(ccec_cp_n(cp)));
    int result = ccec_mult_blinded_ws(ws, cp, R, d, S, rng);
    CC_FREE_WORKSPACE(ws);
    return result;
}

#endif  // !CCEC_VERIFY_ONLY
