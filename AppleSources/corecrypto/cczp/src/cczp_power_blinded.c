/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cczp_internal.h"
#include "ccn_internal.h"
#include <corecrypto/ccrng.h>

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define SCA_MASK_MSBIT (CC_UNIT_C(1) << (SCA_MASK_BITSIZE - 1))

cc_static_assert(SCA_MASK_N == 1, "needs to fit in a word");

int cczp_power_blinded_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, size_t ebitlen, const cc_unit *e, struct ccrng_state *rng)
{
    // Pad ebitlen to at least SCA_MASK_BITSIZE, to handle small bit lengths.
    ebitlen = CC_MAX_EVAL(ebitlen, SCA_MASK_BITSIZE);

    cc_size n = cczp_n(zp);
    cc_size ne = ccn_nof(ebitlen);

    // We require s < p.
    if (ccn_cmp(n, s, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *q = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    cc_unit mask[1];
    int rv = ccn_random_bits(SCA_MASK_BITSIZE, mask, rng);
    cc_require(rv == CCERR_OK, errOut);
    mask[0] |= SCA_MASK_MSBIT;

    // (Re-)Seed the PRNG used for mask generation.
    ccn_mux_seed_mask(mask[0]);

    // e = floor(e / mask) * mask + (e mod mask) = q * mask + b
    cc_unit b[1];
    ccn_divmod_ws(ws, ne, e, ne, q, 1, b, mask);

    // t := s^q
    rv = cczp_power_ws(ws, zp, t, s, ebitlen - SCA_MASK_BITSIZE + 1, q);
    cc_require(rv == CCERR_OK, errOut);

    // r := s^b
    rv = cczp_power_ws(ws, zp, r, s, SCA_MASK_BITSIZE, b);
    cc_require(rv == CCERR_OK, errOut);

    // q := s^q^mask
    rv = cczp_power_ws(ws, zp, q, t, SCA_MASK_BITSIZE, mask);
    cc_require(rv == CCERR_OK, errOut);

    // r := s^b * s^q^mask
    cczp_mul_ws(ws, zp, r, r, q);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
