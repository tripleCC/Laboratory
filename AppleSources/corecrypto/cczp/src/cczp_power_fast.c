/* Copyright (c) (2014-2023) Apple Inc. All rights reserved.
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
#include "cc_workspaces.h"

/* r = s^e (mod zp->prime). Implements 2bit window method
 Leaks the exponent, to be used with public values only.
 Caller provides recip of m as recip; s and r can have the same address. */
int cczp_power_fast_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    cc_assert(r != e);

    size_t ebitlen = ccn_bitlen(n, e);

    // s^0 == 1.
    if (ebitlen == 0) {
        ccn_seti(n, r, 1);
        cczp_to_ws(ws, zp, r, r);
        return CCERR_OK;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *s1 = CC_ALLOC_WS(ws, 3 * n);
    cc_unit *s2 = s1 + (1 * n);
    cc_unit *s3 = s1 + (2 * n);

    // Precompute for a 2-bit window.
    ccn_set(n, s1, s);               // s^1
    cczp_sqr_ws(ws, zp, s2, s1);     // s^2
    cczp_mul_ws(ws, zp, s3, s2, s1); // s^3

    // First iteration uses precomputed values only.
    cc_unit b = ccn_bit(e, ebitlen - 1);

    // If e is an even number of bits,
    // grab the second-most-significant bit too.
    if ((ebitlen & 1) == 0) {
        b = (b << 1) | ccn_bit(e, ebitlen - 2);
    }

    ccn_set(n, r, s1 + n * (b - 1));

    // Round down to the next multiple of two.
    ebitlen -= 2 - (ebitlen & 1);

    // Loop over the remaining bits.
    for (size_t bit = ebitlen; bit > 0; bit -= 2) {
        cczp_sqr_ws(ws, zp, r, r);
        cczp_sqr_ws(ws, zp, r, r);

        b = (ccn_bit(e, bit - 1) << 1) | ccn_bit(e, bit - 2);
        if (b > 0) {
            cczp_mul_ws(ws, zp, r, r, s1 + n * (b - 1));
        }
    }

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int cczp_power_fast(cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_POWER_FAST_WORKSPACE_N(n));
    int rv = cczp_power_fast_ws(ws, zp, r, s, e);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
