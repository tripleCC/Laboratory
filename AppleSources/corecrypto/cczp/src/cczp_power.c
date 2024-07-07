/* Copyright (c) (2011,2012,2014-2022) Apple Inc. All rights reserved.
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
#include "cc_debug.h"
#include "cc_macros.h"
#include "cc_workspaces.h"

/* r = s^e (mod zp->prime).
 Implements square square multiply always: 2bit fix windows
 running in constant time. A dummy multiplication is performed when both bit
 are zeros so that the execution has a regular flow. */
int cczp_power_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, size_t ebitlen, const cc_unit *e)
{
    cc_size n = cczp_n(zp);
    cc_assert(r != e);

    /* We require s < p. */
    if (ccn_cmp(n, s, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_unit *minusone = CC_ALLOC_WS(ws, 4 * n);
    cc_unit *m1 = &minusone[1 * n];
    cc_unit *m2 = &minusone[2 * n];
    cc_unit *m3 = &minusone[3 * n];
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);

    /* Precomputations */

    // Use -1 since 1 has very low hamming weight. Minus one is much less leakage prone.
    ccn_sub1(n, minusone, cczp_prime(zp), 1);
    cczp_to_ws(ws, zp, minusone, minusone);
    ccn_set(n, m1, s);
    cczp_sqr_ws(ws, zp, m2, s);
    cczp_mul_ws(ws, zp, m3, s, m2);
    ccn_set(n, r, minusone);

    ebitlen += ebitlen & 1; // round up to even number

    /* 2bit fixed window */
    for (size_t k = ebitlen; k > 1; k -= 2) {
        // Square & Square.
        cczp_sqr_ws(ws, zp, r, r);
        cczp_sqr_ws(ws, zp, r, r);

        // 4-to-1 multiplexer.
        ccn_mux(2 * n, ccn_bit(e, k - 1), t, &minusone[2 * n], minusone);
        ccn_mux(n, ccn_bit(e, k - 2), t, &t[n], t);

        // Multiply.
        cczp_mul_ws(ws, zp, r, r, t);
    }

    /* compensate for extra -1 operation */
    cczp_cond_negate(zp, (((e[0] >> 1) | e[0]) & 1) ^ 1, r, r);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}
