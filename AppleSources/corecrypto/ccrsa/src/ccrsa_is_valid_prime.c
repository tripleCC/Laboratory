/* Copyright (c) (2020,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"
#include "ccrsa_internal.h"
#include "ccprime_internal.h"
#include "cc_workspaces.h"

int ccrsa_is_valid_prime_ws(cc_ws_t ws,
                            cc_size np,
                            const cc_unit *p,
                            cc_size ne,
                            const cc_unit *e,
                            size_t mr_depth,
                            struct ccrng_state *rng)
{
    cc_assert(ne <= np);
    // The caller should pass the number of units occupied by 'e'.
    cc_assert(ccn_n(ne, e) == ne);

    CC_DECL_BP_WS(ws, bp);

    cc_size n = np;
    cc_unit *pm1 = CC_ALLOC_WS(ws, n);
    ccn_set(np, pm1, p);
    pm1[0] &= ~CC_UNIT_C(1);

    // Check if gcd(p-1,e) == 1.
    cc_unit *t = CC_ALLOC_WS(ws, n);
    size_t k = ccn_gcd_ws(ws, np, t, np, pm1, ne, e);
    int rv = (k == 0) && ccn_is_one(np, t);

    // Check if p is really a prime.
    if (rv == 1) {
        rv = ccprime_rabin_miller_ws(ws, np, p, mr_depth, rng);
    }

    CC_FREE_BP_WS(ws, bp);
    return rv;
}
