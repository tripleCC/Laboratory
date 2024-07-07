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
#include "cczp_internal.h"

int cczp_is_quadratic_residue_ws(cc_ws_t ws, cczp_const_t zp, const cc_unit *a)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    // pm1 = p-1
    cc_unit *pm1 = CC_ALLOC_WS(ws, n);
    ccn_set(n, pm1, cczp_prime(zp));
    pm1[0] &= ~CC_UNIT_C(1);

    // pm1h = (p-1)/2
    cc_unit *pm1h = CC_ALLOC_WS(ws, n);
    ccn_shift_right(n, pm1h, pm1, 1);

    // s = a^((p-1)/2)
    cc_unit *s = CC_ALLOC_WS(ws, n);

    /*
     When cczp_power_fast_ws fails (i.e. when a >= p) it returns 1
     which is the "success" case of cczp_is_quadratic_residue_ws.

     Therefore, when the return value is 0, we need to set rv to 1.
     Otherwise, rv should be 0.
     */
    int rv = cczp_power_fast_ws(ws, zp, s, a, pm1h);

    // Set rv to 0 if rv == 0, set rv to 1 if rv != 0
    CC_HEAVISIDE_STEP(rv, rv);

    // Set rv to 1 if rv == 0, set rv to 0 if rv != 0
    rv ^= 1;

    // a^((p-1)/2) =  1 mod p, if a is a quadratic residue.
    // a^((p-1)/2) = -1 mod p, if a is a non-residue. This is a failure case.
    // a^((p-1)/2) =  0 mod p, if gcd(a,p) > 1. This is a failure case.
    cczp_from_ws(ws, zp, s, s);
    rv &= ccn_is_one(n, s);

    CC_FREE_BP_WS(ws, bp);
    return rv;
}
