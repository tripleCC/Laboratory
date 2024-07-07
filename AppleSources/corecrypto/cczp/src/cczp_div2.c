/* Copyright (c) (2010,2011,2015-2020,2022) Apple Inc. All rights reserved.
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

void cczp_div2_ws(CC_UNUSED cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);

    // if x is odd, r := (x + p) >> 1
    cc_unit carry = ccn_cond_add(n, x[0] & 1, r, x, cczp_prime(zp));
    ccn_shift_right(n, r, r, 1);

    // if x is odd, set carry, if any
    r[n - 1] |= carry << (CCN_UNIT_BITS - 1);

    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
}
