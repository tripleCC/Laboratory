/* Copyright (c) (2018-2020,2022) Apple Inc. All rights reserved.
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

void cczp_negate(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    cc_assert(ccn_cmp(n, x, cczp_prime(zp)) < 0);

    cc_unit z = (cc_unit)ccn_is_zero(n, x);
    (void)ccn_cond_rsub(n, z ^ 1, r, x, cczp_prime(zp));

    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
}

void cczp_cond_negate(cczp_const_t zp, cc_unit s, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    cc_assert(s == 0 || s == 1);
    cc_assert(ccn_cmp(n, x, cczp_prime(zp)) < 0);

    cc_unit z = (cc_unit)ccn_is_zero(n, x);
    (void)ccn_cond_rsub(n, s & (z ^ 1), r, x, cczp_prime(zp));

    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
}
