/* Copyright (c) (2012,2015,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdh_internal.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdh.h>

bool ccdh_valid_shared_secret(cc_size n, const cc_unit *s, ccdh_const_gp_t gp)
{
    cc_assert(ccdh_gp_prime(gp)[0] & 1);

    // Both (a=0 and b=0) iff (s == p - 1).
    // This method does not require any extra stack memory
    cc_unit a = (cc_unit)ccn_cmp(n - 1, ccdh_gp_prime(gp) + 1, s + 1);
    cc_unit b = s[0] ^ (ccdh_gp_prime(gp)[0] - 1);
    cc_unit is_not_pm1;
    CC_HEAVISIDE_STEP(is_not_pm1, a | b);
    
    if (ccn_is_zero_or_one(n, s) || !is_not_pm1) {
        return false;
    }

    return true;
}
