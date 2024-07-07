/* Copyright (c) (2022) Apple Inc. All rights reserved.
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

void ccn_muln(cc_size n, cc_unit *r, const cc_unit *s, cc_size nv, const cc_unit *v)
{
    cc_assert(r != s);
    cc_assert(r != v);

    r[n] = ccn_mul1(n, r, s, v[0]);        
    for (cc_size i = 1; i < nv; i++) {
        r[n + i] = ccn_addmul1(n, &r[i], s, v[i]);
    }
}

