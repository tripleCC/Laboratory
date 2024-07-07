/* Copyright (c) (2012,2015,2020,2022,2023) Apple Inc. All rights reserved.
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

void ccn_neg(cc_size n, cc_unit *r, const cc_unit *x)
{
    for (cc_size i = 0; i < n; i++) {
        r[i] = x[i] ^ CCN_UNIT_MASK;
    }

    ccn_add1_ws(NULL, n, r, r, 1);
}
