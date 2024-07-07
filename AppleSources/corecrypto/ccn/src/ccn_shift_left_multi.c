/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccn.h>
#include "ccn_internal.h"
#include <corecrypto/cc_priv.h>

void ccn_shift_left_multi(cc_size n, cc_unit *r, const cc_unit *s, size_t k)
{
    cc_size offset = k / CCN_UNIT_BITS;
    size_t lshift = k & (CCN_UNIT_BITS - 1);

    // Shift left by 0 <= n < CCN_UNIT_BITS.
    ccn_shift_left(n, r, s, lshift);

    // Apply the word-sized offset.
    for (cc_size i = n - 1; i < n; i--) {
        r[i] = ccn_select(0, i + 1, r, i - offset);
    }
}
