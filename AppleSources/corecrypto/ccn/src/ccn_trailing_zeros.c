/* Copyright (c) (2010,2011,2015,2016,2018,2019) Apple Inc. All rights reserved.
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

size_t ccn_trailing_zeros(cc_size count, const cc_unit *s)
{
    size_t tz = 0;

    cc_unit msb = CC_UNIT_C(1) << (CCN_UNIT_BITS - 1);

    for (cc_size i = count - 1; i < count; i--) {
        cc_unit st;
        CC_HEAVISIDE_STEP(st, s[i]);

        // Update tz only if s[i] > 0. Set s[i]'s most-significant bit
        // to avoid the invalid cc_ctz_nonzero(0) case.
        cc_size ctz = cc_ctz_nonzero(s[i] | msb);
        CC_MUXU(tz, st, ccn_bitsof_n(i) + ctz, tz);
    }

    return tz;
}
