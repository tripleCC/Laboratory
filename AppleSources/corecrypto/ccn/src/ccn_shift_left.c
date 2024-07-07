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

#include "ccn_internal.h"

#if !CCN_SHIFT_LEFT_ASM

void ccn_shift_left(cc_size count, cc_unit *r, const cc_unit *s, size_t k)
{
    cc_assert(k < CCN_UNIT_BITS);

    if (count == 0) {
        return;
    }

    cc_unit knz; // k≠0?
    CC_HEAVISIDE_STEP(knz, k);
    cc_unit kmask = -knz;

    cc_size i = count - 1;
    cc_unit m = CCN_UNIT_BITS - k - (knz ^ 1);

    cc_unit sip1 = s[i];

    while (i) {
        i--;
        cc_unit si = s[i];
        r[i + 1] = (sip1 << k) | ((si >> m) & kmask);
        sip1 = si;
    }
    r[0] = (sip1 << k);
}

#endif // !CCN_SHIFT_LEFT_ASM
