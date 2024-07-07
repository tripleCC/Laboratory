/* Copyright (c) (2010-2012,2014-2016,2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "ccn_internal.h"
#include "cc_priv.h"

#if CCN_SHIFT_RIGHT_ASM
void ccn_shift_right_asm(cc_size count, cc_unit *r, const cc_unit *s, size_t k) __asm__("_ccn_shift_right_asm");
#endif

void ccn_shift_right(cc_size count, cc_unit *r, const cc_unit *s, size_t k)
{
    cc_assert(k < CCN_UNIT_BITS);

    if (count == 0) {
        return;
    }

#if CCN_SHIFT_RIGHT_ASM
    ccn_shift_right_asm(count, r, s, k);
#else

    cc_unit knz; // k≠0?
    CC_HEAVISIDE_STEP(knz, k);
    cc_unit kmask = -knz;

    cc_unit m = CCN_UNIT_BITS - k - (knz ^ 1);
    cc_unit prev = s[0];

    cc_size ix;
    for (ix = 1; ix < count; ++ix) {
        cc_unit v = s[ix];
        r[ix - 1] = (prev >> k) | ((v << m) & kmask);
        prev = v;
    }
    r[ix - 1] = (prev >> k);
#endif // CCN_SHIFT_RIGHT_ASM
}
