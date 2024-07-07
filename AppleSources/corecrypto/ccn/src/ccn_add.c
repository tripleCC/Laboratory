/* Copyright (c) (2010,2015,2018-2022) Apple Inc. All rights reserved.
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

#if CCN_ADD_ASM
cc_unit ccn_add_asm(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t) __asm__("_ccn_add_asm");
#endif

cc_unit ccn_add_ws(CC_UNUSED cc_ws_t ws, cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
#if CCN_ADD_ASM
    return ccn_add_asm(count, r, s, t);
#else

#if CC_DUNIT_SUPPORTED
    cc_dunit carry = 0;

    for (cc_size i = 0; i < count; i++) {
        carry += (cc_dunit)s[i] + t[i];
        r[i] = (cc_unit)carry;
        carry >>= CCN_UNIT_BITS;
    }
#else
    cc_unit carry = 0;

    for (cc_size i = 0; i < count; i++) {
        carry += s[i] & CCN_UNIT_LOWER_HALF_MASK;
        carry += t[i] & CCN_UNIT_LOWER_HALF_MASK;
        cc_unit lo = carry & CCN_UNIT_LOWER_HALF_MASK;
        carry >>= CCN_UNIT_HALF_BITS;

        carry += s[i] >> CCN_UNIT_HALF_BITS;
        carry += t[i] >> CCN_UNIT_HALF_BITS;
        r[i] = (carry << CCN_UNIT_HALF_BITS) | lo;
        carry >>= CCN_UNIT_HALF_BITS;
    }
#endif /* CC_DUNIT_SUPPORTED */

    return (cc_unit)carry;
#endif /* CCN_ADD_ASM */
}

cc_unit ccn_add(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_NULL(ws);
    cc_unit c = ccn_add_ws(ws, n, r, s, t);
    CC_FREE_WORKSPACE(ws);
    return c;
}
