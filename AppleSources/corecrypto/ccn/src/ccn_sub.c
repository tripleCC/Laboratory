/* Copyright (c) (2010,2011,2015,2018-2022) Apple Inc. All rights reserved.
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

#if CCN_SUB_ASM
cc_unit ccn_sub_asm(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t) __asm__("_ccn_sub_asm");
#endif

cc_unit ccn_sub_ws(CC_UNUSED cc_ws_t ws, cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
#if CCN_SUB_ASM
    return ccn_sub_asm(count, r, s, t);
#else

#if CC_DUNIT_SUPPORTED
    cc_dunit borrow = 0;

    for (cc_size i = 0; i < count; i++) {
        borrow = (cc_dunit)s[i] - t[i] - borrow;
        r[i] = (cc_unit)borrow;
        borrow >>= CCN_UNIT_BITS * 2 - 1;
    }
#else
    cc_unit borrow = 0;

    for (cc_size i = 0; i < count; i++) {
        borrow = (s[i] & CCN_UNIT_LOWER_HALF_MASK) -
                 (t[i] & CCN_UNIT_LOWER_HALF_MASK) - borrow;
        cc_unit lo = borrow & CCN_UNIT_LOWER_HALF_MASK;
        borrow >>= CCN_UNIT_BITS - 1;

        borrow = (s[i] >> CCN_UNIT_HALF_BITS) -
                 (t[i] >> CCN_UNIT_HALF_BITS) - borrow;
        r[i] = (borrow << CCN_UNIT_HALF_BITS) | lo;
        borrow >>= CCN_UNIT_BITS - 1;
    }
#endif

    return (cc_unit)borrow;
#endif /* CCN_SUB_ASM */
}

cc_unit ccn_sub(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_NULL(ws);
    cc_unit b = ccn_sub_ws(ws, n, r, s, t);
    CC_FREE_WORKSPACE(ws);
    return b;
}
