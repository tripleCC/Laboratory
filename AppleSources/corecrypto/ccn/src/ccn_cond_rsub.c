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
#include "ccn_mux.h"

cc_unit ccn_cond_rsub(cc_size n, cc_unit s, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit m0, m1, mask;
    ccn_mux_setup(&m0, &m1, &mask, s);

#if CC_DUNIT_SUPPORTED
    cc_dunit b = 0;
#else
    cc_unit b = 0;
#endif

    for (cc_size i = 0; i < n; i++) {
        cc_unit u1 = x[i];

#if CC_DUNIT_SUPPORTED
        b = (cc_dunit)y[i] - x[i] - b;
        cc_unit u0 = (cc_unit)b;
        b >>= CCN_UNIT_BITS * 2 - 1;
#else
        b = (y[i] & CCN_UNIT_LOWER_HALF_MASK) -
            (x[i] & CCN_UNIT_LOWER_HALF_MASK) - b;
        cc_unit lo = b & CCN_UNIT_LOWER_HALF_MASK;
        b >>= CCN_UNIT_BITS - 1;

        b = (y[i] >> CCN_UNIT_HALF_BITS) -
            (x[i] >> CCN_UNIT_HALF_BITS) - b;
        cc_unit u0 = (b << CCN_UNIT_HALF_BITS) | lo;
        b >>= CCN_UNIT_BITS - 1;
#endif

        ccn_mux_op(&r[i], u0, u1, m0, m1, mask);
    }

    return (cc_unit)b & s;
}
