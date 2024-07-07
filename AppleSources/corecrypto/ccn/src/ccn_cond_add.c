/* Copyright (c) (2018,2020,2021) Apple Inc. All rights reserved.
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

cc_unit ccn_cond_add(cc_size n, cc_unit s, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit m0, m1, mask;
    ccn_mux_setup(&m0, &m1, &mask, s);

#if CC_DUNIT_SUPPORTED
    cc_dunit c = 0;
#else
    cc_unit c = 0;
#endif

    for (cc_size i = 0; i < n; i++) {
        cc_unit u1 = x[i];

#if CC_DUNIT_SUPPORTED
        c += (cc_dunit)x[i] + y[i];
        cc_unit u0 = (cc_unit)c;
        c >>= CCN_UNIT_BITS;
#else
        c += x[i] & CCN_UNIT_LOWER_HALF_MASK;
        c += y[i] & CCN_UNIT_LOWER_HALF_MASK;
        cc_unit lo = c & CCN_UNIT_LOWER_HALF_MASK;
        c >>= CCN_UNIT_HALF_BITS;

        c += x[i] >> CCN_UNIT_HALF_BITS;
        c += y[i] >> CCN_UNIT_HALF_BITS;
        cc_unit u0 = (c << CCN_UNIT_HALF_BITS) | lo;
        c >>= CCN_UNIT_HALF_BITS;
#endif

        ccn_mux_op(&r[i], u0, u1, m0, m1, mask);
    }

    return (cc_unit)c & s;
}
