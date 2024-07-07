/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
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

#if CC_DUNIT_SUPPORTED

CC_INLINE cc_unit _sub(cc_unit *r, cc_unit x, cc_unit y)
{
    cc_dunit diff = (cc_dunit)x - y;
    *r = (cc_unit)diff;
    return diff >> (CCN_UNIT_BITS * 2 - 1);
}

CC_INLINE cc_unit _mul_hi(cc_unit x, cc_unit y)
{
    return ((cc_dunit)x * y) >> CCN_UNIT_BITS;
}

#else

CC_INLINE cc_unit _sub(cc_unit *r, cc_unit x, cc_unit y)
{
    return ccn_sub_ws(NULL, 1, r, &x, &y);
}

CC_INLINE cc_unit _mul_hi(cc_unit x, cc_unit y)
{
    cc_unit tmp[2];
    ccn_mul(1, tmp, &x, &y);
    return tmp[1];
}

#endif

bool ccn_divides1(cc_size n, const cc_unit *x, cc_unit q)
{
    cc_unit tmp, bw, cy = 0;
    cc_unit qinv = ccn_invert(q);

    for (cc_size i = 0; i < n; i++) {
        bw = _sub(&tmp, x[i], cy);
        tmp = (tmp * qinv) + bw;
        cy = _mul_hi(tmp, q);
    }

    CC_HEAVISIDE_STEP(cy, cy);
    return 1 ^ cy;
}
