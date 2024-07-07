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

void ccn_cond_shift_right_carry(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, size_t k, cc_unit c)
{
    cc_unit m0, m1, mask;
    ccn_mux_setup(&m0, &m1, &mask, s);

#if !CC_DUNIT_SUPPORTED
    // km := (k > 0) ? 2^w-1 : 0
    cc_unit km;
    CC_HEAVISIDE_STEP(km, k);
    km = -km;

    // ki := (k > 0) ? w-k : 0
    size_t ki = -k & (CCN_UNIT_BITS - 1);
#endif

    for (cc_size i = n - 1; i < n; i--) {
#if CC_DUNIT_SUPPORTED
        cc_unit u0 = (cc_unit)((((cc_dunit)c << CCN_UNIT_BITS) | a[i]) >> k);
#else
        cc_unit u0 = ((c << ki) & km) | (a[i] >> k);
#endif
        cc_unit u1 = c = a[i];
        ccn_mux_op(&r[i], u0, u1, m0, m1, mask);
    }
}

void ccn_cond_shift_right(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, size_t k)
{
    ccn_cond_shift_right_carry(n, s, r, a, k, 0);
}
