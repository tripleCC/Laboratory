/* Copyright (c) (2014-2021) Apple Inc. All rights reserved.
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

CC_PURE cc_size CCN_SQR_WORKSPACE_N(cc_size n)
{
    return CC_MAX_EVAL(2 * n, CCN_MUL_WORKSPACE_N(n));
}

/* Do r = s^2, r is 2 * n cc_units in size, s is n * cc_units in size. */
void ccn_sqr_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s)
{
#if CC_DUNIT_SUPPORTED && !CC_SMALL_CODE
    cc_dunit prod, sum;
    cc_unit cadd;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);

    // Set of s0*sj
    t[n] = ccn_mul1(n - 1, &t[1], &s[1], s[0]);

    // Set of s0^2
    prod = (cc_dunit)s[0] * s[0];
    r[0] = (cc_unit)prod;
    sum = ((cc_dunit)t[1] << 1) + (prod >> CCN_UNIT_BITS);
    r[1] = (cc_unit)sum;
    cadd = (sum >> CCN_UNIT_BITS);

    // Main loop
    for (cc_size i = 1; i < n; i++) {
        // Set of si*sj
        t[i + n] = ccn_addmul1(n - (i + 1), &t[2*i + 1], &s[i + 1], s[i]);

        // 2t + r
        prod = (cc_dunit)s[i] * s[i] + cadd;
        sum = ((cc_dunit)t[2*i] << 1) + (prod & CCN_UNIT_MASK);
        r[2*i] = (cc_unit)sum;
        sum = ((cc_dunit)t[2*i + 1] << 1)
                + (prod >> CCN_UNIT_BITS)
                + (sum >> CCN_UNIT_BITS);
        r[2*i + 1] = (cc_unit)sum;
        cadd = (sum >> CCN_UNIT_BITS);
    }

    CC_FREE_BP_WS(ws, bp);
#else
    ccn_mul_ws(ws, n, r, s, s);
#endif // CC_DUNIT_SUPPORTED && !CC_SMALL_CODE
}
