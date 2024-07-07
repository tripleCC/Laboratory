/* Copyright (c) (2012,2015,2017-2020,2022) Apple Inc. All rights reserved.
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

void ccn_lcm_ws(cc_ws_t ws, cc_size n, cc_unit *r2n, const cc_unit *s, const cc_unit *t)
{
    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    size_t k = ccn_gcd_ws(ws, n, tmp, n, s, n, t);
    ccn_div_exact_ws(ws, n, tmp, t, tmp);
    ccn_shift_right_multi(n, tmp, tmp, k);
    ccn_mul_ws(ws, n, r2n, s, tmp);

    CC_FREE_BP_WS(ws, bp);
}
