/* Copyright (c) (2019-2022) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"

void cczp_mm_redc_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    cc_size n = cczp_n(zp);
    cc_unit n0 = cczp_p0inv(zp);

    // t += (t * N' (mod R)) * N
    for (cc_size i = 0; i < n; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
        t[i] = ccn_addmul1(n, &t[i], cczp_prime(zp), t[i] * n0);
    }

    // Optional final reduction.
    cc_unit s = ccn_add_ws(ws, n, &t[n], &t[n], t);
    s ^= ccn_sub_ws(ws, n, t, &t[n], cczp_prime(zp));
    ccn_mux(n, s, r, &t[n], t);
}
