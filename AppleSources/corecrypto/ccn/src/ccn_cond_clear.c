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

void ccn_cond_clear(cc_size n, cc_unit s, cc_unit *r)
{
    cc_unit m0, m1, mask;
    ccn_mux_setup(&m0, &m1, &mask, s);

    for (cc_size i = 0; i < n; i++) {
        ccn_mux_op(&r[i], 0U, r[i], m0, m1, mask);
    }
}

