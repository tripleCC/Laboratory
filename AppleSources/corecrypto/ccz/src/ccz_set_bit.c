/* Copyright (c) (2012,2015,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccz_priv.h>

void ccz_set_bit(ccz *r, size_t k, bool v) {
    CC_ENSURE_DIT_ENABLED

    const cc_size n = (k / CCN_UNIT_BITS) + 1;
    if (ccz_n(r) < n) {
        ccz_set_capacity(r, n);
        ccn_zero(n - ccz_n(r), r->u + ccz_n(r));
        ccz_set_n(r, n);
    }
    ccn_set_bit(r->u, k, v);
}
