/* Copyright (c) (2011,2012,2015,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccz_priv.h>

void ccz_lsr(ccz *r, const ccz *s, size_t k)
{
    CC_ENSURE_DIT_ENABLED

    size_t l = ccn_bitlen(ccz_n(s), s->u);
    if (l <= k) {
        ccz_zero(r);
    } else {
        cc_size kn = k / CCN_UNIT_BITS;
        l -= k;
        k &= (CCN_UNIT_BITS - 1);
        ccz_set_sign(r, ccz_sign(s));
        ccz_set_capacity(r, ccz_n(s) - kn);
        if (k) {
            ccn_shift_right(ccz_n(s) - kn, r->u, s->u + kn, k);
        } else if (kn || r != s) {
            /* Forward copy, safe to use ccn_set(). */
            ccn_set(ccz_n(s) - kn, r->u, s->u + kn);
        }
        ccz_set_n(r, ccn_nof(l));
    }
}
