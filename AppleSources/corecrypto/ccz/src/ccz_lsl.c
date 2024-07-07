/* Copyright (c) (2011,2012,2015,2017-2021) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"

void ccz_lsl(ccz *r, const ccz *s, size_t k)
{
    CC_ENSURE_DIT_ENABLED

    ccz_set_sign(r, ccz_sign(s));
    ccz_set_capacity(r, ccz_n(s) + ccn_nof(k));

    cc_size kn = k / CCN_UNIT_BITS;
    k &= (CCN_UNIT_BITS - 1);

    // Apply offset kn.
    cc_memmove(r->u + kn, s->u, ccn_sizeof_n(ccz_n(s)));
    ccz_set_n(r, ccz_n(s) + kn);
    ccn_zero(kn, r->u);

    // Apply shift mod w.
    if (k) {
        r->u[ccz_n(r)] = 0;
        ccn_shift_left(ccz_n(r) + 1 - kn, r->u + kn, r->u + kn, k);
        ccz_set_n(r, ccn_n(ccz_n(r) + 1, r->u));
    }
}
