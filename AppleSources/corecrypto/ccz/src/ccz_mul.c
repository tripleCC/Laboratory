/* Copyright (c) (2011,2012,2014,2015,2019-2021) Apple Inc. All rights reserved.
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

void ccz_mul(ccz *r, const ccz *s, const ccz *t)
{
    CC_ENSURE_DIT_ENABLED

    ccz_set_sign(r, ccz_sign(s) * ccz_sign(t));
    cc_size n = CC_MAX(ccz_n(s), ccz_n(t));

    ccz u, v;
    ccz_init(s->isa, &u);
    ccz_init(s->isa, &v);
    ccz_set_capacity(&u, n);
    ccz_set_capacity(&v, n);

    ccn_setn(n, u.u, ccz_n(s), s->u);
    ccn_setn(n, v.u, ccz_n(t), t->u);

    ccz_set_capacity(r, 2 * n);
    ccn_mul(n, r->u, v.u, u.u);
    ccz_set_n(r, ccn_n(ccz_n(s) + ccz_n(t), r->u));

    ccz_free(&u);
    ccz_free(&v);
}
