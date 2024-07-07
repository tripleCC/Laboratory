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

void ccz_add(ccz *r, const ccz *s, const ccz *t)
{
    CC_ENSURE_DIT_ENABLED

    size_t sn = ccz_n(s);
    size_t tn = ccz_n(t);

    if (ccz_sign(s) == ccz_sign(t)) {
        ccz_set_sign(r, ccz_sign(s));
        if (sn >= tn) {
            ccz_set_capacity(r, sn + 1);
            r->u[sn] = ccn_addn(sn, r->u, s->u, tn, t->u);
            sn = sn + 1;
        } else {
            ccz_set_capacity(r, tn + 1);
            r->u[tn] = ccn_addn(tn, r->u, t->u, sn, s->u);
            sn = tn + 1;
        }
    } else {
        if (ccn_cmpn(sn, s->u, tn, t->u) >= 0) {
            ccz_set_sign(r, ccz_sign(s));
            ccz_set_capacity(r, sn);
            ccn_subn(sn, r->u, s->u, tn, t->u);
        } else {
            ccz_set_sign(r, ccz_sign(t));
            ccz_set_capacity(r, tn);
            ccn_subn(tn, r->u, t->u, sn, s->u);
            sn = tn;
        }
    }
    ccz_set_n(r, ccn_n(sn, r->u));
}
