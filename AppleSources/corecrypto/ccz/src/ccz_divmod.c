/* Copyright (c) (2012,2015,2017,2019,2021,2022) Apple Inc. All rights reserved.
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

/* q*t + r == s [e.g. s/t, q=quotient, r=remainder]. */
void ccz_divmod(ccz *q, ccz *r, const ccz *s, const ccz *t) {
    CC_ENSURE_DIT_ENABLED

    if (ccz_is_zero(t)) {
        /* Division by zero is illegal. */
        return;
    }

    /* If s < t then q = 0, r = s */
    if (ccn_cmpn(ccz_n(s), s->u, ccz_n(t), t->u) < 0) {
        if (r) ccz_set(r, s);
        if (q) ccz_zero(q);
        return;
    }

    ccz tr, tt, ta, tq;
    ccz_init(s->isa, &ta);
    ccz_init(s->isa, &tq);
    ccz_init(s->isa, &tr);
    ccz_init(s->isa, &tt);

    size_t k = ccz_bitlen(s) - ccz_bitlen(t);
    ccz_seti(&ta, 1);
    ccz_lsl(&ta, &ta, k);

    ccz_set(&tr, s);
    ccz_set_sign(&tr, 1);

    ccz_lsl(&tt, t, k);
    ccz_set_sign(&tt, 1);

    for (;;) {
        if (ccz_cmp(&tr, &tt) >= 0) {
            ccz_sub(&tr, &tr, &tt);
            ccz_add(&tq, &tq, &ta);
        }
        if (!k--)
            break;

        ccz_lsr(&tt, &tt, 1);
        ccz_lsr(&ta, &ta, 1);
    }

    int rs = ccz_sign(s);
    int qs = rs == ccz_sign(t) ? 1 : -1;
    if (r) {
        ccz_set_capacity(r, ccz_n(&tr));
        ccz_set_n(r, ccz_n(&tr));
        ccn_set(ccz_n(r), r->u, tr.u);
        ccz_set_sign(r, ccz_is_zero(r) ? 1 : rs);
    }
    if (q) {
        ccz_set_capacity(q, ccz_n(&tq));
        ccz_set_n(q, ccz_n(&tq));
        ccn_set(ccz_n(q), q->u, tq.u);
        ccz_set_sign(q, ccz_is_zero(q) ? 1 : qs);
    }

    ccz_free(&ta);
    ccz_free(&tq);
    ccz_free(&tr);
    ccz_free(&tt);
}
