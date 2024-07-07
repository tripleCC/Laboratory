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

#include <corecrypto/ccz_priv.h>

int ccz_sign(const ccz *s) {
    return s->sac < 0 ? -1 : 1;
}

cc_size ccz_n(const ccz *s) {
    return s->n;
}

cc_size ccz_capacity(const ccz *s) {
    return (cc_size)(s->sac < 0 ? -s->sac : s->sac);
}

#if !CC_PTRCHECK

void ccz_set_sign(ccz *r, int sign)
{
    if (ccz_sign(r) != sign)
        r->sac = -r->sac;
}

void ccz_set_n(ccz *r, cc_size n) {
    r->n = n;
}

void ccz_set_capacity(ccz *r, cc_size capacity)
{
    if (r->u == NULL || ccz_capacity(r) < capacity) {
        size_t ncapacity = capacity + (CCZ_PREC * 2) - (capacity % CCZ_PREC);
        cc_unit *t;
        if (ccz_capacity(r))
            t = (cc_unit *)r->isa->ccz_realloc(r->isa->ctx, ccn_sizeof_n(ccz_capacity(r)), r->u, ccn_sizeof_n(ncapacity));
        else
            t = (cc_unit *)r->isa->ccz_alloc(r->isa->ctx, ccn_sizeof_n(ncapacity));

        r->sac = r->sac < 0 ? -(int)ncapacity : (int)ncapacity;
        r->u = t;
    }
}

#endif
