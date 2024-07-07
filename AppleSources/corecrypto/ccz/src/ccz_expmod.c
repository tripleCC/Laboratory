/* Copyright (c) (2012,2015-2022) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "cc_macros.h"

// Computes r := s^t (mod u)
static int ccz_expmod_ws(cc_ws_t ws, ccz *r, const ccz *s, const ccz *t, const ccz *u)
{
    cc_assert(r != t);

    cc_size n = ccz_n(u);
    ccz_set_capacity(r, n);

    CC_DECL_BP_WS(ws, bp);

    cczp_t zu = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(n));
    CCZP_N(zu) = n;
    ccn_set(n, CCZP_PRIME(zu), u->u);

    int status = cczp_init_ws(ws, zu);
    cc_require(status == CCERR_OK, errOut);

    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    if (ccz_n(s) < ccz_n(u)) {
        ccn_setn(n, tmp, ccz_n(s), s->u);
    } else {
        cczp_modn_ws(ws, zu, tmp, ccz_n(s), s->u);
    }

    size_t tbits = ccz_bitlen(t);
    status = cczp_power_ws(ws, zu, r->u, tmp, tbits, t->u);
    cc_require(status == CCERR_OK, errOut);

    ccz_set_n(r, ccn_n(n, r->u));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccz_expmod(ccz *r, const ccz *s, const ccz *t, const ccz *u)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZ_EXPMOD_WORKSPACE_N(ccz_n(u)));
    int rv = ccz_expmod_ws(ws, r, s, t, u);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
