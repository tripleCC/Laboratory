/* Copyright (c) (2010,2011,2014-2017,2019,2021) Apple Inc. All rights reserved.
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
#include "ccrsa_internal.h"

int ccrsa_pub_crypt_ws(cc_ws_t ws, ccrsa_pub_ctx_t ctx, cc_unit *r, const cc_unit *s)
{
    cc_size n = ccrsa_ctx_n(ctx);
    size_t ebitlen = ccn_bitlen(n, ccrsa_ctx_e(ctx));

    // Reject e<=1 and m<=1 as a valid key.
    if ((ebitlen <= 1) || ccn_is_zero_or_one(n, ccrsa_ctx_m(ctx))) {
        return CCRSA_KEY_ERROR;
    }

    // Proceed
    return cczp_mm_power_fast_ws(ws, ccrsa_ctx_zm(ctx), r, s, ccrsa_ctx_e(ctx));
}

int ccrsa_pub_crypt(ccrsa_pub_ctx_t ctx, cc_unit *r, const cc_unit *s)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_PUB_CRYPT_WORKSPACE_N(ccrsa_ctx_n(ctx)));
    int rv = ccrsa_pub_crypt_ws(ws, ctx, r, s);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
