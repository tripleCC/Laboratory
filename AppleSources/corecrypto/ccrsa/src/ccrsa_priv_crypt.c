/* Copyright (c) (2010-2012,2014-2016,2019,2021,2022) Apple Inc. All rights reserved.
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

int ccrsa_priv_crypt_ws(cc_ws_t ws, ccrsa_full_ctx_t key, cc_unit *out, const cc_unit *in)
{
    struct ccrng_state *rng = ccrng(NULL);
    if (!rng) {
        return CCERR_INTERNAL;
    }

    return ccrsa_priv_crypt_blinded_ws(ws, rng, key, out, in);
}

int ccrsa_priv_crypt(ccrsa_full_ctx_t key, cc_unit *out, const cc_unit *in)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_PRIV_CRYPT_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_priv_crypt_ws(ws, key, out, in);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
