/* Copyright (c) (2013-2015,2017-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>

int ccecdh_generate_key_ws(cc_ws_t ws, ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key)
{
    CC_DECL_BP_WS(ws, bp);

    int rv = ccec_generate_key_internal_fips_ws(ws, cp, rng, key);
    if (rv) {
        goto cleanup;
    }

    if (ccecdh_pairwise_consistency_check_ws(ws, key, NULL, rng)) {
        rv = CCEC_GENERATE_KEY_CONSISTENCY;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccecdh_generate_key(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCECDH_GENERATE_KEY_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccecdh_generate_key_ws(ws, cp, rng, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
