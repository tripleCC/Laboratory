/* Copyright (c) (2014-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include "ccec_internal.h"
#include "cc_macros.h"

void ccec_compact_transform_key_ws(cc_ws_t ws, ccec_full_ctx_t key)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);

    // Compute y from a given x intented to be on the curve
    // x can be a pointer to ccec_point_x(r, cp)
    cc_size n = ccec_cp_n(cp);

    cc_unit *k = ccec_ctx_k(key);
    cc_unit *y = ccec_ctx_y(key);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    // https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
    // Convention for y = min(y',p-y'), divide key space by 2 (1 security bit)
    cczp_negate(ccec_cp_zp(cp), t, y);

    // Adjust key to match convention
    if (ccn_cmp(n, t, y) < 0) {
        ccn_set(n, y, t);
        ccn_sub_ws(ws, n, k, cczp_prime(ccec_cp_zq(cp)), k);
    }

    CC_FREE_BP_WS(ws, bp);
}

int ccec_compact_transform_key(ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_COMPACT_TRANSFORM_KEY_WORKSPACE_N(ccec_cp_n(cp)));
    ccec_compact_transform_key_ws(ws, key);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccec_compact_generate_key_ws(cc_ws_t ws,
                                        ccec_const_cp_t cp,
                                        struct ccrng_state *rng,
                                        ccec_full_ctx_t key)
{
    CC_DECL_BP_WS(ws, bp);

    int rv = ccec_generate_key_internal_fips_ws(ws, cp, rng, key);
    cc_require(rv == CCERR_OK, errOut);

    ccec_compact_transform_key_ws(ws, key);

    if (ccec_pairwise_consistency_check_ws(ws, key, rng)) {
        rv = CCEC_GENERATE_KEY_CONSISTENCY;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_compact_generate_key(ccec_const_cp_t cp,
                              struct ccrng_state *rng,
                              ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_COMPACT_GENERATE_KEY_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_compact_generate_key_ws(ws, cp, rng, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_compact_generate_key_init(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_generate_key_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_KEY_INTERNAL_FIPS_WORKSPACE_N(ccec_cp_n(cp)));
    
    ccec_generate_key_ctx_state(key) = CCEC_GENERATE_KEY_START;
    ccec_generate_key_ctx_n(key) = ccec_cp_n(cp);
    ccec_ctx_init(cp, ccec_generate_key_ctx_fk(key));
    
    int rv = ccec_generate_key_internal_fips_ws(ws, cp, rng, ccec_generate_key_ctx_fk(key));
    cc_require(rv == CCERR_OK, errOut);
    
    ccec_generate_key_ctx_state(key) = CCEC_GENERATE_KEY_COMPACT_TRANSFORM;
errOut:
    CC_FREE_WORKSPACE(ws);
    return rv;
}

static int ccec_compact_generate_key_step_ws(cc_ws_t ws, struct ccrng_state *rng, ccec_generate_key_ctx_t key, ccec_full_ctx_t *fullkey)
{
    *fullkey = NULL;
        
    switch (ccec_generate_key_ctx_state(key))
    {
        case CCEC_GENERATE_KEY_COMPACT_TRANSFORM:
            ccec_compact_transform_key_ws(ws, ccec_generate_key_ctx_fk(key));
            ccec_generate_key_ctx_state(key) = CCEC_GENERATE_KEY_SIGN;
            return CCERR_OK;
        case CCEC_GENERATE_KEY_SIGN:
            return ccec_compact_generate_key_checksign_ws(ws, rng, key);
        case CCEC_GENERATE_KEY_VERIFY:
            return ccec_compact_generate_key_checkverify_and_extract_ws(ws, key, fullkey);
        default:
            return CCERR_PARAMETER;
    }
}

int ccec_compact_generate_key_step(struct ccrng_state *rng, ccec_generate_key_ctx_t key, ccec_full_ctx_t *fullkey)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_COMPACT_GENERATE_KEY_STEP_WORKSPACE_N(ccec_generate_key_ctx_n(key)));
    int rv = ccec_compact_generate_key_step_ws(ws, rng, key, fullkey);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
