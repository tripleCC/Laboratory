/* Copyright (c) (2011,2012,2014-2017,2019,2021-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng.h>
#include "ccec_internal.h"
#include "cc_memory.h"

#include "fipspost_trace.h"

static const uint8_t FAKE_DIGEST[CCSHA256_OUTPUT_SIZE] = {
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa
};

int ccec_pairwise_consistency_check_ws(cc_ws_t ws, ccec_full_ctx_t full_key, struct ccrng_state *rng)
{
    FIPSPOST_TRACE_EVENT;

    ccec_const_cp_t cp = ccec_ctx_cp(full_key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    int rv = ccec_sign_internal_ws(ws, full_key, sizeof(FAKE_DIGEST), FAKE_DIGEST, r, s, rng);
    cc_require(rv == CCERR_OK, errOut);

    cc_fault_canary_t canary;
    rv = ccec_verify_internal_ws(ws, ccec_ctx_pub(full_key), sizeof(FAKE_DIGEST), FAKE_DIGEST, r, s, canary);
    cc_require(rv == CCERR_OK && CC_FAULT_CANARY_EQUAL(CCEC_FAULT_CANARY, canary), errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

bool ccec_pairwise_consistency_check(ccec_full_ctx_t full_key, struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(full_key);

    int rv;
    CC_DECL_WORKSPACE_RV(ws, CCEC_PAIRWISE_CONSISTENCY_CHECK_WORKSPACE_N(ccec_cp_n(cp)), rv);
    if (rv != CCERR_OK) {
        return false;
    }

    rv = ccec_pairwise_consistency_check_ws(ws, full_key, rng);
    CC_FREE_WORKSPACE(ws);
    return rv == CCERR_OK;
}

int ccec_compact_generate_key_checksign_ws(cc_ws_t ws, struct ccrng_state *rng, ccec_generate_key_ctx_t key)
{
    cc_require_or_return(ccec_generate_key_ctx_state(key) == CCEC_GENERATE_KEY_SIGN, CCERR_CALL_SEQUENCE);

    int rv = ccec_sign_internal_ws(ws, ccec_generate_key_ctx_fk(key), sizeof(FAKE_DIGEST), FAKE_DIGEST, ccec_generate_key_ctx_r(key), ccec_generate_key_ctx_s(key), rng);
    cc_require_or_return(rv == CCERR_OK, rv);

    ccec_generate_key_ctx_state(key) = CCEC_GENERATE_KEY_VERIFY;
    return CCERR_OK;
}

int ccec_compact_generate_key_checkverify_and_extract_ws(cc_ws_t ws, ccec_generate_key_ctx_t key, ccec_full_ctx_t *fkey)
{
    *fkey = NULL;
    cc_require_or_return(ccec_generate_key_ctx_state(key) == CCEC_GENERATE_KEY_VERIFY, CCERR_CALL_SEQUENCE);

    cc_fault_canary_t canary;
    int rv = ccec_verify_internal_ws(ws, ccec_ctx_pub(ccec_generate_key_ctx_fk(key)), sizeof(FAKE_DIGEST), FAKE_DIGEST, ccec_generate_key_ctx_r(key), ccec_generate_key_ctx_s(key), canary);
    cc_require_or_return(rv == CCERR_OK && CC_FAULT_CANARY_EQUAL(CCEC_FAULT_CANARY, canary), rv);

    ccec_generate_key_ctx_state(key) = CCEC_GENERATE_KEY_COMPLETE;
    *fkey = ccec_generate_key_ctx_fk(key);
    return CCERR_OK;
}
