/* Copyright (c) (2018-2023) Apple Inc. All rights reserved.
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
#include "ccsae_priv.h"
#include "ccsae_internal.h"
#include "cc_workspaces.h"
#include <corecrypto/cchmac.h>

CC_NONNULL_ALL CC_WARN_RESULT
static int ccsae_generate_confirmation_ws(cc_ws_t ws, ccsae_ctx_t ctx, const uint8_t *send_confirm_counter, uint8_t *confirmation)
{
    CCSAE_EXPECT_STATES(COMMIT_BOTH, CONFIRMATION_VERIFIED);

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);

    cchmac_di_decl(di, hc);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *scratch = (uint8_t *)CC_ALLOC_WS(ws, n);

    /*
     The confirmation is an HMAC of the following with the key == KCK
        1. My Send Confirm Counter (2 bytes)
        2. My Commit Scalar (tn bytes)
        3. My Commit Element (2 * tn bytes)
        4. Peer Commit Scalar (tn bytes)
        5. Peer Commit Element (2 * tn bytes)
     */

    cchmac_init(di, hc, ccsae_sizeof_kck_internal(ctx), ccsae_ctx_KCK(ctx));

    cchmac_update(di, hc, 2, send_confirm_counter);

    ccn_write_uint_padded(n, ccsae_ctx_commitscalar(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_CE_x(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_CE_y(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_commitscalar(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_CE_x(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_CE_y(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    cchmac_final(di, hc, confirmation);

    cchmac_di_clear(di, hc);
    CCSAE_ADD_STATE(CONFIRMATION_GENERATED);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int ccsae_generate_confirmation(ccsae_ctx_t ctx, const uint8_t *send_confirm_counter, uint8_t *confirmation)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_GENERATE_CONFIRMATION_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_generate_confirmation_ws(ws, ctx, send_confirm_counter, confirmation);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
