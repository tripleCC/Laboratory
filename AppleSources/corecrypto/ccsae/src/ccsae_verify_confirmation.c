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
static int ccsae_verify_confirmation_ws(cc_ws_t ws, ccsae_ctx_t ctx, const uint8_t *peer_send_confirm_counter, const uint8_t *peer_confirmation)
{
    CCSAE_EXPECT_STATES(COMMIT_BOTH, CONFIRMATION_GENERATED);

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    cc_assert(n == ccn_nof_size(tn));
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);

    cchmac_di_decl(di, hc);
    uint8_t myconfirm[MAX_DIGEST_OUTPUT_SIZE];

    CC_DECL_BP_WS(ws, bp);
    uint8_t *scratch = (uint8_t *)CC_ALLOC_WS(ws, n);

    /*
     The confirmation is an HMAC of the following with the key == KCK
         1. Peer Send Confirm Counter (2 bytes)
         2. Peer Commit Scalar (tn bytes)
         3. Peer Commit Element (2 * tn bytes)
         4. My Commit Scalar (tn bytes)
         5. My Commit Element (2 * tn bytes)
     */

    cchmac_init(di, hc, ccsae_sizeof_kck_internal(ctx), ccsae_ctx_KCK(ctx));

    cchmac_update(di, hc, 2, peer_send_confirm_counter);

    ccn_write_uint_padded(n, ccsae_ctx_peer_commitscalar(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_CE_x(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_peer_CE_y(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_commitscalar(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_CE_x(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    ccn_write_uint_padded(n, ccsae_ctx_CE_y(ctx), tn, scratch);
    cchmac_update(di, hc, tn, scratch);

    cchmac_final(di, hc, myconfirm);

    cchmac_di_clear(di, hc);
    CCSAE_ADD_STATE(CONFIRMATION_VERIFIED);

    CC_FREE_BP_WS(ws, bp);
    return cc_cmp_safe(di->output_size, myconfirm, peer_confirmation);
}

int ccsae_verify_confirmation(ccsae_ctx_t ctx, const uint8_t *peer_send_confirm_counter, const uint8_t *peer_confirmation)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_VERIFY_CONFIRMATION_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_verify_confirmation_ws(ws, ctx, peer_send_confirm_counter, peer_confirmation);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
