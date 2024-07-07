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
#include <corecrypto/cchmac.h>
#include "ccsae.h"
#include "cc_macros.h"
#include "ccsae_priv.h"
#include "ccec_internal.h"
#include "ccsae_internal.h"

CC_NONNULL_ALL
static void ccsae_generate_keyseed_ws(cc_ws_t ws, ccec_const_cp_t cp, const struct ccdigest_info *di, const struct ccec_projective_point *P, uint8_t *keyseed)
{
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    cc_assert(n == ccn_nof_size(tn));

    uint8_t zeros[32] = { 0 };

    CC_DECL_BP_WS(ws, bp);
    uint8_t *x_coord = (uint8_t *)CC_ALLOC_WS(ws, n);

    ccn_write_uint_padded(n, ccec_point_x(P, cp), tn, x_coord);

    cchmac_di_decl(di, hc);
    cchmac_init(di, hc, 32, zeros);
    cchmac_update(di, hc, tn, x_coord);
    cchmac_final(di, hc, keyseed);

    cchmac_di_clear(di, hc);
    CC_FREE_BP_WS(ws, bp);
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccsae_verify_commitment_ws(cc_ws_t ws, ccsae_ctx_t ctx, const uint8_t *peer_commitment)
{
    CCSAE_EXPECT_STATE(COMMIT_GENERATED);

    struct ccrng_state *rng = ccsae_ctx_rng(ctx);
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    cc_assert(n == ccn_nof_size(tn));

    int result = CCERR_PARAMETER;
    uint8_t keyseed[MAX_DIGEST_OUTPUT_SIZE];

    CC_DECL_BP_WS(ws, bp);
    cc_unit *context = CC_ALLOC_WS(ws, n);

    ccec_projective_point *PWE = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *PEER_CE = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *I1 = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *I2 = CCEC_ALLOC_POINT_WS(ws, n);

    ccn_read_uint(n, ccsae_ctx_peer_commitscalar(ctx), tn, peer_commitment);
    ccn_read_uint(n, ccsae_ctx_peer_CE_x(ctx), tn, peer_commitment + tn);
    ccn_read_uint(n, ccsae_ctx_peer_CE_y(ctx), tn, peer_commitment + tn + tn);

    // [WPA3] 12.4.5.4: 1 < scalar < order(cp), peer scalar / element != my scalar / element
    cc_require(!ccn_is_one(n, ccsae_ctx_peer_commitscalar(ctx)), cleanup);
    result = ccec_validate_scalar(cp, ccsae_ctx_peer_commitscalar(ctx));
    cc_require(result == CCERR_OK, cleanup);

    result = CCERR_PARAMETER;
    cc_require(ccn_cmp(n, ccsae_ctx_peer_commitscalar(ctx), ccsae_ctx_commitscalar(ctx)) != 0, cleanup);
    cc_require(ccn_cmp(n, ccsae_ctx_peer_CE_x(ctx), ccsae_ctx_CE_x(ctx)) != 0, cleanup);
    cc_require(ccn_cmp(n, ccsae_ctx_peer_CE_y(ctx), ccsae_ctx_CE_y(ctx)) != 0, cleanup);

    // [WPA3] 12.4.5.4: Point validation
    result = ccec_validate_point_and_projectify_ws(ws, cp, PEER_CE, (ccec_const_affine_point_t)ccsae_ctx_peer_CE(ctx), rng);
    cc_require(result == CCERR_OK, cleanup);

    /*
     * ccsae_ctx_PWE is the same point we found in the generate commitment step
     * so we can simply call ccec_projectify
     */
    result = ccec_projectify_ws(ws, cp, PWE, (ccec_const_affine_point_t)ccsae_ctx_PWE(ctx), rng);
    cc_require(result == CCERR_OK, cleanup);

    // [WPA3] 12.4.5.4: I1 = peer_scalar * PWE
    result = ccec_mult_blinded_ws(ws, cp, I1, ccsae_ctx_peer_commitscalar(ctx), PWE, rng);
    cc_require(result == CCERR_OK, cleanup);

    // [WPA3] 12.4.5.4: PWE = I1 + PEER_CE
    ccec_full_add_ws(ws, cp, PWE, I1, PEER_CE);

    // [WPA3] 12.4.5.4: I2 = rand * PWE
    result = ccec_mult_blinded_ws(ws, cp, I2, ccsae_ctx_rand(ctx), PWE, rng);
    cc_require(result == CCERR_OK, cleanup);

    // [WPA3] 12.4.5.4: Generate the keyseed
    result = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)I2, I2);
    cc_require(result == CCERR_OK, cleanup);

    ccsae_generate_keyseed_ws(ws, cp, di, I2, keyseed);

    // [WPA3] 12.4.5.4: Generate KCK, PMK
    cczp_add_ws(ws, zq, context, ccsae_ctx_commitscalar(ctx), ccsae_ctx_peer_commitscalar(ctx));
    result = ccsae_gen_keys_ws(ws, ctx, keyseed, context);
    cc_require(result == CCERR_OK, cleanup);

    CCSAE_ADD_STATE(COMMIT_VERIFIED);

cleanup:
    cc_clear(di->output_size, keyseed);
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccsae_verify_commitment(ccsae_ctx_t ctx, const uint8_t *peer_commitment)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_VERIFY_COMMITMENT_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_verify_commitment_ws(ws, ctx, peer_commitment);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
