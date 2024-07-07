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
#include <corecrypto/ccspake.h>
#include "ccec_internal.h"
#include "ccspake_internal.h"

CC_NONNULL_ALL CC_WARN_RESULT
static int ccspake_lazy_gen_xy_XY_ws(cc_ws_t ws, ccspake_ctx_t ctx)
{
    struct ccrng_state *rng = ccspake_ctx_rng(ctx);
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    int rv;

    if (!ccn_is_zero(n, ccspake_ctx_xy(ctx))) {
        return CCERR_OK;
    }

    CC_DECL_BP_WS(ws, bp);

    ccec_pub_ctx_t pub = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, pub);

    ccec_projective_point *S = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *T = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *U = CCEC_ALLOC_POINT_WS(ws, n);

    cc_unit *xy = CC_ALLOC_WS(ws, n);

    // Generate a new scalar and store it.
    if ((rv = ccec_generate_scalar_fips_retry_ws(ws, cp, ccspake_ctx_rng(ctx), xy))) {
        goto cleanup;
    }

    // U = base point G
    if ((rv = ccec_projectify_ws(ws, cp, U, ccec_cp_g(cp), rng))) {
        goto cleanup;
    }

    // S = x * U (prover) or S = y * U (verifier)
    if ((rv = ccec_mult_blinded_ws(ws, cp, S, xy, U, rng))) {
        goto cleanup;
    }

    const cc_unit *MN = ccspake_ctx_is_prover(ctx) ?
        ccspake_ctx_scp(ctx)->m : ccspake_ctx_scp(ctx)->n;

    // U = "random element M/N".
    if ((rv = ccec_projectify_ws(ws, cp, U, (ccec_const_affine_point_t)MN, rng))) {
        goto cleanup;
    }

    // T = w0 * U
    if ((rv = ccec_mult_blinded_ws(ws, cp, T, ccspake_ctx_w0(ctx), U, rng))) {
        goto cleanup;
    }

    // X = S + T
    ccec_full_add_ws(ws, cp, ccec_ctx_point(pub), S, T);

    if ((rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(pub), ccec_ctx_point(pub)))) {
        goto cleanup;
    }

    ccspake_store_pub_key(pub, ccspake_ctx_XY(ctx));
    ccn_set(n, ccspake_ctx_xy(ctx), xy);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccspake_kex_generate(ccspake_ctx_t ctx, size_t x_len, uint8_t *x)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    size_t len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);
    int rv;

    CCSPAKE_EXPECT_STATES(INIT, KEX_PROCESS);

    if (x_len != 1 + len * 2) {
        return CCERR_PARAMETER;
    }

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_LAZY_GEN_XY_XY_WORKSPACE_N(n));

    // Generate (x, X) or (y, Y), if needed.
    if ((rv = ccspake_lazy_gen_xy_XY_ws(ws, ctx))) {
        goto cleanup;
    }

    // Write the public share.
    *x++ = CCSPAKE_X963_UNCOMPRESSED;
    ccn_write_uint_padded(n, ccspake_ctx_XY_x(ctx), len, x);
    ccn_write_uint_padded(n, ccspake_ctx_XY_y(ctx), len, x + len);

    CCSPAKE_ADD_STATE(KEX_GENERATE);

cleanup:
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccspake_kex_process_ws(cc_ws_t ws, ccspake_ctx_t ctx, size_t y_len, const uint8_t *y)
{
    ccspake_const_cp_t scp = ccspake_ctx_scp(ctx);
    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    cc_size n = ccec_cp_n(cp);
    int rv;

    if (y_len != ccspake_sizeof_point(scp)) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    ccec_pub_ctx_t Q_pub = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, Q_pub);

    ccec_projective_point *U = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *Q = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *S = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *T = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *Z = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *V = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *L = CCEC_ALLOC_POINT_WS(ws, n);

    struct ccrng_state *rng = ccspake_ctx_rng(ctx);

    CCSPAKE_EXPECT_STATES(INIT, KEX_GENERATE);

    // Import and verify our peer's share.
    if ((rv = ccspake_import_pub_ws(ws, Q_pub, y_len, y))) {
        goto cleanup;
    }

    // Generate (x, X) or (y, Y), if needed.
    if ((rv = ccspake_lazy_gen_xy_XY_ws(ws, ctx))) {
        goto cleanup;
    }

    // The peer's share must not be the same as ours.
    if (ccspake_cmp_pub_key(Q_pub, ccspake_ctx_XY(ctx)) == 0) {
        rv = CCERR_PARAMETER;
        goto cleanup;
    }

    if ((rv = ccec_projectify_ws(ws, cp, Q, (ccec_const_affine_point_t)ccec_ctx_point(Q_pub), rng))) {
        goto cleanup;
    }

    const cc_unit *MN = ccspake_ctx_is_prover(ctx) ?
        ccspake_ctx_scp(ctx)->n : ccspake_ctx_scp(ctx)->m;

    // Import the "random element M/N".
    if ((rv = ccec_projectify_ws(ws, cp, U, (ccec_const_affine_point_t)MN, rng))) {
        goto cleanup;
    }

    // S = w0 * M (prover) or S = w0 * N (verifier)
    if ((rv = ccec_mult_blinded_ws(ws, cp, S, ccspake_ctx_w0(ctx), U, rng))) {
        goto cleanup;
    }

    // T = Q - S
    ccec_full_sub_ws(ws, cp, T, Q, S);

    // Z = x * T (prover) or Z = y * T (verifier)
    if ((rv = ccec_mult_blinded_ws(ws, cp, Z, ccspake_ctx_xy(ctx), T, rng))) {
        goto cleanup;
    }

    if (ccspake_ctx_is_prover(ctx)) {
        // V = w1 * T
        if ((rv = ccec_mult_blinded_ws(ws, cp, V, ccspake_ctx_w1(ctx), T, rng))) {
            goto cleanup;
        }
    } else {
        if ((rv = ccec_validate_point_and_projectify_ws(ws, cp, L, (ccec_const_affine_point_t)ccspake_ctx_L(ctx), rng))) {
            goto cleanup;
        }

        // V = y * L
        if ((rv = ccec_mult_blinded_ws(ws, cp, V, ccspake_ctx_xy(ctx), L, rng))) {
            goto cleanup;
        }
    }

    // Get affine coordinates.
    if ((rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)Z, Z))) {
        goto cleanup;
    }
    if ((rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)V, V))) {
        goto cleanup;
    }

    // Save Q.
    ccspake_store_pub_key(Q_pub, ccspake_ctx_Q(ctx));

    // TT += len(X) || X || len(Y) || Y
    if (ccspake_ctx_is_prover(ctx)) {
        ccspake_transcript_append_point(ctx, cp, ccspake_ctx_XY_x(ctx), ccspake_ctx_XY_y(ctx));
        ccspake_transcript_append_point(ctx, cp, ccspake_ctx_Q_x(ctx), ccspake_ctx_Q_y(ctx));
    } else {
        ccspake_transcript_append_point(ctx, cp, ccspake_ctx_Q_x(ctx), ccspake_ctx_Q_y(ctx));
        ccspake_transcript_append_point(ctx, cp, ccspake_ctx_XY_x(ctx), ccspake_ctx_XY_y(ctx));
    }

    // TT += len(Z) || Z || len(V) || V
    ccspake_transcript_append_point(ctx, cp, ccec_point_x(Z, cp), ccec_point_y(Z, cp));
    ccspake_transcript_append_point(ctx, cp, ccec_point_x(V, cp), ccec_point_y(V, cp));

    // TT += len(w0) || w0.
    ccspake_transcript_append_scalar(ctx, cp, ccspake_ctx_w0(ctx));

    // K_main = Hash(TT)
    ccspake_transcript_finish(ctx, ccspake_ctx_main_key(ctx));

    CCSPAKE_ADD_STATE(KEX_PROCESS);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccspake_kex_process(ccspake_ctx_t ctx, size_t y_len, const uint8_t *y)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_KEX_PROCESS_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccspake_kex_process_ws(ws, ctx, y_len, y);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
