/* Copyright (c) (2019-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccckg.h>

#include "ccec_internal.h"
#include "ccckg_internal.h"

int ccckg_contributor_commit(ccckg_ctx_t ctx, size_t commitment_len, uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    ccdigest_di_decl(di, dc);
    int rv;

    CCCKG_EXPECT_STATE(INIT);

    if (commitment_len != ccckg_sizeof_commitment(cp, di)) {
        return CCERR_PARAMETER;
    }

    // Generate a new scalar and store it.
    if ((rv = ccec_generate_scalar_fips_retry(cp, ccckg_ctx_rng(ctx), ccckg_ctx_s(ctx)))) {
        goto cleanup;
    }

    // Generate a nonce r.
    if ((rv = ccrng_generate(ccckg_ctx_rng(ctx), di->output_size, ccckg_ctx_r(ctx)))) {
        goto cleanup;
    }

    // Write the commitment.
    uint8_t buf[CCCKG_CURVE_MAX_NBYTES];
    ccn_write_uint_padded(n, ccckg_ctx_s(ctx), ccec_cp_order_size(cp), buf);

    ccdigest_init(di, dc);
    ccdigest_update(di, dc, ccec_cp_order_size(cp), buf);
    ccdigest_update(di, dc, di->output_size, ccckg_ctx_r(ctx));
    ccdigest_final(di, dc, commitment);
    ccdigest_di_clear(di, dc);

    CCCKG_SET_STATE(COMMIT);

cleanup:
    cc_clear(sizeof(buf), buf);

    return rv;
}

static int ccckg_contributor_finish_ws(cc_ws_t ws,
                                       ccckg_ctx_t ctx,
                                       size_t share_len,
                                       const uint8_t *share,
                                       size_t opening_len,
                                       uint8_t *opening,
                                       ccec_pub_ctx_t P,
                                       size_t sk_len,
                                       uint8_t *sk)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    struct ccrng_state *rng = ccckg_ctx_rng(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *X = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *Y = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *G = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *Q = CCEC_ALLOC_POINT_WS(ws, n);

    ccec_pub_ctx_t pub = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, pub);
    int rv;

    CCCKG_EXPECT_STATE(COMMIT);

    if (ccec_ctx_cp(P) != cp) {
        return CCERR_PARAMETER;
    }

    if (share_len != ccckg_sizeof_share(cp, di)) {
        return CCERR_PARAMETER;
    }

    if (opening_len != ccckg_sizeof_opening(cp, di)) {
        return CCERR_PARAMETER;
    }

    if (share[0] != 0x04) {
        return CCERR_PARAMETER;
    }

    if ((rv = ccec_raw_import_pub(cp, ccec_export_pub_size(pub) - 1, share + 1, pub))) {
        goto cleanup;
    }

    if ((rv = ccec_validate_point_and_projectify_ws(ws, cp, X, (ccec_const_affine_point_t)ccec_ctx_point(pub), rng))) {
        goto cleanup;
    }

    if ((rv = ccec_projectify_ws(ws, cp, G, ccec_cp_g(cp), rng))) {
        goto cleanup;
    }

    // Y = s * G
    if ((rv = ccec_mult_blinded_ws(ws, cp, Y, ccckg_ctx_s(ctx), G, rng))) {
        goto cleanup;
    }

    // Q = X + Y
    ccec_full_add_ws(ws, cp, Q, X, Y);

    // Export Q.
    if ((rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(P), Q))) {
        goto cleanup;
    }

    const uint8_t *r1 = (const uint8_t *)ccckg_ctx_r(ctx);
    const uint8_t *r2 = (const uint8_t *)share + ccec_export_pub_size(pub);

    // Derive SK.
    if ((rv = ccckg_derive_sk(ctx, ccec_ctx_x(P), r1, r2, sk_len, sk))) {
        goto cleanup;
    }

    // Open the commitment.
    ccn_write_uint_padded(n, ccckg_ctx_s(ctx), ccec_cp_order_size(cp), opening);
    cc_memcpy(opening + ccec_cp_order_size(cp), ccckg_ctx_r(ctx), di->output_size);

    CCCKG_SET_STATE(FINISH);

cleanup:
    ccec_pub_ctx_clear_cp(cp, pub);
    CC_FREE_BP_WS(ws, bp);

    return rv;
}

int ccckg_contributor_finish(ccckg_ctx_t ctx,
                             size_t share_len,
                             const uint8_t *share,
                             size_t opening_len,
                             uint8_t *opening,
                             ccec_pub_ctx_t P,
                             size_t sk_len,
                             uint8_t *sk)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCKG_CONTRIBUTOR_FINISH_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccckg_contributor_finish_ws(ws, ctx, share_len, share, opening_len, opening, P, sk_len, sk);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
