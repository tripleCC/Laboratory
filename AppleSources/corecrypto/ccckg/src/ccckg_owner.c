/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"

CC_NONNULL_ALL CC_WARN_RESULT
static int ccckg_owner_generate_share_ws(cc_ws_t ws,
                                         ccckg_ctx_t ctx,
                                         size_t commitment_nbytes,
                                         const uint8_t *commitment,
                                         size_t share_nbytes,
                                         uint8_t *share)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    int rv = CCERR_PARAMETER;

    CCCKG_EXPECT_STATE(INIT);

    CC_DECL_BP_WS(ws, bp);
    ccec_full_ctx_t S = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, S);

    cc_require_action(commitment_nbytes == ccckg_sizeof_commitment(cp, di), cleanup, rv = CCERR_PARAMETER);
    cc_require_action(share_nbytes == ccckg_sizeof_share(cp, di), cleanup, rv = CCERR_PARAMETER);

    // Store the contributor's commitment.
    cc_memcpy(ccckg_ctx_c(ctx), commitment, commitment_nbytes);

    // Generate a new key share.
    rv = ccec_generate_key_fips_ws(ws, cp, ccckg_ctx_rng(ctx), S);
    cc_require(rv == CCERR_OK, cleanup);

    // Generate a nonce.
    rv = ccrng_generate(ccckg_ctx_rng(ctx), di->output_size, ccckg_ctx_r(ctx));
    cc_require(rv == CCERR_OK, cleanup);

    // Store our key share's scalar.
    ccn_set(n, ccckg_ctx_s(ctx), ccec_ctx_k(S));

    // Assemble the share.
    rv = ccec_export_pub(ccec_ctx_pub(S), share);
    cc_require(rv == CCERR_OK, cleanup);

    cc_memcpy(share + ccec_export_pub_size(ccec_ctx_pub(S)), ccckg_ctx_r(ctx), di->output_size);

    CCCKG_SET_STATE(SHARE);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccckg_owner_generate_share(ccckg_ctx_t ctx,
                               size_t commitment_nbytes,
                               const uint8_t *commitment,
                               size_t share_nbytes,
                               uint8_t *share)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCKG_OWNER_GENERATE_SHARE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccckg_owner_generate_share_ws(ws, ctx, commitment_nbytes, commitment, share_nbytes, share);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccckg_owner_finish(ccckg_ctx_t ctx, size_t opening_nbytes, const uint8_t *opening, ccec_full_ctx_t P, size_t sk_nbytes, uint8_t *sk)
{
    CC_ENSURE_DIT_ENABLED

    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    int rv;

    CCCKG_EXPECT_STATE(SHARE);

    cc_require_or_return(ccec_ctx_cp(P) == cp, CCERR_PARAMETER);
    cc_require_or_return(opening_nbytes == ccckg_sizeof_opening(cp, di), CCERR_PARAMETER);

    uint8_t buf[CCCKG_HASH_MAX_NBYTES];
    ccdigest(di, opening_nbytes, opening, buf);

    // Check the commitment.
    if (cc_cmp_safe(di->output_size, buf, ccckg_ctx_c(ctx))) {
        rv = CCERR_INTEGRITY;
        goto cleanup;
    }

    ccn_read_uint(n, ccec_ctx_k(P), ccec_cp_order_size(cp), opening);

    // Check the contributor's scalar.
    if (ccec_validate_scalar(cp, ccec_ctx_k(P))) {
        rv = CCERR_PARAMETER;
        goto cleanup;
    }

    // Add our scalar to the contributor's.
    rv = cczp_add(ccec_cp_zq(cp), ccec_ctx_k(P), ccec_ctx_k(P), ccckg_ctx_s(ctx));
    cc_require(rv == CCERR_OK, cleanup);

    rv = ccec_make_pub_from_priv(cp, ccckg_ctx_rng(ctx), ccec_ctx_k(P), NULL, ccec_ctx_pub(P));
    cc_require(rv == CCERR_OK, cleanup);

    const uint8_t *r1 = (const uint8_t *)opening + ccec_cp_order_size(cp);
    const uint8_t *r2 = (const uint8_t *)ccckg_ctx_r(ctx);

    // Derive SK.
    rv = ccckg_derive_sk(ctx, ccec_ctx_x(P), r1, r2, sk_nbytes, sk);
    cc_require(rv == CCERR_OK, cleanup);

    CCCKG_SET_STATE(FINISH);

cleanup:
    cc_clear(sizeof(buf), buf);

    return rv;
}
