/* Copyright (c) (2020-2023) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "cc_macros.h"

static int ccec_blinding_op_ws(cc_ws_t ws,
                               struct ccrng_state *rng,
                               const cc_unit *scalar,
                               const ccec_pub_ctx_t pub,
                               ccec_pub_ctx_t pub_out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *P_p = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *P_b = CCEC_ALLOC_POINT_WS(ws, n);

    int result = ccec_validate_point_and_projectify_ws(ws, cp, P_p, (ccec_const_affine_point_t)ccec_ctx_point(pub), rng);
    if (result != CCERR_OK) {
        goto cleanup;
    }

    result = ccec_mult_blinded_ws(ws, cp, P_b, scalar, P_p, rng);
    if (result != CCERR_OK) {
        goto cleanup;
    }

    result = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(pub_out), P_b);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static int ccec_generate_blinding_keys_ws(cc_ws_t ws,
                                          ccec_const_cp_t cp,
                                          struct ccrng_state *rng,
                                          ccec_full_ctx_t blinding_key,
                                          ccec_full_ctx_t unblinding_key)
{
    ccec_ctx_init(cp, blinding_key);
    ccec_ctx_init(cp, unblinding_key);

    cc_size n = ccec_cp_n(cp);
    CC_DECL_BP_WS(ws, bp);

    ccec_pub_ctx_t P = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_projective_point *base = CCEC_ALLOC_POINT_WS(ws, n);

    int result = ccec_generate_scalar_fips_retry_ws(ws, cp, rng, ccec_ctx_k(blinding_key));
    cc_require(result == CCERR_OK, err);

    result = cczp_inv_ws(ws, ccec_cp_zq(cp), ccec_ctx_k(unblinding_key), ccec_ctx_k(blinding_key));
    cc_require(result == CCERR_OK, err);

    // Now to perform a consistency check
    // First we'll compute public keys from
    result = ccec_projectify_ws(ws, cp, base, ccec_cp_g(cp), rng);
    cc_require(result == CCERR_OK, err);

    result = ccec_mult_blinded_ws(ws, cp, ccec_ctx_point(blinding_key), ccec_ctx_k(blinding_key), base, rng);
    cc_require(result == CCERR_OK, err);
    result = ccec_mult_blinded_ws(ws, cp, ccec_ctx_point(unblinding_key), ccec_ctx_k(unblinding_key), base, rng);
    cc_require(result == CCERR_OK, err);
    result = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(blinding_key), ccec_ctx_point(blinding_key));
    cc_require(result == CCERR_OK, err);
    result = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(unblinding_key), ccec_ctx_point(unblinding_key));
    cc_require(result == CCERR_OK, err);

    // Blinding the "unblinded" public key will give us G
    result = ccec_blinding_op_ws(ws, rng, ccec_ctx_k(blinding_key), ccec_ctx_pub(unblinding_key), P);
    cc_require(result == CCERR_OK, err);
    cc_require(ccn_cmp(n, ccec_ctx_x(P), ccec_point_x(ccec_cp_g(cp), cp)) == 0, err);

    // Unblinding the "blinded" public key will also give us G
    result = ccec_blinding_op_ws(ws, rng, ccec_ctx_k(unblinding_key), ccec_ctx_pub(blinding_key), P);
    cc_require(result == CCERR_OK, err);
    cc_require(ccn_cmp(n, ccec_ctx_x(P), ccec_point_x(ccec_cp_g(cp), cp)) == 0, err);

err:
    if (result != CCERR_OK) {
        ccec_full_ctx_clear_cp(cp, blinding_key);
        ccec_full_ctx_clear_cp(cp, unblinding_key);
    }

    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_generate_blinding_keys(ccec_const_cp_t cp,
                                struct ccrng_state *rng,
                                ccec_full_ctx_t blinding_key,
                                ccec_full_ctx_t unblinding_key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_BLINDING_KEYS_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_generate_blinding_keys_ws(ws, cp, rng, blinding_key, unblinding_key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_blind(struct ccrng_state *rng,
               const ccec_full_ctx_t blinding_key,
               const ccec_pub_ctx_t pub,
               ccec_pub_ctx_t blinded_pub)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_BLINDING_OP_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_blinding_op_ws(ws, rng, ccec_ctx_k(blinding_key), pub, blinded_pub);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_unblind(struct ccrng_state *rng,
                 const ccec_full_ctx_t unblinding_key,
                 const ccec_pub_ctx_t pub,
                 ccec_pub_ctx_t unblinded_pub)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_BLINDING_OP_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_blinding_op_ws(ws, rng, ccec_ctx_k(unblinding_key), pub, unblinded_pub);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
