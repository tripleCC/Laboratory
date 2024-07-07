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
#include "cc_macros.h"
#include "ccsae_priv.h"
#include "ccsae_internal.h"
#include "ccec_internal.h"
#include <corecrypto/cchmac.h>

CC_WARN_RESULT
static int ccsae_generate_commitment_shared_ws(cc_ws_t ws,
                                               ccsae_ctx_t ctx,
                                               ccec_const_projective_point_t PWE_projective,
                                               uint8_t *commitment)
{
    int error = CCERR_PARAMETER;

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    struct ccrng_state *rng = ccsae_ctx_rng(ctx);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *s_mask = CC_ALLOC_WS(ws, n);

    // [WPA3] 12.4.5.2: Generate rand & mask
    cc_require(ccec_generate_scalar_fips_retry_ws(ws, cp, rng, ccsae_ctx_rand(ctx)) == CCERR_OK, out);
    cc_require(ccec_generate_scalar_fips_retry_ws(ws, cp, rng, s_mask) == CCERR_OK, out);

    // CE = mask * PWE
    cc_require(ccec_mult_blinded_ws(
                   ws, cp, (ccec_projective_point_t)ccsae_ctx_CE(ctx), s_mask, PWE_projective, rng) == CCERR_OK,
               out);

    cc_require(ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccsae_ctx_CE(ctx), (ccec_projective_point_t)ccsae_ctx_CE(ctx)) ==
                   CCERR_OK,
               out);

    // CE = -CE
    cczp_negate(ccec_cp_zp(cp), ccsae_ctx_CE_y(ctx), ccsae_ctx_CE_y(ctx));

    // [WPA3] 12.4.5.3: Generate the Commit Scalar
    cczp_add_ws(ws, (cczp_const_t)ccec_cp_zq(cp), ccsae_ctx_commitscalar(ctx), ccsae_ctx_rand(ctx), s_mask);
    cc_require(!ccn_is_zero_or_one(n, ccsae_ctx_commitscalar(ctx)), out);

    cc_require(ccn_write_uint_padded_ct(n, ccsae_ctx_commitscalar(ctx), tn, commitment) >= 0, out);
    cc_require(ccn_write_uint_padded_ct(n, ccsae_ctx_CE_x(ctx), tn, commitment + tn) >= 0, out);
    cc_require(ccn_write_uint_padded_ct(n, ccsae_ctx_CE_y(ctx), tn, commitment + 2 * tn) >= 0, out);

    error = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccsae_ctx_PWE(ctx), PWE_projective);
    cc_require(error == CCERR_OK, out);

out:
    CC_FREE_BP_WS(ws, bp);
    return error;
}

int ccsae_generate_commitment_init(ccsae_ctx_t ctx)
{
    CC_ENSURE_DIT_ENABLED

    CCSAE_EXPECT_STATE(INIT);

    ccsae_ctx_current_loop_iteration(ctx) = 1; // Hunting and pecking always starts with the counter = 1
    ccsae_ctx_found_qr(ctx) = ccsae_ctx_temp_lsb(ctx) = 0;

    CCSAE_ADD_STATE(COMMIT_INIT);
    return CCERR_OK;
}

CC_WARN_RESULT
static int ccsae_generate_commitment_partial_ws(cc_ws_t ws,
                                                ccsae_ctx_t ctx,
                                                const uint8_t *A,
                                                size_t A_nbytes,
                                                const uint8_t *B,
                                                size_t B_nbytes,
                                                const uint8_t *password,
                                                size_t password_nbytes,
                                                const uint8_t *identifier,
                                                size_t identifier_nbytes,
                                                uint8_t max_num_iterations)
{
    CCSAE_EXPECT_STATES(COMMIT_UPDATE, COMMIT_INIT);
    if (max_num_iterations == 0) {
        return CCERR_PARAMETER;
    }

    if (A_nbytes > CCSAE_MAX_IDENTITY_SIZE || B_nbytes > CCSAE_MAX_IDENTITY_SIZE) {
        return CCERR_PARAMETER;
    }

    if (password_nbytes > CCSAE_MAX_PASSWORD_IDENTIFIER_SIZE || identifier_nbytes > CCSAE_MAX_PASSWORD_IDENTIFIER_SIZE) {
        return CCERR_PARAMETER;
    }

    // The current loop iteration starts at 1 so subtract to get the number of iterations we have performed
    uint8_t loop_iterations_complete = ccsae_ctx_current_loop_iteration(ctx) - 1;
    if (loop_iterations_complete == ccsae_ctx_max_loop_iterations(ctx)) {
        return CCERR_OK;
    }

    uint8_t actual_iterations =
        (uint8_t)CC_MIN_EVAL(max_num_iterations, ccsae_ctx_max_loop_iterations(ctx) - loop_iterations_complete);

    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    uint8_t LSB = ccsae_ctx_temp_lsb(ctx);
    uint8_t found_qr = ccsae_ctx_found_qr(ctx);

    size_t keySize = A_nbytes + B_nbytes;
    uint8_t key[2 * CCSAE_MAX_IDENTITY_SIZE];

    ccsae_lexographic_order_key(A, A_nbytes, B, B_nbytes, key);

    CC_DECL_BP_WS(ws, bp);

    // Initialize per-iteration HMAC.
    cchmac_di_decl(di, hc);
    cchmac_init(di, hc, keySize, key);
    cchmac_update(di, hc, password_nbytes, password);
    if (identifier != NULL) {
        cchmac_update(di, hc, identifier_nbytes, identifier);
    }

    // Save initial, per-iteration HMAC state.
    cchmac_di_decl(di, state);
    cc_memcpy(state, hc, cchmac_di_size(di));

    for (uint8_t counter = 0; counter < actual_iterations; counter++) {
        uint8_t actual_counter = ccsae_ctx_current_loop_iteration(ctx) + counter;

        // Compute next seed and value.
        cc_memcpy(hc, state, cchmac_di_size(di));
        cchmac_update(di, hc, 1, &actual_counter);
        cchmac_final(di, hc, ccsae_ctx_S_PWD_SEED(ctx));
        ccsae_gen_password_value_ws(ws, ctx, ccsae_ctx_S_PWD_SEED(ctx), ccsae_ctx_S_PWD_VALUE(ctx));

        ccn_mux(n, found_qr, ccsae_ctx_PWE_x(ctx), ccsae_ctx_PWE_x(ctx), ccsae_ctx_S_PWD_VALUE(ctx));
        CC_MUXU(LSB, found_qr, LSB, ccsae_ctx_S_PWD_SEED_LSB(ctx, di) & 1);
        found_qr |= ccsae_y2_from_x_ws(ws, cp, ccsae_ctx_PWE_y(ctx), ccsae_ctx_PWE_x(ctx));
    }

    ccsae_ctx_temp_lsb(ctx) = LSB;
    ccsae_ctx_found_qr(ctx) = found_qr;
    ccsae_ctx_current_loop_iteration(ctx) += actual_iterations;

    CCSAE_ADD_STATE(COMMIT_UPDATE);

    CC_FREE_BP_WS(ws, bp);

    if (ccsae_ctx_current_loop_iteration(ctx) - 1 == ccsae_ctx_max_loop_iterations(ctx)) {
        return CCERR_OK;
    }

    return CCSAE_GENERATE_COMMIT_CALL_AGAIN;
}

int ccsae_generate_commitment_partial(ccsae_ctx_t ctx,
                                      const uint8_t *A,
                                      size_t A_nbytes,
                                      const uint8_t *B,
                                      size_t B_nbytes,
                                      const uint8_t *password,
                                      size_t password_nbytes,
                                      const uint8_t *identifier,
                                      size_t identifier_nbytes,
                                      uint8_t max_num_iterations)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_GENERATE_COMMITMENT_PARTIAL_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_generate_commitment_partial_ws(
        ws, ctx, A, A_nbytes, B, B_nbytes, password, password_nbytes, identifier, identifier_nbytes, max_num_iterations);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_WARN_RESULT
static int ccsae_generate_commitment_finalize_ws(cc_ws_t ws, ccsae_ctx_t ctx, uint8_t *commitment)
{
    CCSAE_EXPECT_STATE(COMMIT_UPDATE);

    struct ccrng_state *rng = ccsae_ctx_rng(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    bool LSB = ccsae_ctx_temp_lsb(ctx) & 1;
    cczp_const_decl(zp, ccec_cp_zp(cp));

    if (ccsae_ctx_current_loop_iteration(ctx) - 1 < ccsae_ctx_max_loop_iterations(ctx)) {
        return CCSAE_NOT_ENOUGH_COMMIT_PARTIAL_CALLS;
    }

    if (!ccsae_ctx_found_qr(ctx)) {
        return CCSAE_HUNTPECK_EXCEEDED_MAX_TRIALS;
    }

    CC_DECL_BP_WS(ws, bp);
    ccec_projective_point *PWE_projective = CCEC_ALLOC_POINT_WS(ws, n);

    int rv = cczp_sqrt_ws(ws, zp, ccsae_ctx_CE_y(ctx), ccsae_ctx_PWE_y(ctx));
    cc_require(rv == CCERR_OK, errOut);

    cczp_from_ws(ws, zp, ccsae_ctx_PWE_y(ctx), ccsae_ctx_CE_y(ctx));
    cczp_cond_negate(zp, ccn_bit(ccsae_ctx_PWE_y(ctx), 0) ^ LSB, ccsae_ctx_PWE_y(ctx), ccsae_ctx_PWE_y(ctx));

    /* 12.4.5.3: Generate the Commit Element
     * We already know ccsase_ctx_PWE is a valid point because of the above loop,
     * so we can simply call ccec_projectify.
     */
    rv = ccec_projectify_ws(ws, cp, PWE_projective, (ccec_const_affine_point_t)ccsae_ctx_PWE(ctx), rng);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccsae_generate_commitment_shared_ws(ws, ctx, PWE_projective, commitment);
    cc_require(rv == CCERR_OK, errOut);

    ccsae_ctx_alg(ctx) = CCSAE_ALG_HAP;
    CCSAE_ADD_STATE(COMMIT_GENERATED);
errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccsae_generate_commitment_finalize(ccsae_ctx_t ctx, uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_GENERATE_COMMITMENT_FINALIZE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_generate_commitment_finalize_ws(ws, ctx, commitment);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccsae_generate_commitment(ccsae_ctx_t ctx,
                              const uint8_t *A,
                              size_t A_nbytes,
                              const uint8_t *B,
                              size_t B_nbytes,
                              const uint8_t *password,
                              size_t password_nbytes,
                              const uint8_t *identifier,
                              size_t identifier_nbytes,
                              uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    int error = ccsae_generate_commitment_init(ctx);
    if (error != CCERR_OK) {
        return error;
    }

    error = ccsae_generate_commitment_partial(
        ctx, A, A_nbytes, B, B_nbytes, password, password_nbytes, identifier, identifier_nbytes, SAE_HUNT_AND_PECK_ITERATIONS);
    if (error != CCERR_OK) {
        return error;
    }

    return ccsae_generate_commitment_finalize(ctx, commitment);
}

static int ccsae_generate_h2c_commit_init_ws(cc_ws_t ws,
                                             ccsae_ctx_t ctx,
                                             const uint8_t *A,
                                             size_t A_nbytes,
                                             const uint8_t *B,
                                             size_t B_nbytes,
                                             const uint8_t *pt,
                                             size_t pt_nbytes)
{
    CCSAE_EXPECT_STATE(INIT);
    int error = CCERR_PARAMETER;

    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cczp_const_t zq = ccec_cp_zq(cp);
    struct ccrng_state *rng = ccsae_ctx_rng(ctx);
    cc_size n = ccec_cp_n(cp);
    cc_size nd = ccn_nof_size(di->output_size);

    uint8_t key[2 * CCSAE_MAX_IDENTITY_SIZE];
    cc_unit hash[ccn_nof_size(MAX_DIGEST_OUTPUT_SIZE)];
    uint8_t hash_bytes[MAX_DIGEST_OUTPUT_SIZE];
    const uint8_t zeros[MAX_DIGEST_OUTPUT_SIZE] = { 0 };

    CC_DECL_BP_WS(ws, bp);
    cc_unit *qm1 = CC_ALLOC_WS(ws, n);
    cc_unit *val = CC_ALLOC_WS(ws, n);

    ccec_pub_ctx_t PT = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_projective_point *PT_projective = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *PWE_projective = (ccec_projective_point *)ccsae_ctx_PWE(ctx);

    cc_require((A_nbytes <= CCSAE_MAX_IDENTITY_SIZE) && (B_nbytes <= CCSAE_MAX_IDENTITY_SIZE), out);
    size_t keySize = A_nbytes + B_nbytes;
    ccsae_lexographic_order_key(A, A_nbytes, B, B_nbytes, key);

    cchmac(di, di->output_size, zeros, keySize, key, hash_bytes);
    error = ccn_read_uint(nd, hash, di->output_size, hash_bytes);
    cc_require(error == CCERR_OK, out);

    ccn_set(n, qm1, cczp_prime(zq));
    qm1[0] &= ~CC_UNIT_C(1);
    ccn_mod_ws(ws, nd, hash, n, val, qm1);
    ccn_add1_ws(ws, n, val, val, 1); // 1 <= val <= q - 1

    ccec_ctx_init(cp, PT);
    error = ccec_import_pub_ws(ws, cp, pt_nbytes, pt, PT);
    cc_require(error == CCERR_OK, out);

    error = ccec_validate_point_and_projectify_ws(ws, cp, PT_projective, (ccec_const_affine_point_t)ccec_ctx_point(PT), rng);
    cc_require(error == CCERR_OK, out);

    error = ccec_mult_blinded_ws(ws, cp, PWE_projective, val, PT_projective, rng);
    cc_require(error == CCERR_OK, out);

    CCSAE_ADD_STATE(COMMIT_UPDATE);
out:
    CC_FREE_BP_WS(ws, bp);
    return error;
}

static int ccsae_generate_h2c_commit_finalize_ws(cc_ws_t ws, ccsae_ctx_t ctx, uint8_t *commitment)
{
    CCSAE_EXPECT_STATE(COMMIT_UPDATE);
    
    ccec_projective_point *PWE_projective = (ccec_projective_point *)ccsae_ctx_PWE(ctx);
    int rv = ccsae_generate_commitment_shared_ws(ws, ctx, PWE_projective, commitment);
    cc_require(rv == CCERR_OK, out);

    ccsae_ctx_alg(ctx) = CCSAE_ALG_H2C;
    CCSAE_ADD_STATE(COMMIT_GENERATED);
out:
    return rv;
}

int ccsae_generate_h2c_commit_finalize(ccsae_ctx_t ctx, uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_GENERATE_H2C_COMMIT_FINALIZE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_generate_h2c_commit_finalize_ws(ws, ctx, commitment);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccsae_generate_h2c_commit_init(ccsae_ctx_t ctx,
                                   const uint8_t *A,
                                   size_t A_nbytes,
                                   const uint8_t *B,
                                   size_t B_nbytes,
                                   const uint8_t *pt,
                                   size_t pt_nbytes)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_GENERATE_H2C_COMMIT_INIT_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_generate_h2c_commit_init_ws(ws, ctx, A, A_nbytes, B, B_nbytes, pt, pt_nbytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccsae_generate_h2c_commit(ccsae_ctx_t ctx,
                              const uint8_t *A,
                              size_t A_nbytes,
                              const uint8_t *B,
                              size_t B_nbytes,
                              const uint8_t *pt,
                              size_t pt_nbytes,
                              uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_WORKSPACE_OR_FAIL(
        ws, CC_MAX_EVAL(CCSAE_GENERATE_H2C_COMMIT_INIT_WORKSPACE_N(n), CCSAE_GENERATE_H2C_COMMIT_FINALIZE_WORKSPACE_N(n)));

    int rv = ccsae_generate_h2c_commit_init_ws(ws, ctx, A, A_nbytes, B, B_nbytes, pt, pt_nbytes);
    cc_require(rv == CCERR_OK, out);

    rv = ccsae_generate_h2c_commit_finalize_ws(ws, ctx, commitment);

out:
    CC_FREE_WORKSPACE(ws);
    return rv;
}
