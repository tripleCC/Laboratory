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
#include "ccec_internal.h"
#include "ccspake_internal.h"

int ccspake_prover_init(ccspake_ctx_t ctx,
                        ccspake_const_cp_t scp,
                        ccspake_const_mac_t mac,
                        struct ccrng_state *rng,
                        size_t aad_nbytes,
                        const uint8_t *aad,
                        size_t w_nbytes,
                        const uint8_t *w0,
                        const uint8_t *w1)
{
    CC_ENSURE_DIT_ENABLED

    cc_clear(ccspake_sizeof_ctx(scp), ctx);

    // This API supports the CCC variant only.
    if (scp->var != CCSPAKE_VARIANT_CCC_V1) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_w(scp) != w_nbytes) {
        return CCERR_PARAMETER;
    }

    if (aad_nbytes > sizeof(ctx->aad)) {
        return CCERR_PARAMETER;
    }

    ccspake_ctx_scp(ctx) = scp;
    ccspake_ctx_mac(ctx) = mac;
    ccspake_ctx_rng(ctx) = rng;
    ccspake_ctx_aad_nbytes(ctx) = aad_nbytes;
    ccspake_ctx_is_prover(ctx) = true;
    ccspake_ctx_state(ctx) = CCSPAKE_STATE_INIT;

    if (aad_nbytes > 0) {
        cc_memcpy(ccspake_ctx_aad(ctx), aad, aad_nbytes);
    }

    ccec_const_cp_t cp = ccspake_cp_ec(scp);

    int rv = ccec_generate_scalar_fips_extrabits(cp, w_nbytes, w0, ccspake_ctx_w0(ctx));
    cc_require_or_return(rv == CCERR_OK, rv);

    rv = ccec_generate_scalar_fips_extrabits(cp, w_nbytes, w1, ccspake_ctx_w1(ctx));
    cc_require_or_return(rv == CCERR_OK, rv);

    ccspake_transcript_init(ctx);

    return CCERR_OK;
}

int ccspake_prover_initialize(ccspake_ctx_t ctx,
                              ccspake_const_cp_t scp,
                              ccspake_const_mac_t mac,
                              struct ccrng_state *rng,
                              size_t context_nbytes,
                              const uint8_t *context,
                              size_t id_prover_nbytes,
                              const uint8_t *id_prover,
                              size_t id_verifier_nbytes,
                              const uint8_t *id_verifier,
                              size_t w_nbytes,
                              const uint8_t *w0,
                              const uint8_t *w1)
{
    CC_ENSURE_DIT_ENABLED
    
    if (scp->var == CCSPAKE_VARIANT_CCC_V1) {
        // The CCC variant does not support identities.
        if (id_prover || id_verifier) {
            return CCERR_PARAMETER;
        }

        return ccspake_prover_init(ctx, scp, mac, rng, context_nbytes, context, w_nbytes, w0, w1);
    }

    // The RFC variant requires a context.
    if (context_nbytes == 0) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_w(scp) != w_nbytes) {
        return CCERR_PARAMETER;
    }

    cc_clear(ccspake_sizeof_ctx(scp), ctx);

    ccspake_ctx_scp(ctx) = scp;
    ccspake_ctx_mac(ctx) = mac;
    ccspake_ctx_rng(ctx) = rng;
    ccspake_ctx_aad_nbytes(ctx) = 0;
    ccspake_ctx_is_prover(ctx) = true;
    ccspake_ctx_state(ctx) = CCSPAKE_STATE_INIT;

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    cc_size n = ccec_cp_n(cp);

    // Read w0.
    int rv = ccn_read_uint(n, ccspake_ctx_w0(ctx), w_nbytes, w0);
    cc_require_or_return(rv == CCERR_OK, rv);

    // Read w1.
    rv = ccn_read_uint(n, ccspake_ctx_w1(ctx), w_nbytes, w1);
    cc_require_or_return(rv == CCERR_OK, rv);

    // RFC: TT = Context || idProver || idVerifier || M || N || (...)
    ccspake_transcript_init(ctx);
    ccspake_transcript_begin(ctx, context_nbytes, context, id_prover_nbytes, id_prover, id_verifier_nbytes, id_verifier);

    return CCERR_OK;
}

CC_NONNULL((1, 2, 3, 4, 5, 9, 11)) CC_WARN_RESULT
static int ccspake_verifier_init_ws(cc_ws_t ws,
                                    ccspake_ctx_t ctx,
                                    ccspake_const_cp_t scp,
                                    ccspake_const_mac_t mac,
                                    struct ccrng_state *rng,
                                    size_t aad_nbytes,
                                    const uint8_t *aad,
                                    size_t w0_nbytes,
                                    const uint8_t *w0,
                                    size_t L_nbytes,
                                    const uint8_t *L)
{
    cc_clear(ccspake_sizeof_ctx(scp), ctx);

    // This API supports the CCC variant only.
    if (scp->var != CCSPAKE_VARIANT_CCC_V1) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_w(scp) != w0_nbytes) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_point(scp) != L_nbytes) {
        return CCERR_PARAMETER;
    }

    if (aad_nbytes > sizeof(ctx->aad)) {
        return CCERR_PARAMETER;
    }

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_pub_ctx_t L_pub = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, L_pub);

    ccspake_ctx_scp(ctx) = scp;
    ccspake_ctx_mac(ctx) = mac;
    ccspake_ctx_rng(ctx) = rng;
    ccspake_ctx_aad_nbytes(ctx) = aad_nbytes;
    ccspake_ctx_is_prover(ctx) = false;
    ccspake_ctx_state(ctx) = CCSPAKE_STATE_INIT;

    if (aad_nbytes > 0) {
        cc_memcpy(ccspake_ctx_aad(ctx), aad, aad_nbytes);
    }

    int rv = ccec_generate_scalar_fips_extrabits_ws(ws, cp, w0_nbytes, w0, ccspake_ctx_w0(ctx));
    cc_require(rv == CCERR_OK, errOut);

    rv = ccspake_import_pub_ws(ws, L_pub, L_nbytes, L);
    cc_require(rv == CCERR_OK, errOut);

    ccspake_store_pub_key(L_pub, ccspake_ctx_L(ctx));
    ccspake_transcript_init(ctx);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccspake_verifier_init(ccspake_ctx_t ctx,
                          ccspake_const_cp_t scp,
                          ccspake_const_mac_t mac,
                          struct ccrng_state *rng,
                          size_t aad_nbytes,
                          const uint8_t *aad,
                          size_t w0_nbytes,
                          const uint8_t *w0,
                          size_t L_nbytes,
                          const uint8_t *L)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_VERIFIER_INIT_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccspake_verifier_init_ws(ws, ctx, scp, mac, rng, aad_nbytes, aad, w0_nbytes, w0, L_nbytes, L);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_WARN_RESULT CC_NONNULL((1, 2, 3, 4, 5, 13, 15))
static int ccspake_verifier_initialize_ws(cc_ws_t ws,
                                          ccspake_ctx_t ctx,
                                          ccspake_const_cp_t scp,
                                          ccspake_const_mac_t mac,
                                          struct ccrng_state *rng,
                                          size_t context_nbytes,
                                          const uint8_t *context,
                                          size_t id_prover_nbytes,
                                          const uint8_t *id_prover,
                                          size_t id_verifier_nbytes,
                                          const uint8_t *id_verifier,
                                          size_t w0_nbytes,
                                          const uint8_t *w0,
                                          size_t L_nbytes,
                                          const uint8_t *L)
{
    if (scp->var == CCSPAKE_VARIANT_CCC_V1) {
        // The CCC variant does not support identities.
        if (id_prover || id_verifier) {
            return CCERR_PARAMETER;
        }

        return ccspake_verifier_init_ws(ws, ctx, scp, mac, rng, context_nbytes, context, w0_nbytes, w0, L_nbytes, L);
    }

    // The RFC variant requires a context.
    if (context_nbytes == 0) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_point(scp) != L_nbytes) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_w(scp) != w0_nbytes) {
        return CCERR_PARAMETER;
    }

    cc_clear(ccspake_sizeof_ctx(scp), ctx);

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_pub_ctx_t L_pub = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, L_pub);

    ccspake_ctx_scp(ctx) = scp;
    ccspake_ctx_mac(ctx) = mac;
    ccspake_ctx_rng(ctx) = rng;
    ccspake_ctx_aad_nbytes(ctx) = 0;
    ccspake_ctx_is_prover(ctx) = false;
    ccspake_ctx_state(ctx) = CCSPAKE_STATE_INIT;

    // Read w0.
    int rv = ccn_read_uint(n, ccspake_ctx_w0(ctx), w0_nbytes, w0);
    cc_require(rv == CCERR_OK, errOut);

    // Read L.
    rv = ccspake_import_pub_ws(ws, L_pub, L_nbytes, L);
    cc_require(rv == CCERR_OK, errOut);

    ccspake_store_pub_key(L_pub, ccspake_ctx_L(ctx));

    // RFC: TT = Context || idProver || idVerifier || M || N || (...)
    ccspake_transcript_init(ctx);
    ccspake_transcript_begin(ctx, context_nbytes, context, id_prover_nbytes, id_prover, id_verifier_nbytes, id_verifier);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccspake_verifier_initialize(ccspake_ctx_t ctx,
                                ccspake_const_cp_t scp,
                                ccspake_const_mac_t mac,
                                struct ccrng_state *rng,
                                size_t context_nbytes,
                                const uint8_t *context,
                                size_t id_prover_nbytes,
                                const uint8_t *id_prover,
                                size_t id_verifier_nbytes,
                                const uint8_t *id_verifier,
                                size_t w0_nbytes,
                                const uint8_t *w0,
                                size_t L_nbytes,
                                const uint8_t *L)
{
    CC_ENSURE_DIT_ENABLED
    
    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_VERIFIER_INITIALIZE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccspake_verifier_initialize_ws(ws, ctx, scp, mac, rng,
                                            context_nbytes, context,
                                            id_prover_nbytes, id_prover,
                                            id_verifier_nbytes, id_verifier,
                                            w0_nbytes, w0, L_nbytes, L);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
