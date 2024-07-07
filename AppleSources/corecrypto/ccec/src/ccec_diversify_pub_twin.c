/* Copyright (c) (2018,2019,2021-2023) Apple Inc. All rights reserved.
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

static int ccec_diversify_pub_twin_ws(cc_ws_t ws, ccec_const_cp_t cp,
                                      const ccec_pub_ctx_t pub,
                                      size_t entropy_len,
                                      const uint8_t *entropy,
                                      struct ccrng_state *masking_rng,
                                      ccec_pub_ctx_t pub_out)
{
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    ccec_projective_point *G = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *P = CCEC_ALLOC_POINT_WS(ws, n);
    ccec_projective_point *S = CCEC_ALLOC_POINT_WS(ws, n);

    // Alias T as P for readability.
    ccec_projective_point_t T = P;

    int rv = ccec_validate_point_and_projectify_ws(ws, cp, P, (ccec_const_affine_point_t)ccec_ctx_point(pub), masking_rng);
    if (rv) {
        goto cleanup;
    }

    rv = ccec_projectify_ws(ws, cp, G, ccec_cp_g(cp), masking_rng);
    if (rv) {
        goto cleanup;
    }

    // Derive scalars u and v.
    rv = ccec_diversify_twin_scalars_ws(ws, cp, u, v, entropy_len, entropy);
    if (rv) {
        goto cleanup;
    }

    // S = u * P
    rv = ccec_mult_blinded_ws(ws, cp, S, u, P, masking_rng);
    if (rv) {
        goto cleanup;
    }

    // T = v * G
    rv = ccec_mult_blinded_ws(ws, cp, T, v, G, masking_rng);
    if (rv) {
        goto cleanup;
    }

    // S' = S + T
    ccec_full_add_ws(ws, cp, S, S, T);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(pub_out), S);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_diversify_pub_twin(ccec_const_cp_t cp,
                            const ccec_pub_ctx_t pub,
                            size_t entropy_len,
                            const uint8_t *entropy,
                            struct ccrng_state *masking_rng,
                            ccec_pub_ctx_t pub_out)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_DIVERSIFY_PUB_TWIN_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_diversify_pub_twin_ws(ws, cp, pub, entropy_len, entropy, masking_rng, pub_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
