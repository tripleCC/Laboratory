/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
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

static int ccec_diversify_priv_twin_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       const cc_unit *d,
                                       size_t entropy_len,
                                       const uint8_t *entropy,
                                       struct ccrng_state *masking_rng,
                                       ccec_full_ctx_t full)
{
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    int rv = ccec_diversify_twin_scalars_ws(ws, cp, u, v, entropy_len, entropy);
    if (rv) {
        goto cleanup;
    }

    cczp_const_t zq = ccec_cp_zq(cp);
    cc_unit *d2 = ccec_ctx_k(full);

    // d' = d * u + v
    cczp_mul_ws(ws, zq, d2, d, u);
    cczp_add_ws(ws, zq, d2, d2, v);

    // pub(full) = d' * G
    rv = ccec_make_pub_from_priv_ws(ws, cp, masking_rng, d2, NULL, ccec_ctx_pub(full));

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_diversify_priv_twin(ccec_const_cp_t cp,
                             const cc_unit *d,
                             size_t entropy_len,
                             const uint8_t *entropy,
                             struct ccrng_state *masking_rng,
                             ccec_full_ctx_t full)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_DIVERSIFY_PRIV_TWIN_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_diversify_priv_twin_ws(ws, cp, d, entropy_len, entropy, masking_rng, full);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
