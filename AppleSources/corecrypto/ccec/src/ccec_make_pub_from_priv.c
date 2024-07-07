/* Copyright (c) (2015-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include "cc_macros.h"
#include "cc_workspaces.h"
#include "cc_debug.h"

/* Compute the public point from k.
 k must be in the correct range and without bias */

int ccec_make_pub_from_priv_ws(cc_ws_t ws,
                               ccec_const_cp_t cp,
                               struct ccrng_state *masking_rng,
                               const cc_unit *k,
                               ccec_const_affine_point_t generator,
                               ccec_pub_ctx_t key)
{
    int result = CCEC_GENERATE_KEY_DEFAULT_ERR;

    CC_DECL_BP_WS(ws, bp);

    ccec_ctx_init(cp, key);
    cc_size n = ccec_ctx_n(key);
    ccec_projective_point *base = CCEC_ALLOC_POINT_WS(ws, n);

    cc_require_action(ccec_validate_scalar(cp, k) == CCERR_OK, errOut,
        result = CCEC_GENERATE_INVALID_INPUT);

    //==========================================================================
    // Calculate the public key for k
    //==========================================================================
    if (generator) {
        cc_require((result = ccec_validate_point_and_projectify_ws(ws, cp, base, generator, masking_rng)) == CCERR_OK, errOut);
    } else {
        cc_require((result = ccec_projectify_ws(ws, cp, base, ccec_cp_g(cp), masking_rng)) == CCERR_OK, errOut);
    }
    cc_require_action(ccec_mult_blinded_ws(ws, cp, ccec_ctx_point(key), k, base, masking_rng) == CCERR_OK, errOut,
                      result = CCEC_GENERATE_KEY_MULT_FAIL);
    cc_require_action(ccec_is_point_projective_ws(ws, cp, ccec_ctx_point(key)),errOut,
                      result = CCEC_GENERATE_NOT_ON_CURVE);
    cc_require_action(ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(key), ccec_ctx_point(key)) == 0,errOut,
                      result = CCEC_GENERATE_KEY_AFF_FAIL);
    ccn_seti(n, ccec_ctx_z(key), 1);

    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_make_pub_from_priv(ccec_const_cp_t cp,
                            struct ccrng_state *masking_rng,
                            const cc_unit *k,
                            ccec_const_affine_point_t generator,
                            ccec_pub_ctx_t key)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_MAKE_PUB_FROM_PRIV_WORKSPACE_N(ccec_cp_n(cp)));
    int result = ccec_make_pub_from_priv_ws(ws, cp, masking_rng, k, generator, key);
    CC_FREE_WORKSPACE(ws);
    return result;
}
