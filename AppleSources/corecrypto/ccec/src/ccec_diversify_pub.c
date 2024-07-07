/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
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

size_t ccec_diversify_min_entropy_len(ccec_const_cp_t cp)
{
    CC_ENSURE_DIT_ENABLED

    return ccec_scalar_fips_extrabits_min_entropy_len(cp);
}

static int ccec_diversify_pub_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_pub_ctx_t pub_key,
                                 size_t entropy_len,
                                 const uint8_t *entropy,
                                 struct ccrng_state *masking_rng,
                                 ccec_pub_ctx_t diversified_generator,
                                 ccec_pub_ctx_t diversified_pub_key)
{
    int retval = CCERR_INTERNAL;
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);

    //==========================================================================
    // Generate adequate random for private key
    // This does not preserve properties of the key so that output so that
    // care must be taken when using compact formating.
    // Valid with compact points when using ECDH and only X coordinate is used
    //==========================================================================

    // Method is from FIPS 186-4 Extra Bits method.
    //  r = entropy mod (q-1)) + 1, where entropy is interpreted as big endian.
    cc_require((retval = ccec_generate_scalar_fips_extrabits_ws(ws, cp, entropy_len, entropy, r)) == CCERR_OK, errOut);

    //==========================================================================
    // Scalar multiplication generator and public point
    //==========================================================================

    // s * generator
    cc_require((retval = ccec_make_pub_from_priv_ws(ws, cp, masking_rng, r, NULL, diversified_generator)) == CCERR_OK, errOut);

    // s * pub
    cc_require((retval = ccec_make_pub_from_priv_ws(ws, cp, masking_rng, r, (ccec_const_affine_point_t)ccec_ctx_point(pub_key), diversified_pub_key)) == CCERR_OK, errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return retval;
}

int ccec_diversify_pub(ccec_const_cp_t cp,
                       ccec_pub_ctx_t pub_key,
                       size_t entropy_len,
                       const uint8_t *entropy,
                       struct ccrng_state *masking_rng,
                       ccec_pub_ctx_t diversified_generator,
                       ccec_pub_ctx_t diversified_pub_key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_DIVERSIFY_PUB_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_diversify_pub_ws(ws, cp, pub_key, entropy_len, entropy, masking_rng, diversified_generator, diversified_pub_key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
