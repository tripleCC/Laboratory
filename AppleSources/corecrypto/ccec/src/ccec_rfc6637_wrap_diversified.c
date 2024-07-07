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
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "cc_macros.h"
#include "cc_debug.h"

// Similar to FIPS generation, except that the generator is an input.
CC_NONNULL_ALL CC_WARN_RESULT
static int ccec_generate_diversified_key_ws(cc_ws_t ws,
                                            ccec_const_cp_t cp,
                                            struct ccrng_state *rng,
                                            ccec_const_affine_point_t generator,
                                            ccec_full_ctx_t key)
{
    CC_DECL_BP_WS(ws, bp);

    // Not particular verification made on generator since none of the EC groups
    // in corecrypto have small subgroup.

    // Init key structure
    ccec_ctx_init(cp, key);

    // Generate the private scalar
    int result = ccec_generate_scalar_fips_retry_ws(ws, cp, rng, ccec_ctx_k(key));
    cc_require(result == CCERR_OK, errOut);

    // Generate the corresponding public key
    result = ccec_make_pub_from_priv_ws(ws, cp, rng, ccec_ctx_k(key), generator, ccec_ctx_pub(key));
    cc_require(result == CCERR_OK, errOut);

    // Check consistency
    if (ccecdh_pairwise_consistency_check_ws(ws, key, generator, rng)) {
        result = CCEC_GENERATE_KEY_CONSISTENCY;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccec_rfc6637_wrap_key_diversified_ws(cc_ws_t ws,
                                                ccec_pub_ctx_t generator,
                                                ccec_pub_ctx_t public_key,
                                                void *wrapped_key,
                                                unsigned long flags,
                                                uint8_t symm_alg_id,
                                                size_t key_len,
                                                const void *key,
                                                const struct ccec_rfc6637_curve *curve,
                                                const struct ccec_rfc6637_wrap *wrap,
                                                const uint8_t *fingerprint, /* 20 bytes */
                                                struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_full_ctx_t ephemeral_key = CCEC_ALLOC_FULL_WS(ws, n);

    /*
     * Generate an ephemeral key pair
     * We use the same generation method irrespective
     * of compact format since the sign does not matter in wrapping operations
     */
    int rv = ccec_generate_diversified_key_ws(ws, cp, rng, (ccec_const_affine_point_t)ccec_ctx_point(generator), ephemeral_key);
    cc_require(rv == CCERR_OK, errOut);

    /*
     *  Perform wrapping
     */

    rv = ccec_rfc6637_wrap_core_ws(ws, public_key,
                                       ephemeral_key,
                                       wrapped_key, flags,
                                       symm_alg_id, key_len,
                                       key, curve, wrap,
                                       fingerprint, rng);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_rfc6637_wrap_key_diversified(ccec_pub_ctx_t generator,
                                      ccec_pub_ctx_t public_key,
                                      void *wrapped_key,
                                      unsigned long flags,
                                      uint8_t symm_alg_id,
                                      size_t key_len,
                                      const void *key,
                                      const struct ccec_rfc6637_curve *curve,
                                      const struct ccec_rfc6637_wrap *wrap,
                                      const uint8_t *fingerprint, /* 20 bytes */
                                      struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_RFC6637_WRAP_KEY_DIVERSIFIED_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_rfc6637_wrap_key_diversified_ws(ws, generator, public_key,
                                                      wrapped_key, flags,
                                                      symm_alg_id, key_len, key,
                                                      curve, wrap, fingerprint, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
