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

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include "cc_macros.h"
#include "cc_workspaces.h"
#include "cc_debug.h"

static uint8_t is_non_zero(size_t l,uint8_t *s) {
    uint8_t t=0;
    for(size_t i=0;i<l;i++) {t|=s[i];}
    return t;
}

/*!
 @function   ccecdh_fast_scalar_mult_ws
 @abstract   Perform fast scalar multiplication.

 @discussion This function uses plain dbl-and-add scalar multiplication and
             must not be used with secret scalars. It's meant to be fast
             and doesn't aim to offer any SCA resistance.

 @param      cp             EC parameters.
 @param      R              Projective output point.
 @param      d              Non-secret scalar.
 @param      base           Base point on the chosen curve.

 @returns    0 for success, negative for failure.
 */
CC_NONNULL_ALL
static int ccecdh_fast_scalar_mult_ws(cc_ws_t ws,
                                      ccec_const_cp_t cp,
                                      ccec_projective_point_t R,
                                      const cc_unit *d,
                                      ccec_const_affine_point_t base)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccec_cp_n(cp);
    ccec_projective_point *B = CCEC_ALLOC_POINT_WS(ws, n);

    int rv = ccec_projectify_ws(ws, cp, B, base, NULL);
    cc_require(rv == CCERR_OK, out);

    // Set R := B.
    ccn_set(3 * n, ccec_point_x(R, cp), ccec_point_x(B, cp));

    for (size_t i = ccn_bitlen(n, d) - 1; i > 0; i--) {
        ccec_double_ws(ws, cp, R, R);

        if (ccn_bit(d, i - 1)) {
            ccec_full_add_normalized_ws(ws, cp, R, R, B);
        }
    }

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/*!
 @function   ccecdh_fast_compute_pub_from_priv_ws
 @abstract   Compute a public point from a given scalar.

 @discussion This function uses plain dbl-and-add scalar multiplication and
             must not be used with secret scalars. It's meant to be fast
             and doesn't aim to offer any SCA resistance.

 @param      ws             Workspace.
 @param      cp             EC parameters.
 @param      full_key       Full output key containing the scalar.
 @param      base           Base point on the chosen curve.

 @returns    0 for success, negative for failure.
 */
CC_NONNULL_ALL CC_UNUSED
static int ccecdh_fast_compute_pub_from_priv_ws(cc_ws_t ws,
                                                ccec_const_cp_t cp,
                                                ccec_full_ctx_t full_key,
                                                ccec_const_affine_point_t base)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccec_cp_n(cp);
    ccec_projective_point *R = CCEC_ALLOC_POINT_WS(ws, n);

    int rv = ccecdh_fast_scalar_mult_ws(ws, cp, R, ccec_ctx_k(full_key), base);
    if (rv) {
        goto out;
    }

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(full_key), R);
    if (rv) {
        goto out;
    }

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/*!
 @function   ccecdh_fast_compute_shared_secret_ws
 @abstract   Compute a shared secret given a scalar and a public point.

 @discussion This function uses plain dbl-and-add scalar multiplication and
             must not be used with secret scalars. It's meant to be fast
             and doesn't aim to offer any SCA resistance.

 @param      ws             Workspace.
 @param      cp             EC parameters.
 @param      d              Non-secret scalar.
 @param      base           Base point on the chosen curve.
 @param      sk             Shared key output.

 @returns    0 for success, negative for failure.
 */
CC_NONNULL_ALL CC_UNUSED
static int ccecdh_fast_compute_shared_secret_ws(cc_ws_t ws,
                                                ccec_const_cp_t cp,
                                                const cc_unit *d,
                                                ccec_const_affine_point_t base,
                                                uint8_t *sk)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccec_cp_n(cp);
    ccec_projective_point *R = CCEC_ALLOC_POINT_WS(ws, n);

    int rv = ccecdh_fast_scalar_mult_ws(ws, cp, R, d, base);
    if (rv) {
        goto out;
    }

    cc_unit *x = CC_ALLOC_WS(ws, n);
    rv = ccec_affinify_x_only_ws(ws, cp, x, R);
    if (rv) {
        goto out;
    }

    ccn_write_uint_padded(n, x, ccec_cp_prime_size(cp), sk);

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_NONNULL_ALL
static int ccecdh_pcc_compute_pub_from_priv_ws(cc_ws_t ws,
                                               ccec_const_cp_t cp,
                                               ccec_full_ctx_t key,
                                               ccec_const_affine_point_t base)
{
#if CC_SMALL_CODE
    return ccec_make_pub_from_priv_ws(ws, cp, NULL, ccec_ctx_k(key), base, ccec_ctx_pub(key));
#else
    return ccecdh_fast_compute_pub_from_priv_ws(ws, cp, key, base);
#endif
}

CC_NONNULL_ALL
static int ccecdh_pcc_compute_shared_secret_ws(cc_ws_t ws,
                                               ccec_full_ctx_t key,
                                               ccec_pub_ctx_t pub,
                                               CC_UNUSED size_t *sk_len,
                                               uint8_t *sk)
{
#if CC_SMALL_CODE
    return ccecdh_compute_shared_secret_ws(ws, key, pub, sk_len, sk, NULL);
#else
    return ccecdh_fast_compute_shared_secret_ws(ws, ccec_ctx_cp(key), ccec_ctx_k(key), (ccec_const_affine_point_t)ccec_ctx_point(pub), sk);
#endif
}

// Override workspace definitions so they're correct for default and CC_SMALL_CODE=1.
CC_WORKSPACE_OVERRIDE(ccecdh_pcc_compute_pub_from_priv_ws, ccec_make_pub_from_priv_ws)
CC_WORKSPACE_OVERRIDE(ccecdh_pcc_compute_pub_from_priv_ws, ccecdh_fast_compute_pub_from_priv_ws)
CC_WORKSPACE_OVERRIDE(ccecdh_pcc_compute_shared_secret_ws, ccecdh_compute_shared_secret_ws)
CC_WORKSPACE_OVERRIDE(ccecdh_pcc_compute_shared_secret_ws, ccecdh_fast_compute_shared_secret_ws)

#define CCN32_N ccn_nof(32)
static const cc_unit REF_K[CCN32_N] = { CCN32_C(60,0d,de,ed) };

int ccecdh_pairwise_consistency_check_ws(cc_ws_t ws,
                                         ccec_full_ctx_t full_key,
                                         ccec_const_affine_point_t base,
                                         struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccec_ctx_cp(full_key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    // Use a dummy key for reference
    ccec_full_ctx_t reference_key = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, reference_key);
    ccn_setn(ccec_cp_n(cp), ccec_ctx_k(reference_key), CCN32_N, REF_K);

    // Default to the generator as the base point.
    if (base == NULL) {
        base = ccec_cp_g(cp);
    }

    // Compute the public from the private reference key.
    int rv = ccecdh_pcc_compute_pub_from_priv_ws(ws, cp, reference_key, base);
    cc_require(rv == CCERR_OK, errOut);

    // Do a ECDH with newly generated key and received key
    size_t shared_key_size = ccec_cp_prime_size(cp);
    size_t shared_key1_size = shared_key_size;
    size_t shared_key2_size = shared_key_size;

    uint8_t *shared_key1 = (uint8_t *)CC_ALLOC_WS(ws, n);
    uint8_t *shared_key2 = (uint8_t *)CC_ALLOC_WS(ws, n);

    cc_clear(shared_key_size, shared_key1);
    cc_clear(shared_key_size, shared_key2);

    rv = ccecdh_compute_shared_secret_ws(ws, full_key, ccec_ctx_pub(reference_key), &shared_key1_size, shared_key1, rng);
    cc_require(rv == CCERR_OK, errOut);

    cc_require_action(is_non_zero(shared_key1_size, shared_key1), errOut, rv = CCEC_GENERATE_KEY_CONSISTENCY);

    // Compute the shared secret using the private reference key.
    rv = ccecdh_pcc_compute_shared_secret_ws(ws, reference_key, ccec_ctx_pub(full_key), &shared_key2_size, shared_key2);
    cc_require(rv == CCERR_OK, errOut);

    cc_require_action(shared_key1_size == shared_key2_size, errOut, rv = CCEC_GENERATE_KEY_CONSISTENCY);
    cc_require_action(shared_key_size == shared_key1_size, errOut, rv = CCEC_GENERATE_KEY_CONSISTENCY);
    cc_require_action(cc_cmp_safe(shared_key_size, shared_key1, shared_key2) == 0, errOut, rv = CCEC_GENERATE_KEY_CONSISTENCY);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccecdh_pairwise_consistency_check(ccec_full_ctx_t full_key,
                                      ccec_const_affine_point_t base,
                                      struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccec_ctx_cp(full_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCECDH_PAIRWISE_CONSISTENCY_CHECK_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccecdh_pairwise_consistency_check_ws(ws, full_key, base, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
