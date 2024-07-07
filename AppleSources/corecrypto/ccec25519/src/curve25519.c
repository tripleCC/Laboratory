/* Copyright (c) (2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_priv.h"
#include "cc_internal.h"
#include "ccn_internal.h"
#include "ccrng_internal.h"
#include "ccec25519_internal.h"

// Conditionally swap contents of two points in constant time.
#define cond_swap_points(...) ccn_cond_swap(CCN256_N * 2, __VA_ARGS__)

// X25519's base point: u=9.
static const uint8_t kX25519BasePoint[32] = { 9 };

// Cofactor clearing, see decodeScalar25519() in RFC 7748.
CC_INLINE void ccx25519_clamp_scalar(ccec25519secretkey sk)
{
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}

/*! @function ccx25519_scalar_mult_ws
 @abstract Scalar multiplication using a Montgomery Ladder and
           differential addition formulas that allow for Z ≠ 1.

 @param ws        Workspace
 @param cp        Curve parameters.
 @param resultx   Output for X-coordinate of the result.
 @param resultz   Output for Z-coordinate of the result.
 @param e         The "scalar" or "exponent".
 @param lambda0   Random field element.
 @param xlambda0  Randomized X-coordinate of the base point.
 @param lambda1   Second random field element.
 */
CC_NONNULL_ALL
static void ccx25519_scalar_mult_ws(cc_ws_t ws,
                                    ccec_const_cp_t cp,
                                    cc_unit *resultx,
                                    cc_unit *resultz,
                                    const cc_unit *e,
                                    const cc_unit *lambda0,
                                    const cc_unit *xlambda0,
                                    const cc_unit *lambda1)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *x1 = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *z1 = &x1[n];
    cc_unit *x2 = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *z2 = &x2[n];
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);

    ccn_clear(n, z2);

    ccn_set(n, z1, lambda0);
    ccn_set(n, x1, xlambda0);
    ccn_set(n, x2, lambda1);

    cc_unit lbit = 0;

    for (size_t i = 255; i > 0; i--) {
        cc_unit ebit = ccn_bit(e, i - 1);
        cond_swap_points(ebit ^ lbit, x1, x2);
        lbit = ebit;

        cczp_sub_ws(ws, zp, t0, x1, z1);
        cczp_sub_ws(ws, zp, t1, x2, z2);
        cczp_add_ws(ws, zp, x2, x2, z2);
        cczp_add_ws(ws, zp, z2, x1, z1);
        cczp_mul_ws(ws, zp, z1, t0, x2);
        cczp_mul_ws(ws, zp, z2, z2, t1);
        cczp_sqr_ws(ws, zp, t0, t1);
        cczp_sqr_ws(ws, zp, t1, x2);
        cczp_add_ws(ws, zp, x1, z1, z2);
        cczp_sub_ws(ws, zp, z2, z1, z2);
        cczp_mul_ws(ws, zp, x2, t1, t0);
        cczp_sub_ws(ws, zp, t1, t1, t0);
        cczp_sqr_ws(ws, zp, z2, z2);
        ccec25519_mul121666_ws(ws, zp, z1, t1);
        cczp_sqr_ws(ws, zp, x1, x1);
        cczp_mul_ws(ws, zp, x1, x1, lambda0);
        cczp_add_ws(ws, zp, t0, t0, z1);
        cczp_mul_ws(ws, zp, z1, z2, xlambda0);
        cczp_mul_ws(ws, zp, z2, t1, t0);
    }

    ccn_mux(n, lbit, resultx, x1, x2);
    ccn_mux(n, lbit, resultz, z1, z2);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function cccurve25519_internal_ws
 @abstract Scalar multiplication on Curve25519.

 @param ws   Workspace.
 @param cp   Curve parameters.
 @param out  Output shared secret or public key.
 @param sk   Input secret key.
 @param base Input basepoint (for computing a shared secret)
 @param rng  RNG for masking and/or randomization.
 */
CC_NONNULL_ALL CC_WARN_RESULT
static int cccurve25519_internal_ws(cc_ws_t ws,
                                    ccec_const_cp_t cp,
                                    ccec25519key out,
                                    const ccec25519secretkey sk,
                                    const ccec25519base base,
                                    struct ccrng_state *rng)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *l0 = CC_ALLOC_WS(ws, n);
    cc_unit *l1 = CC_ALLOC_WS(ws, n);
    cc_unit *pk = CC_ALLOC_WS(ws, n);
    cc_unit *bp = CC_ALLOC_WS(ws, n);
    cc_unit *x = CC_ALLOC_WS(ws, n);
    cc_unit *z = CC_ALLOC_WS(ws, n);

    int rv = ccrng_generate(rng, 32, l0);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccrng_generate(rng, 32, l1);
    cc_require(rv == CCERR_OK, errOut);

    // Reseed the PRNG used for cswap mask generation.
    cc_unit seed;
    ccn_random(1, &seed, rng);
    ccn_mux_seed_mask(seed);

    // Load scalar.
    ccec25519secretkey e;
    cc_memcpy(e, sk, 32);
    ccx25519_clamp_scalar(e);
    ccn_read_le_bytes(n, e, pk);

    // Load base.
    ccn_read_le_bytes(n, base, bp);
    ccn_set_bit(bp, 255, 0);
    cczp_to_ws(ws, zp, bp, bp);
    cczp_mul_ws(ws, zp, bp, bp, l0);
    ccx25519_scalar_mult_ws(ws, cp, x, z, pk, l0, bp, l1);

    cczp_inv_ws(ws, zp, l0, z);
    cczp_mul_ws(ws, zp, z, x, l0);
    cczp_from_ws(ws, zp, z, z);

    ccn_write_le_bytes(n, z, out);

    const uint8_t zeros[32] = { 0 };
    if (cc_cmp_safe(32, out, zeros) == 0) {
        return CCERR_PARAMETER;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cccurve25519_internal(ccec_const_cp_t cp,
                          ccec25519key out,
                          const ccec25519secretkey sk,
                          const ccec25519base base,
                          struct ccrng_state *rng)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCCURVE25519_INTERNAL_WORKSPACE_N(CCN256_N));
    int rv = cccurve25519_internal_ws(ws, cp, out, sk, base, rng);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}

int cccurve25519_with_rng(struct ccrng_state *rng, ccec25519key out, const ccec25519secretkey sk, const ccec25519base base)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_x25519();
    return cccurve25519_internal(cp, out, sk, base, rng);
}

int cccurve25519(ccec25519key out, const ccec25519secretkey sk, const ccec25519base base)
{
    CC_ENSURE_DIT_ENABLED

    struct ccrng_state *rng = ccrng(NULL);
    cc_require_or_return(rng != NULL, CCERR_INTERNAL);

    ccec_const_cp_t cp = ccec_cp_x25519();
    return cccurve25519_internal(cp, out, sk, base, rng);
}

int cccurve25519_make_priv(struct ccrng_state *rng, ccec25519secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    int rv = ccrng_generate_fips(rng, 32, sk);
    cc_require_or_return(rv == CCERR_OK, rv);
    ccx25519_clamp_scalar(sk);

    return CCERR_OK;
}

int cccurve25519_make_pub_with_rng(struct ccrng_state *rng, ccec25519pubkey pk, const ccec25519secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_x25519();
    return cccurve25519_internal(cp, pk, sk, kX25519BasePoint, rng);
}

int cccurve25519_make_pub(ccec25519pubkey pk, const ccec25519secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    struct ccrng_state *rng = ccrng(NULL);
    cc_require_or_return(rng != NULL, CCERR_INTERNAL);

    return cccurve25519_make_pub_with_rng(rng, pk, sk);
}

int cccurve25519_make_key_pair(struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    int rv = cccurve25519_make_priv(rng, sk);
    cc_require_or_return(rv == CCERR_OK, rv);

    return cccurve25519_make_pub_with_rng(rng, pk, sk);
}
