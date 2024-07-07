/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_memory.h"
#include "ccn_internal.h"
#include "ccec_internal.h"
#include "ccrng_internal.h"
#include "ccshake_internal.h"
#include "ccec448_internal.h"

// -39081 (mod p)
const cc_unit kNegative39081[] = {
    CCN448_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,
             ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,67,56)
};

// dom4(0, "")
static const uint8_t kSigEd448[] = {
    'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0, 0
};

void cced448_to_ed448_point_ws(cc_ws_t ws,
                               ccec_const_cp_t cp,
                               cced448_point R,
                               ccec_const_projective_point_t P)
{
    const cc_unit *x = ccec_const_point_x(P, cp);
    const cc_unit *y = ccec_const_point_y(P, cp);
    const cc_unit *z = ccec_const_point_z(P, cp);

    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    // To get (XZ,YZ,XYZ,Z) from (XZ,YZ,Z), compute (XZ*Z,YZ*Z,XZ*YZ,Z^2).

    CC_DECL_BP_WS(ws, bp);
    cczp_mul_ws(ws, zp, &R[2 * n], x, y);
    cczp_mul_ws(ws, zp, &R[0 * n], x, z);
    cczp_mul_ws(ws, zp, &R[1 * n], y, z);
    cczp_sqr_ws(ws, zp, &R[3 * n], z);
    CC_FREE_BP_WS(ws, bp);
}

void cced448_from_ed448_point_ws(CC_UNUSED cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_projective_point_t R,
                                 cced448_const_point P)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    // To get (XZ,YZ,Z) from (XZ,YZ,XYZ,Z), simply ignore XYZ.

    ccn_set(n, ccec_point_x(R, cp), &P[0 * n]);
    ccn_set(n, ccec_point_y(R, cp), &P[1 * n]);
    ccn_set(n, ccec_point_z(R, cp), &P[3 * n]);
}

/*! @function cced448_make_pub_ws
 @abstract Creates an Ed448 public key from a private key.

 @param ws  Workspace
 @param cp  Curve parameters.
 @param pk  Receives a 56-byte public key.
 @param sk  Receives a 56-byte secret key.
 @param rng An initialized RNG.
 */
CC_NONNULL_ALL CC_WARN_RESULT
static int cced448_make_pub_ws(cc_ws_t ws,
                               ccec_const_cp_t cp,
                               cced448pubkey pk,
                               const cced448secretkey sk,
                               struct ccrng_state *rng)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    ccec_projective_point *R = CCEC_ALLOC_POINT_WS(ws, n);

    // Compute scalar.
    uint8_t h[114];
    ccshake256(sizeof(cced448secretkey), sk, 114, h);
    ccec448_clamp_scalar(h);
    ccn_read_le_bytes(n, h, s);

    // Scalar multiplication.
    int rv = cced448_scalar_mult_base_masked_ws(ws, cp, rng, R, s);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    cc_require(rv == CCERR_OK, errOut);

    // Encode.
    cced448_encode_coordinate(cp, (ccec_const_affine_point_t)R, pk);

errOut:
    cc_clear(sizeof(h), h);
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cced448_make_pub(struct ccrng_state *rng, cced448pubkey pk, const cced448secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_ed448();
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCED448_MAKE_PUB_WORKSPACE_N(CCN448_N));
    int rv = cced448_make_pub_ws(ws, cp, pk, sk, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cced448_make_key_pair(struct ccrng_state *rng, cced448pubkey pk, cced448secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    int rv = ccrng_generate_fips(rng, sizeof(cced448secretkey), sk);
    cc_require_or_return(rv == CCERR_OK, rv);

    return cced448_make_pub(rng, pk, sk);
}

void cced448_shake_to_scalar_ws(cc_ws_t ws,
                                ccec_const_cp_t cp,
                                cc_unit *s,
                                size_t data1_nbytes,
                                const uint8_t *data1,
                                size_t data2_nbytes,
                                const uint8_t *data2,
                                size_t msg_nbytes,
                                const uint8_t *msg)
{
    const struct ccxof_info *xi = ccshake256_xi();

    cczp_const_t zp = ccec_cp_zp(cp);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n + 1);

    uint8_t h[120] = { 0 };

    // SHAKE256("SigEd448" || "0" || "0" || data1 || data2 || M, 114)
    ccshake256_ctx_decl(ctx);
    ccxof_init(xi, ctx);
    ccxof_absorb(xi, ctx, sizeof(kSigEd448), kSigEd448);
    ccxof_absorb(xi, ctx, data1_nbytes, data1);
    ccxof_absorb(xi, ctx, data2_nbytes, data2);
    ccxof_absorb(xi, ctx, msg_nbytes, msg);
    ccxof_squeeze(xi, ctx, 114, h);
    ccshake256_ctx_clear(ctx);

    // Compute r (mod q).
    ccn_read_le_bytes(2 * n + 1, h, t);
    cczp_modn_ws(ws, zq, s, 2 * n + 1, t);
    cc_clear(sizeof(h), h);

    CC_FREE_BP_WS(ws, bp);
}
