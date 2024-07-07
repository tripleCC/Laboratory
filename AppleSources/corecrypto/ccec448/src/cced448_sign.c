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

/*! @function cced448_sign_ws
 @abstract Generates a Ed448 signature.

 @param ws         Workspace.
 @param cp         Curve parameters.
 @param sig        The 114-byte signature.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Data to sign.
 @param pk         57-byte public key.
 @param sk         57-byte secret key.
 @param Z          Random element (optional).
 @param rng        An initialized RNG.
*/
CC_NONNULL((1, 2, 3, 5, 6, 7, 9)) CC_WARN_RESULT
static int cced448_sign_ws(cc_ws_t ws,
                           ccec_const_cp_t cp,
                           cced448signature sig,
                           size_t msg_nbytes,
                           const uint8_t *msg,
                           const cced448pubkey pk,
                           const cced448secretkey sk,
                           const uint8_t *Z,
                           struct ccrng_state *rng)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *s = CC_ALLOC_WS(ws, n);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *k = CC_ALLOC_WS(ws, n);

    ccec_projective_point *R = CCEC_ALLOC_POINT_WS(ws, n);

    // Compute scalar.
    uint8_t h[126] = { 0 };
    ccshake256(sizeof(cced448secretkey), sk, 114, h);
    ccec448_clamp_scalar(h);
    ccn_read_le_bytes(n, h, s);

    // Scalar multiplication [s]B.
    int rv = cced448_scalar_mult_base_masked_ws(ws, cp, rng, R, s);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    cc_require(rv == CCERR_OK, errOut);

    // Recompute public key.
    uint8_t pk_computed[57];
    cced448_encode_coordinate(cp, (ccec_const_affine_point_t)R, pk_computed);
    cc_require_action(cc_cmp_safe(57, pk, pk_computed) == 0, errOut, rv = CCERR_PARAMETER);

    size_t Z_nbytes = 0;
    size_t prefix_nbytes = 57;

    // Randomize the signature.
    // See https://datatracker.ietf.org/doc/html/draft-mattsson-cfrg-det-sigs-with-noise-04.
    if (Z) {
        Z_nbytes = 57;
        prefix_nbytes += 12;
    }

    // r = SHAKE256("SigEd448" || 0 || 0 || Z || prefix || 000... || M, 114)
    cced448_shake_to_scalar_ws(ws, cp, r, Z_nbytes, Z, prefix_nbytes, &h[57], msg_nbytes, msg);

    // Scalar multiplication, [r]B.
    rv = cced448_scalar_mult_base_masked_ws(ws, cp, rng, R, r);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    cc_require(rv == CCERR_OK, errOut);

    // Encode R.
    cced448_encode_coordinate(cp, (ccec_const_affine_point_t)R, sig);

    // SHAKE256("SigEd448" || 0 || 0 || R || A || M, 114)
    cced448_shake_to_scalar_ws(ws, cp, k, 57, sig, 57, pk, msg_nbytes, msg);

    // Compute S = (r + k * s) mod q.
    cczp_mul_ws(ws, zq, s, s, k);
    cczp_add_ws(ws, zq, s, s, r);

    // Encode S.
    ccn_write_le_bytes(n, s, &sig[57]);
    sig[113] = 0;

errOut:
    cc_clear(sizeof(h), h);
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cced448_sign_internal(ccec_const_cp_t cp,
                          cced448signature sig,
                          size_t msg_nbytes,
                          const uint8_t *cc_sized_by(msg_nbytes) msg,
                          const cced448pubkey pk,
                          const cced448secretkey sk,
                          struct ccrng_state *rng)
{
    uint8_t Z[57];
    int rv = ccrng_generate_fips(rng, sizeof(Z), Z);
    cc_require_or_return(rv == CCERR_OK, rv);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCED448_SIGN_WORKSPACE_N(CCN448_N));
    rv = cced448_sign_ws(ws, cp, sig, msg_nbytes, msg, pk, sk, Z, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cced448_sign(struct ccrng_state *rng,
                 cced448signature sig,
                 size_t msg_nbytes,
                 const uint8_t *cc_sized_by(msg_nbytes) msg,
                 const cced448pubkey pk,
                 const cced448secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_ed448();
    return cced448_sign_internal(cp, sig, msg_nbytes, msg, pk, sk, rng);
}

int cced448_sign_deterministic(ccec_const_cp_t cp,
                               cced448signature sig,
                               size_t msg_nbytes,
                               const uint8_t *cc_sized_by(msg_nbytes) msg,
                               const cced448pubkey pk,
                               const cced448secretkey sk,
                               struct ccrng_state *rng)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCED448_SIGN_WORKSPACE_N(CCN448_N));
    int rv = cced448_sign_ws(ws, cp, sig, msg_nbytes, msg, pk, sk, NULL, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
