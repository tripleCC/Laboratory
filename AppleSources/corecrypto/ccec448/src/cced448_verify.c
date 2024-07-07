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
#include "ccec448_internal.h"

// 2^446 - 2^222 - 1 = (p-3) / 4
static const cc_unit kPsub3div4[] = {
    CCN448_C(3f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,
             bf,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
};

/*! @function cced448_decode_public_key_and_negate_ws
 @abstract Decodes and negates a given 57-byte public key.
           See <https://www.rfc-editor.org/rfc/rfc8032#section-5.2.3>.

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting projective point (with Z=1).
 @param pk 57-byte public key to decode.
*/
CC_NONNULL_ALL CC_WARN_RESULT
static int cced448_decode_public_key_and_negate_ws(cc_ws_t ws,
                                                   ccec_const_cp_t cp,
                                                   ccec_projective_point_t R,
                                                   const cced448pubkey pk)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    cc_unit *x = ccec_point_x(R, cp);
    cc_unit *y = ccec_point_y(R, cp);
    cc_unit *z = ccec_point_z(R, cp);

    int rv = CCERR_PARAMETER;

    // The MSB signals the sign of the x-coordinate.
    cc_require_or_return((pk[56] == 0x80) || (pk[56] == 0), rv);

    ccn_read_le_bytes(n, pk, y);
    cc_require_or_return(ccn_cmp(n, y, cczp_prime(zp)) < 0, rv);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);
    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    // The curve equation implies that:
    //   x^2 = (y^2 - 1) / (d * y^2 - 1) (mod p)
    //
    // Let u = (y^2 - 1) and v = (d * y^2 - 1).
    //
    // The candidate root is then computed as:
    //   x = (u/v)^((p+1)/4) (mod p).
    //
    // The modular inverse of v and the candidate root can be
    // computed using a single modular exponentiation as follows:
    //   x = u^3 * v * (u^5 * v^3)^((p-3)/4)

    ccn_seti(n, z, 1);

    cczp_sqr_ws(ws, zp, u, y);         // u = y^2
    cczp_mul_ws(ws, zp, v, u, kNegative39081); // v = -39081 * y^2
    cczp_sub_ws(ws, zp, u, u, z);      // u = y^2 - 1
    cczp_sub_ws(ws, zp, v, v, z);      // v = -39081 * y^2 - 1 (= d * y^2 - 1)

    cczp_sqr_ws(ws, zp, x, v);         // x = v^2
    cczp_mul_ws(ws, zp, x, x, v);      // x = v^3
    cczp_sqr_ws(ws, zp, t, u);         // t = u^2
    cczp_mul_ws(ws, zp, x, x, t);      // x = u^2 * v^3
    cczp_mul_ws(ws, zp, t, t, u);      // t = u^3
    cczp_mul_ws(ws, zp, x, x, t);      // x = u^5 * v^3

    rv = cczp_power_fast_ws(ws, zp, x, x, kPsub3div4); // x = (u^5 * v^3)^((p-3)/4)
    cc_require(rv == CCERR_OK, errOut);

    cczp_mul_ws(ws, zp, x, x, t);      // x = u^3 * (u^5 * v^3)^((p-3)/4)
    cczp_mul_ws(ws, zp, x, x, v);      // x = u^3 * v * (u^5 * v^3)^((p-3)/4)

    cczp_sqr_ws(ws, zp, t, x);         // t = x^2
    cczp_mul_ws(ws, zp, v, v, t);      // v = v * x^2

    cczp_from_ws(ws, zp, u, u);
    cczp_from_ws(ws, zp, v, v);

    // If v * x^2 = u, the recovered x-coordinate is x.
    // Otherwise, no square root exists, and the decoding fails.
    cc_require_action(ccn_cmp(n, u, v) == 0, errOut, rv = CCERR_PARAMETER);

    cczp_from_ws(ws, zp, x, x);

    // Use the MSB of the given pubkey (x_0) to select the right square root.
    cc_unit x_0 = pk[56] >> 7;

    // If x = 0 and x_0 = 1, decoding fails.
    cc_require_action(!(ccn_is_zero(n, x) && (x_0 == 1)), errOut, rv = CCERR_PARAMETER);

    // Otherwise, if x_0 == x (mod 2) negate x, which effectively
    // negates the public key that was just decoded.
    if ((x[0] & 1) == x_0) {
        cczp_negate(zp, x, x);
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/*! @function cced448_verify_ws
 @abstract Verifies an Ed448 signature.

 @param ws         Workspace.
 @param cp         Curve parameters.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Signed data to verify.
 @param sig        The 114-byte signature.
 @param pk         57-byte public key.
*/
CC_NONNULL_ALL CC_WARN_RESULT
static int cced448_verify_ws(cc_ws_t ws,
                             ccec_const_cp_t cp,
                             size_t msg_nbytes,
                             const uint8_t *msg,
                             const cced448signature sig,
                             const cced448pubkey pk)
{
    int rv = CCERR_INVALID_SIGNATURE;

    cczp_const_t zp = ccec_cp_zp(cp);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *k = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    ccec_projective_point *Q = CCEC_ALLOC_POINT_WS(ws, n);

    // Ensure 0 <= S < q.
    ccn_read_le_bytes(n, &sig[57], s);
    cc_require(sig[113] == 0, errOut);
    cc_require(ccn_cmp(n, s, cczp_prime(zq)) < 0, errOut);

    // Decode the public key and negate.
    rv = cced448_decode_public_key_and_negate_ws(ws, cp, Q, pk);
    cc_require(rv == CCERR_OK, errOut);

    // SHAKE256("SigEd448" || 0 || 0 || R || A || M, 114)
    cced448_shake_to_scalar_ws(ws, cp, k, 57, sig, 57, pk, msg_nbytes, msg);

    // Compute [S]B - [k]A.
    cced448_double_scalar_mult_ws(ws, cp, Q, s, k, Q);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)Q, Q);
    cc_require(rv == CCERR_OK, errOut);

    // The RFC says to check that [S]B = R + [k]A. Instead, we can
    // rearrange and check that R = [S]B - [k]A, to avoid decoding R.
    uint8_t r_computed[57];
    cced448_encode_coordinate(cp, (ccec_const_affine_point_t)Q, r_computed);
    cc_require_action(cc_cmp_safe(57, r_computed, sig) == 0, errOut, rv = CCERR_INVALID_SIGNATURE);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cced448_verify_internal(ccec_const_cp_t cp,
                            size_t msg_nbytes,
                            const uint8_t *msg,
                            const cced448signature sig,
                            const cced448pubkey pk)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCED448_VERIFY_WORKSPACE_N(CCN448_N));
    int rv = cced448_verify_ws(ws, cp, msg_nbytes, msg, sig, pk);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cced448_verify(size_t msg_nbytes,
                   const uint8_t *cc_sized_by(msg_nbytes) msg,
                   const cced448signature sig,
                   const cced448pubkey pk)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_ed448();
    return cced448_verify_internal(cp, msg_nbytes, msg, sig, pk);
}
