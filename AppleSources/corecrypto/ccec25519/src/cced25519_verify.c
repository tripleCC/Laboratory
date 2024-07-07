/* Copyright (c) (2014-2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccec25519_internal.h"
#include "cced25519_internal.h"

// 2^252 - 3 = (p-5) / 8
static const cc_unit kPsub5div8[] = {
    CCN256_C(0f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fd)
};

// 2^((p-1)/4) (mod p)
static const cc_unit k2toPsub1div4[] = {
    CCN256_C(2b,83,24,80,4f,c1,df,0b,2b,4d,00,99,3d,fb,d7,a7,2f,43,18,06,ad,2f,e4,78,c4,ee,1b,27,4a,0e,a0,b0)
};

/*! @function cced25519_decode_public_and_negate_key_ws
 @abstract Decodes and negates a given 32-byte public key.
           See <https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3>.

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting projective point.
 @param pk 32-byte public key to decode.
*/
CC_NONNULL_ALL CC_WARN_RESULT
static int cced25519_decode_public_and_negate_key_ws(cc_ws_t ws,
                                                     ccec_const_cp_t cp,
                                                     ccec_projective_point_t R,
                                                     const ccec25519pubkey pk)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    cc_unit *x = ccec_point_x(R, cp);
    cc_unit *y = ccec_point_y(R, cp);
    cc_unit *z = ccec_point_z(R, cp);

    int rv = CCERR_PARAMETER;

    cc_unit x_0 = pk[31] >> 7;
    ccn_read_le_bytes(n, pk, y);
    y[n - 1] &= CCN_UNIT_MASK >> 1;
    cc_require_or_return(ccn_cmp(n, y, cczp_prime(zp)) < 0, rv);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);
    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    ccn_seti(n, z, 1);

    // The curve equation implies that:
    //   x^2 = (y^2 - 1) / (d * y^2 + 1) (mod p)
    //
    // Let u = (y^2 - 1) and v = (d * y^2 + 1).
    //
    // The candidate root is then computed as:
    //   x = (u/v)^((p+3)/8) (mod p).
    //
    // The modular inverse of v and the candidate root can be
    // computed using a single modular exponentiation as follows:
    //   x = u * v^3 * (u * v^7)^((p-5)/8)

    cczp_sqr_ws(ws, zp, u, y);         // u = y^2
    cczp_mul_ws(ws, zp, v, u, kLowerCaseD); // v = d * y^2
    cczp_sub_ws(ws, zp, u, u, z);      // u = y^2 - 1
    cczp_add_ws(ws, zp, v, v, z);      // v = d * y^2 + 1

    cczp_sqr_ws(ws, zp, t, v);         // t = v^2
    cczp_mul_ws(ws, zp, x, t, v);      // x = v^3
    cczp_mul_ws(ws, zp, t, x, u);      // t = u * v^3

    cczp_mul_ws(ws, zp, x, x, t);      // x = u * v^6
    cczp_mul_ws(ws, zp, x, x, v);      // x = u * v^7

    rv = cczp_power_fast_ws(ws, zp, x, x, kPsub5div8); // x = (u * v^7)^((p-5)/8)
    cc_require(rv == CCERR_OK, errOut);

    cczp_mul_ws(ws, zp, x, x, t);      // x = u * v^3 * (u * v^7)^((p-5)/8)

    cczp_sqr_ws(ws, zp, t, x);         // t = x^2
    cczp_mul_ws(ws, zp, v, v, t);      // v = v * x^2

    cczp_from_ws(ws, zp, u, u);
    cczp_from_ws(ws, zp, v, v);

    // If v * x^2 = u, x is a square root.
    if (ccn_cmp(n, u, v) != 0) {
        // If v * x^2 = -u, set x = x * 2^((p-1)/4), which is a square root.
        // Otherwise, no square root exists, and the decoding fails.
        cczp_negate(zp, u, u);
        cc_require_action(ccn_cmp(n, u, v) == 0, errOut, rv = CCERR_PARAMETER);
        cczp_mul_ws(ws, zp, x, x, k2toPsub1div4);
    }

    cczp_from_ws(ws, zp, x, x);

    // Use the MSB of the given pubkey (x_0) to select the right square root.
    // If x = 0 and x_0 = 1, decoding fails.
    cc_require_action(!(ccn_is_zero(n, x) && (x_0 == 1)), errOut, rv = CCERR_PARAMETER);

    // Otherwise, if x_0 == x (mod 2) negate x, which effectively
    // negates the public key that was just decoded.
    if ((x[0] & 1) == x_0) {
        cczp_negate(zp, x, x);
    }

    rv = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/*! @function cced25519_verify_ws
 @abstract Verifies an Ed25519 signature.

 @param ws         Workspace.
 @param cp         Curve parameters.
 @param di         512-bit hash descriptor.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Signed data to verify.
 @param sig        The 64-byte signature.
 @param pk         32-byte public key.
*/
CC_NONNULL_ALL CC_WARN_RESULT
static int cced25519_verify_ws(cc_ws_t ws,
                               ccec_const_cp_t cp,
                               const struct ccdigest_info *di,
                               size_t msg_nbytes,
                               const uint8_t *cc_sized_by(msg_nbytes) msg,
                               const ccec25519signature sig,
                               const ccec25519pubkey pk)
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
    ccn_read_le_bytes(n, &sig[32], s);
    cc_require(ccn_cmp(n, s, cczp_prime(zq)) < 0, errOut);

    uint8_t r_computed[32];

    // SHA-512(R || A || M)
    cced25519_hash_to_scalar_ws(ws, cp, di, k, 32, sig, 32, pk, msg_nbytes, msg);

#if (CCN_UNIT_SIZE == 4 || CC_DUNIT_SUPPORTED == 0)
    ge_p3 A;
    ge_p2 R;

    uint8_t h[64];
    ccn_write_le_bytes(2 * n, k, h);

    // Decode the public key and negate.
    rv = ge_frombytes_negate_vartime(&A, pk);
    cc_require(rv == CCERR_OK, errOut);

    // Compute [S]B - [k]A.
    ge_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge_tobytes(r_computed, &R);
#else
    // Decode the public key and negate.
    rv = cced25519_decode_public_and_negate_key_ws(ws, cp, Q, pk);
    cc_require(rv == CCERR_OK, errOut);

    // Compute [S]B - [k]A.
    cced25519_double_scalar_mult_ws(ws, cp, Q, s, k, Q);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)Q, Q);
    cc_require(rv == CCERR_OK, errOut);

    cced25519_encode_coordinate(cp, (ccec_const_affine_point_t)Q, r_computed);
#endif // (CCN_UNIT_SIZE == 4 || CC_DUNIT_SUPPORTED == 0)

    // The RFC says to check that [S]B = R + [k]A. Instead, we can
    // rearrange and check that R = [S]B - [k]A, to avoid decoding R.
    cc_require_action(cc_cmp_safe(32, r_computed, sig) == 0, errOut, rv = CCERR_INVALID_SIGNATURE);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cced25519_verify_internal(ccec_const_cp_t cp,
                              const struct ccdigest_info *di,
                              size_t msg_nbytes,
                              const void *cc_sized_by(msg_nbytes) msg,
                              const ccec25519signature sig,
                              const ccec25519pubkey pk)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCED25519_VERIFY_WORKSPACE_N(CCN256_N));
    int rv = cced25519_verify_ws(ws, cp, di, msg_nbytes, msg, sig, pk);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cced25519_verify(const struct ccdigest_info *di,
                     size_t msg_nbytes,
                     const void *cc_sized_by(msg_nbytes) msg,
                     const ccec25519signature sig,
                     const ccec25519pubkey pk)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_ed25519();
    return cced25519_verify_internal(cp, di, msg_nbytes, msg, sig, pk);
}
