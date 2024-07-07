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

#ifndef _CORECRYPTO_CCEC448_INTERNAL_H_
#define _CORECRYPTO_CCEC448_INTERNAL_H_

#include "ccn_internal.h"
#include "ccec_internal.h"
#include "ccec448_priv.h"
#include "cc_memory.h"

typedef cc_unit *cced448_point;
typedef const cc_unit *cced448_const_point;

extern const cc_unit kNegative39081[CCN448_N];

typedef enum {
    CCED448_ADD_POINTS_FLAG_NONE     = 0b000,
    CCED448_ADD_POINTS_FLAG_NEGATE_Q = 0b001,
    CCED448_ADD_POINTS_FLAG_Z_EQ_ONE = 0b010,
    CCED448_ADD_POINTS_FLAG_SKIP_T   = 0b100,
} cced448_add_points_flags_t;

CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x448(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x448_c(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x448_opt(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x448_asm(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed448(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed448_c(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed448_opt(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed448_asm(void);

typedef ccec_const_cp_t (*ccec_cp_x448_impl_t)(void);
typedef ccec_const_cp_t (*ccec_cp_ed448_impl_t)(void);

static ccec_cp_x448_impl_t ccec_cp_x448_impls[] = {
    ccec_cp_x448,
    ccec_cp_x448_c,
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    ccec_cp_x448_opt,
#endif
#if CCN_MULMOD_448_ASM
    ccec_cp_x448_asm,
#endif
};

static ccec_cp_ed448_impl_t ccec_cp_ed448_impls[] = {
    ccec_cp_ed448,
    ccec_cp_ed448_c,
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    ccec_cp_ed448_opt,
#endif
#if CCN_MULMOD_448_ASM
    ccec_cp_ed448_asm,
#endif
};

/*! @function ccec448_add_ws
 @abstract Computes r := x + y (mod 2^448 - 2^224 - 1).

 @discussion Ensures that r < 2^448. Might not be fully reduced.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Sum.
 @param x   First summand.
 @param y   Second summand.
 */
CC_NONNULL_ALL
void ccec448_add_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/*! @function ccec448_sub_ws
 @abstract Computes r := x - y (mod 2^448 - 2^224 - 1).

 @discussion Ensures that r < 2^448. Might not be fully reduced.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Difference.
 @param x   Minuend.
 @param y   Subtrahend.
 */
CC_NONNULL_ALL
void ccec448_sub_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/*! @function ccec448_mul_ws
 @abstract Computes r := x * y (mod 2^448 - 2^224 - 1).

 @discussion Ensures that r < 2^448. Might not be fully reduced.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Difference.
 @param x   Multiplier.
 @param y   Multiplicand.
 */
CC_NONNULL_ALL
void ccec448_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/*! @function ccec448_sqr_ws
 @abstract Computes r := x^2 (mod 2^448 - 2^224 - 1).

 @discussion Ensures that r < 2^448. Might not be fully reduced.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Difference.
 @param x   Element.
 */
CC_NONNULL_ALL
void ccec448_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

// Assembly versions.
void ccec448_add_asm(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec448_sub_asm(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec448_mul_asm(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec448_sqr_asm(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function ccec448_inv_ws
 @abstract Computes r := x^-1 (mod 2^448 - 2^224 - 1).

 @discussion Ensures that r < 2^448. Might not be fully reduced.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Modular inverse.
 @param x   Element to invert.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccec448_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function ccec448_from_ws
 @abstract Computes r := x (mod 2^448 - 2^224 - 1).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param x   Number to reduce
 */
CC_NONNULL_ALL
void ccec448_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

// Cofactor clearing, see decodeScalar448() in RFC 7748.
CC_INLINE void ccec448_clamp_scalar(uint8_t sk[56])
{
    sk[0] &= 252;
    sk[55] |= 128;
}

// See RFC 8032, section 5.2.2.
CC_NONNULL_ALL
CC_INLINE void cced448_encode_coordinate(ccec_const_cp_t cp, ccec_const_affine_point_t s, uint8_t out[57])
{
    ccn_write_le_bytes(CCN448_N, ccec_const_point_y(s, cp), out);
    out[56] = (uint8_t)(ccec_point_x(s, cp)[0] << 7);
}

/*! @function cced448_full_add_ws
 @abstract Add two arbitrary points S and T. Both points must be represented
           by standard projective coordinates (X/Z,Y/Z).

 @param ws  Workspace.
 @param cp  Curve parameters.
 @param r   The resulting point R := S + T.
 @param s   The first input point S.
 @param t   The second input point T.
*/
CC_NONNULL_ALL
void cced448_full_add_ws(cc_ws_t ws,
                         ccec_const_cp_t cp,
                         ccec_projective_point_t r,
                         ccec_const_projective_point_t s,
                         ccec_const_projective_point_t t);

/*! @function cced448_shake_to_scalar_ws
 @abstract Computes SHAKE256("SigEd448" || "0" || "0" || data1 || data2 || M, 114),
           interprets the result as a little-endian integer and reduces (mod q)
           to produce a valid Ed448 scalar.

 @param ws           Workspace.
 @param cp           Curve parameters.
 @param s            The resulting Ed448 scalar.
 @param data1_nbytes Length of data1 in bytes.
 @param data1        Data to absorb (optional).
 @param data2_nbytes Length of data2 in bytes.
 @param data2        Data to absorb.
 @param msg_nbytes   Length of message in bytes.
 @param msg          The signed message.
*/
CC_NONNULL((1, 2, 3, 7, 9))
void cced448_shake_to_scalar_ws(cc_ws_t ws,
                                ccec_const_cp_t cp,
                                cc_unit *s,
                                size_t data1_nbytes,
                                const uint8_t *cc_sized_by(data1_nbytes) data1,
                                size_t data2_nbytes,
                                const uint8_t *cc_sized_by(data1_nbytes) data2,
                                size_t msg_nbytes,
                                const uint8_t *cc_sized_by(msg_nbytes) msg);

/*! @function cced448_add_points_unified_ws
 @abstract Computes R = P + Q. Unified addition with no constraints on P or Q.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param R     The resulting point R = P + Q.
 @param P     A projective (ext. twisted Edwards coordinate) point P.
 @param Q     A projective (ext. twisted Edwards coordinate) point Q.
 @param flags Flags to speed up the computation or turn addition into subtraction.
*/
CC_NONNULL_ALL
void cced448_add_points_unified_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   cced448_point R,
                                   cced448_const_point P,
                                   cced448_const_point Q,
                                   cced448_add_points_flags_t flags);

/*! @function cced448_scalar_mult_ws
 @abstract Performs scalar multiplication, computing R = s * P.

 @discussion The runtime depends on `sbitlen` only.
             Base point P is not randomized.

 @param ws      Workspace.
 @param cp      Curve parameters.
 @param R       The resulting point R = s * P.
 @param s       The scalar s.
 @param sbitlen Length of scalar s in bits.
 @param P       A projective base point P.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_scalar_mult_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_projective_point_t R, const cc_unit *s, size_t sbitlen, ccec_const_projective_point_t P);

/*! @function cced448_scalar_mult_base_masked_ws
 @abstract Performs masked scalar multiplication, computing R = s * B,
           where B is Curve448's base point.

 @param ws  Workspace.
 @param cp  Curve parameters.
 @param rng An initialized RNG.
 @param R   The resulting point R = s * B.
 @param s   The scalar s.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_scalar_mult_base_masked_ws(cc_ws_t ws, ccec_const_cp_t cp, struct ccrng_state *rng, ccec_projective_point_t R, const cc_unit *s);

/*! @function cced448_double_scalar_mult_ws
 @abstract Performs a double-base scalar multiplication,
           computing R = s * B + t * Q.

 @discussion This function is variable-time, with precomputed points
             retrieved from a lookup table.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param R     The resulting point R = s * B + t * Q.
 @param s     The scalar s.
 @param t     The scalar t.
 @param Q     A projective point Q.
*/
CC_NONNULL_ALL
void cced448_double_scalar_mult_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   ccec_projective_point_t R,
                                   const cc_unit *s,
                                   const cc_unit *t,
                                   ccec_const_projective_point_t Q);

/*! @function cced448_to_ed448_point_ws
 @abstract Convert a point represented by standard projective
           coordinates (X,Y,Z) to ext. twisted Edwards coordinates (X,Y,T,Z).

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting point R.
 @param P  The input point P.
*/
CC_NONNULL_ALL
void cced448_to_ed448_point_ws(cc_ws_t ws,
                               ccec_const_cp_t cp,
                               cced448_point R,
                               ccec_const_projective_point_t P);

/*! @function cced448_from_ed448_point_ws
 @abstract Convert a point represented by ext. twisted Edwards
           coordinates (X,Y,T,Z) to standard projective coordinates (X,Y,Z).

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting point R.
 @param P  The input point P.
*/
CC_NONNULL_ALL
void cced448_from_ed448_point_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_projective_point_t R,
                                 cced448_const_point P);

/*! @function cccurve448_internal
 @abstract Scalar multiplication on Curve448.

 @param cp   Curve parameters.
 @param out  Output shared secret or public key.
 @param sk   Input secret key.
 @param base Input basepoint (for computing a shared secret).
 @param rng  RNG for masking and/or randomization.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cccurve448_internal(ccec_const_cp_t cp,
                        ccec448key out,
                        const ccec448secretkey sk,
                        const ccec448base base,
                        struct ccrng_state *rng);

/*! @function cced448_verify_internal
 @abstract Verifies an Ed448 signature.

 @param cp         Curve parameters.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Signed data to verify.
 @param sig        The 114-byte signature.
 @param pk         57-byte public key.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_verify_internal(ccec_const_cp_t cp,
                            size_t msg_nbytes,
                            const uint8_t *msg,
                            const cced448signature sig,
                            const cced448pubkey pk);

/*! @function cced448_sign_internal
 @abstract Generates a Ed448 signature.

 @param cp         Curve parameters.
 @param sig        The 114-byte signature.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Data to sign.
 @param pk         57-byte public key.
 @param sk         57-byte secret key.
 @param rng        An initialized RNG.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_sign_internal(ccec_const_cp_t cp,
                          cced448signature sig,
                          size_t msg_nbytes,
                          const uint8_t *msg,
                          const cced448pubkey pk,
                          const cced448secretkey sk,
                          struct ccrng_state *rng);

/*! @function cced448_sign_deterministic
 @abstract Generates a deterministic Ed448 signature.

 @param cp         Curve parameters.
 @param sig        The 114-byte signature.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Data to sign.
 @param pk         57-byte public key.
 @param sk         57-byte secret key.
 @param rng        An initialized RNG.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_sign_deterministic(ccec_const_cp_t cp,
                               cced448signature sig,
                               size_t msg_nbytes,
                               const uint8_t *msg,
                               const cced448pubkey pk,
                               const cced448secretkey sk,
                               struct ccrng_state *rng);

#endif /* _CORECRYPTO_CCEC448_INTERNAL_H_ */
