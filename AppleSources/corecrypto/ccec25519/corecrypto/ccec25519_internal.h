/* Copyright (c) (2019,2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCEC25519_INTERNAL_H_
#define _CORECRYPTO_CCEC25519_INTERNAL_H_

#include "ccn_internal.h"
#include "ccec_internal.h"
#include <corecrypto/ccec25519_priv.h>

typedef cc_unit *cced25519_point;
typedef const cc_unit *cced25519_const_point;

// d = -121665/121666
extern const cc_unit kLowerCaseD[CCN256_N];

typedef enum {
    CCED25519_ADD_POINTS_FLAG_NONE     = 0b000,
    CCED25519_ADD_POINTS_FLAG_NEGATE_Q = 0b001,
    CCED25519_ADD_POINTS_FLAG_Z_EQ_ONE = 0b010,
    CCED25519_ADD_POINTS_FLAG_SKIP_T   = 0b100,
} cced25519_add_points_flags_t;

CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x25519(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x25519_c(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x25519_opt(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_x25519_asm(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed25519(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed25519_c(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed25519_opt(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_ed25519_asm(void);

#if CCN_MULMOD_25519_ASM
// Wrapper to implement runtime checks for Intel extensions.
static ccec_const_cp_t ccec_cp_x25519_asm_if_available(void)
{
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
    return ccec_cp_x25519_asm();

#if defined(__x86_64__)
    return NULL;
#endif
}

// Wrapper to implement runtime checks for Intel extensions.
static ccec_const_cp_t ccec_cp_ed25519_asm_if_available(void)
{
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
    return ccec_cp_ed25519_asm();

#if defined(__x86_64__)
    return NULL;
#endif
}
#endif

typedef ccec_const_cp_t (*ccec_cp_x25519_impl_t)(void);
typedef ccec_const_cp_t (*ccec_cp_ed25519_impl_t)(void);

static ccec_cp_x25519_impl_t ccec_cp_x25519_impls[] = {
    ccec_cp_x25519,
    ccec_cp_x25519_c,
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    ccec_cp_x25519_opt,
#endif
#if CCN_MULMOD_25519_ASM
    ccec_cp_x25519_asm_if_available,
#endif
};

static ccec_cp_ed25519_impl_t ccec_cp_ed25519_impls[] = {
    ccec_cp_ed25519,
    ccec_cp_ed25519_c,
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    ccec_cp_ed25519_opt,
#endif
#if CCN_MULMOD_25519_ASM
    ccec_cp_ed25519_asm_if_available,
#endif
};

/*! @function ccec25519_add_ws
 @abstract Computes r := x + y (mod 2^256-38).

 @discussion Ensures that r < 2^256. Might not be fully reduced
             mod 2^256-38, but will always fit in 256 bits.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Sum.
 @param x   First summand.
 @param y   Second summand.
 */
CC_NONNULL_ALL
void ccec25519_add_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/*! @function ccec25519_sub_ws
 @abstract Computes r := x - y (mod 2^256-38).

 @discussion Ensures that r < 2^256. Might not be fully reduced
             mod 2^256-38, but will always fit in 256 bits.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Difference.
 @param x   Minuend.
 @param y   Subtrahend.
 */
CC_NONNULL_ALL
void ccec25519_sub_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/*! @function ccec25519_mul_ws
 @abstract Computes x*y (mod 2^256-38).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
void ccec25519_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/*! @function ccec25519_sqr_ws
 @abstract Computes x^2 (mod 2^256-38).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
void ccec25519_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function ccec25519_mul121666_ws
 @abstract Computes x * 121666 (mod 2^256-38).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier.
 */
CC_NONNULL_ALL
void ccec25519_mul121666_ws(cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x);

// Optimized version.
void ccec25519_add_opt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec25519_sub_opt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec25519_mul_opt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec25519_sqr_opt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

// Assembly versions.
void ccec25519_add_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec25519_sub_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec25519_mul_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void ccec25519_sqr_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function ccec25519_inv_ws
 @abstract Computes x^-1 (mod 2^255-19).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to invert.
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccec25519_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function ccec25519_from_ws
 @abstract Computes r := x (mod 2^255-19).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param x   Number to reduce
 */
CC_NONNULL_ALL
void ccec25519_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*!
    @function   cccurve25519_internal
    @abstract   Scalar multiplication on Curve25519.

    @param      cp   Curve parameters.
    @param      out  Output shared secret or public key.
    @param      sk   Input secret key.
    @param      base Input basepoint (for computing a shared secret)
    @param      rng  RNG for masking and/or randomization.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cccurve25519_internal(ccec_const_cp_t cp,
                          ccec25519key out,
                          const ccec25519secretkey sk,
                          const ccec25519base base,
                          struct ccrng_state *rng);

// See RFC 8032, section 5.1.2.
CC_NONNULL_ALL
CC_INLINE void cced25519_encode_coordinate(ccec_const_cp_t cp, ccec_const_affine_point_t s, uint8_t out[32])
{
    ccn_write_le_bytes(CCN256_N, ccec_const_point_y(s, cp), out);
    out[31] |= (uint8_t)(ccec_point_x(s, cp)[0] << 7);
}

/*! @function cced25519_full_add_ws
 @abstract Add two arbitrary points S and T. Both points must be represented
           by standard projective coordinates (X/Z,Y/Z).

 @param ws  Workspace.
 @param cp  Curve parameters.
 @param r   The resulting point R := S + T.
 @param s   The first input point S.
 @param t   The second input point T.
*/
CC_NONNULL_ALL
void cced25519_full_add_ws(cc_ws_t ws,
                           ccec_const_cp_t cp,
                           ccec_projective_point_t r,
                           ccec_const_projective_point_t s,
                           ccec_const_projective_point_t t);

/*! @function cced25519_hash_to_scalar_ws
 @abstract Computes SHA-512(data1 || data2 || M),
           interprets the result as a little-endian integer and reduces (mod q)
           to produce a valid Ed25519 scalar.

 @param ws           Workspace.
 @param cp           Curve parameters.
 @param di           512-bit hash descriptor.
 @param s            The resulting Ed25519 scalar.
 @param data1_nbytes Length of data1 in bytes.
 @param data1        Data to absorb (optional).
 @param data2_nbytes Length of data2 in bytes.
 @param data2        Data to absorb.
 @param msg_nbytes   Length of message in bytes.
 @param msg          The signed message.
*/
CC_NONNULL((1, 2, 3, 4, 8, 10))
void cced25519_hash_to_scalar_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 const struct ccdigest_info *di,
                                 cc_unit *s,
                                 size_t data1_nbytes,
                                 const uint8_t *cc_sized_by(data1_nbytes) data1,
                                 size_t data2_nbytes,
                                 const uint8_t *cc_sized_by(data1_nbytes) data2,
                                 size_t msg_nbytes,
                                 const uint8_t *cc_sized_by(msg_nbytes) msg);

/*! @function cced25519_add_points_unified_ws
 @abstract Computes R = P + Q. Unified addition with no constraints on P or Q.

 @param ws    Workspace.
 @param cp    Curve parameters.
 @param R     The resulting point R = P + Q.
 @param P     A projective (ext. twisted Edwards coordinate) point P.
 @param Q     A projective (ext. twisted Edwards coordinate) point Q.
 @param flags Flags to speed up the computation or turn addition into subtraction.
*/
CC_NONNULL_ALL
void cced25519_add_points_unified_ws(cc_ws_t ws,
                                     ccec_const_cp_t cp,
                                     cced25519_point R,
                                     cced25519_const_point P,
                                     cced25519_const_point Q,
                                     cced25519_add_points_flags_t flags);

/*! @function cced25519_scalar_mult_ws
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
int cced25519_scalar_mult_ws(cc_ws_t ws,
                             ccec_const_cp_t cp,
                             ccec_projective_point_t R,
                             const cc_unit *s, size_t sbitlen,
                             ccec_const_projective_point_t P);

/*! @function cced25519_double_scalar_mult_ws
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
void cced25519_double_scalar_mult_ws(cc_ws_t ws,
                                     ccec_const_cp_t cp,
                                     ccec_projective_point_t R,
                                     const cc_unit *s,
                                     const cc_unit *t,
                                     ccec_const_projective_point_t Q);

/*! @function cced25519_to_ed25519_point_ws
 @abstract Convert a point represented by standard projective
           coordinates (X,Y,Z) to ext. twisted Edwards coordinates (X,Y,T,Z).

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting point R.
 @param P  The input point P.
*/
CC_NONNULL_ALL
void cced25519_to_ed25519_point_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   cced25519_point R,
                                   ccec_const_projective_point_t P);

/*! @function cced25519_from_ed25519_point_ws
 @abstract Convert a point represented by ext. twisted Edwards
           coordinates (X,Y,T,Z) to standard projective coordinates (X,Y,Z).

 @param ws Workspace.
 @param cp Curve parameters.
 @param R  The resulting point R.
 @param P  The input point P.
*/
CC_NONNULL_ALL
void cced25519_from_ed25519_point_ws(cc_ws_t ws,
                                     ccec_const_cp_t cp,
                                     ccec_projective_point_t R,
                                     cced25519_const_point P);

/*! @function cced25519_verify_internal
 @abstract Verifies an Ed25519 signature.

 @param cp         Curve parameters.
 @param di         512-bit hash descriptor.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Signed data to verify.
 @param sig        The 64-byte signature.
 @param pk         32-byte public key.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced25519_verify_internal(ccec_const_cp_t cp,
                              const struct ccdigest_info *di,
                              size_t msg_nbytes,
                              const void *cc_sized_by(msg_nbytes) msg,
                              const ccec25519signature sig,
                              const ccec25519pubkey pk);

#endif /* _CORECRYPTO_CCEC25519_INTERNAL_H_ */
