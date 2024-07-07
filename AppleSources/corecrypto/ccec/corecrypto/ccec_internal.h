/* Copyright (c) (2010-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCEC_INTERNAL_H_
#define _CORECRYPTO_CCEC_INTERNAL_H_

#include <corecrypto/ccec_priv.h>
#include "cc_internal.h"
#include "cczp_internal.h"
#include <corecrypto/cczp.h>
#include <corecrypto/cc_fault_canary.h>

/* Configuration */
#ifndef CCEC_VERIFY_ONLY
#define CCEC_VERIFY_ONLY 0
#endif

// In general, CCEC_USE_TWIN_MULT is set when CC_SMALL_CODE is unset.
//
// When would we set CCEC_USE_TWIN_MULT and CC_SMALL_CODE at the same
// time? It's possible we would do this when only public-key
// operations (i.e. verification) are required. Although this does
// increase code size by 1.5-2k, it is significantly faster. This may
// be enabled manually in configuration on a per-target basis by
// setting CCEC_VERIFY_ONLY. CCEC_USE_TWIN_MULT should not be set
// directly.

#define CCEC_USE_TWIN_MULT (!CC_SMALL_CODE || CCEC_VERIFY_ONLY)

#define CCEC_DEBUG 0

/* Low level ec functions and types. */

/* Declare storage for a projected or affine point respectively. */
#define ccec_point_ws(_n_)                 (3 * (_n_))
#define ccec_point_size_n(_cp_)            (3 * ccec_cp_n(_cp_))
#define ccec_point_sizeof(_cp_)            ccn_sizeof_n(ccec_point_size_n(_cp_))
#define ccec_point_decl_cp(_cp_, _name_)   cc_ctx_decl(struct ccec_projective_point, ccec_point_sizeof(_cp_), _name_)
#define ccec_point_clear_cp(_cp_, _name_)  cc_clear(ccec_point_sizeof(_cp_), _name_)
#define ccec_point_sizeof_n(_n_)           ccn_sizeof_n(3 * (_n_))

#define ccec_affine_decl_cp(_cp_, _name_)  cc_ctx_decl(struct ccec_affine_point, 2 * ccec_ccn_size(_cp_), _name_)
#define ccec_affine_clear_cp(_cp_, _name_) cc_clear(2 * ccec_ccn_size(_cp_), _name_)

/* Macros for accessing X and Y in an ccec_affine_point and X Y and Z in
   an ccec_projective_point. */

#define ccec_const_point_x(EP, _cp_)  ((const cc_unit *)((EP)->xyz + ccec_cp_n(_cp_) * 0))
#define ccec_const_point_y(EP, _cp_)  ((const cc_unit *)((EP)->xyz + ccec_cp_n(_cp_) * 1))
#define ccec_const_point_z(EP, _cp_)  ((const cc_unit *)((EP)->xyz + ccec_cp_n(_cp_) * 2))

#define ccec_point_x(EP, _cp_)  ((EP)->xyz + ccec_cp_n(_cp_) * 0)
#define ccec_point_y(EP, _cp_)  ((EP)->xyz + ccec_cp_n(_cp_) * 1)
#define ccec_point_z(EP, _cp_)  ((EP)->xyz + ccec_cp_n(_cp_) * 2)

// Function pointers for overridable ccec functions.
struct ccec_funcs {
    __CCZP_FUNCS_DECLARATIONS(cczp_funcs)

    // Convert to projective coordinates.
    int (*CC_SPTR(ccec_funcs, ccec_projectify))(cc_ws_t ws,
                                                ccec_const_cp_t cp,
                                                ccec_projective_point_t r,
                                                ccec_const_affine_point_t s,
                                                struct ccrng_state *rng);
    // Convert to affine coordinates.
    int (*CC_SPTR(ccec_funcs, ccec_affinify))(cc_ws_t ws,
                                              ccec_const_cp_t cp,
                                              ccec_affine_point_t r,
                                              ccec_const_projective_point_t s);
    // Full point addition.
    void (*CC_SPTR(ccec_funcs, ccec_full_add))(cc_ws_t ws,
                                               ccec_const_cp_t cp,
                                               ccec_projective_point_t r,
                                               ccec_const_projective_point_t s,
                                               ccec_const_projective_point_t t);
    // Scalar multiplication.
    int (*CC_SPTR(ccec_funcs, ccec_mult))(cc_ws_t ws,
                                          ccec_const_cp_t cp,
                                          ccec_projective_point_t r,
                                          const cc_unit *d,
                                          size_t dbitlen,
                                          ccec_const_projective_point_t s);
};

typedef const struct ccec_funcs *ccec_funcs_t;

#define CCEC_FUNCS(CP) ((ccec_funcs_t)(CP)->funcs)
#define CCEC_FUNCS_GET(CP, NAME) (CCEC_FUNCS(CP)->NAME)

#define CCEC_FUNCS_DEFAULT_DEFINITIONS              \
    .ccec_projectify = ccec_projectify_jacobian_ws, \
    .ccec_affinify = ccec_affinify_jacobian_ws,     \
    .ccec_full_add = ccec_full_add_default_ws,      \
    .ccec_mult = ccec_mult_default_ws

// Default implementations for ccec function pointers.
int ccec_affinify_jacobian_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_affine_point_t r, ccec_const_projective_point_t s);
int ccec_projectify_jacobian_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_projective_point_t r, ccec_const_affine_point_t s, struct ccrng_state *masking_rng);
int ccec_mult_default_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_projective_point_t r, const cc_unit *d, size_t dbitlen, ccec_const_projective_point_t s);
void ccec_full_add_default_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_projective_point_t r, ccec_const_projective_point_t s, ccec_const_projective_point_t t);

/* Macro to define a struct for a ccec_cp of _n_ units. This is
   only to be used for static initializers of curve parameters.
   Note that _n_ is evaluated multiple times. */
#define ccec_cp_decl_n(_n_) struct { \
    struct cczp_hd hp;               \
    cc_unit p[(_n_)];                \
    cc_unit p0inv;                   \
    cc_unit pr2[(_n_)];              \
    cc_unit b[(_n_)];                \
    cc_unit gx[(_n_)];               \
    cc_unit gy[(_n_)];               \
    struct cczp_hd hq;               \
    cc_unit q[(_n_)];                \
    cc_unit q0inv;                   \
    cc_unit qr2[(_n_)];              \
}

/* Macro to define a struct for a ccec_cp of _bits_ bits. This is
   only to be used for static initializers of curve parameters. */
#define ccec_cp_decl(_bits_) ccec_cp_decl_n(ccn_nof(_bits_))

// Workspace helpers.
#define CCEC_ALLOC_PUB_WS(ws, n) (ccec_pub_ctx_t)CC_ALLOC_WS(ws, ccec_pub_ctx_ws(n))
#define CCEC_ALLOC_FULL_WS(ws, n) (ccec_full_ctx_t)CC_ALLOC_WS(ws, ccec_full_ctx_ws(n))
#define CCEC_ALLOC_POINT_WS(ws, n) (ccec_projective_point *)CC_ALLOC_WS(ws, ccec_point_ws(n))

// P-224 cczp function pointers.
CC_WARN_RESULT CC_NONNULL_ALL
int ccn_p224_sqrt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

CC_NONNULL_ALL
void ccn_p224_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

// P-256 cczp function pointers.
CC_NONNULL_ALL
void ccn_p256_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

// P-384 cczp function pointers.
CC_NONNULL_ALL
void ccn_p384_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

// EC parameters using smaller, generic field arithmetic functions.
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_224_c(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_224_asm(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_224_small_asm(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_256_c(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_256_asm(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_256_small(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_384_c(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_384_asm(void);
CC_WARN_RESULT CC_CONST ccec_const_cp_t ccec_cp_384_small(void);

/*! @function ccec_projectify_ws
 @abstract Convert a point represented by affine coordinates to
           projective, randomized coordinates.

 @param ws  Workspace.
 @param cp  Curve parameters.
 @param r   The resulting projective point R.
 @param s   The affine input point S.
 @param rng RNG for randomization (optional).
*/
CC_WARN_RESULT CC_NONNULL((1, 2, 3, 4))
int ccec_projectify_ws(cc_ws_t ws,
                       ccec_const_cp_t cp,
                       ccec_projective_point_t r,
                       ccec_const_affine_point_t s,
                       struct ccrng_state *rng);

/*! @function ccec_projectify_homogeneous_ws
 @abstract Convert a point represented by affine coordinates to standard
           projective (homogeneous) coordinates (X/Z,Y/Z) with Z randomized.

 @param ws  Workspace.
 @param cp  Curve parameters.
 @param r   The resulting projective point R.
 @param s   The affine input point S.
 @param rng RNG to generate a random Z (optional).
*/
CC_WARN_RESULT CC_NONNULL((1, 2, 3, 4))
int ccec_projectify_homogeneous_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   ccec_projective_point_t r,
                                   ccec_const_affine_point_t s,
                                   struct ccrng_state *rng);

/*! @function ccec_affinify_ws
 @abstract Convert a point represented by projective randomized coordinates
           to affine coordinates.

 @param ws  Workspace.
 @param cp  Curve parameters.
 @param r   The resulting affine point R.
 @param s   The projective input point S.
*/
CC_WARN_RESULT CC_NONNULL_ALL
int ccec_affinify_ws(cc_ws_t ws,
                     ccec_const_cp_t cp,
                     ccec_affine_point_t r,
                     ccec_const_projective_point_t s);

/*! @function ccec_affinify_homogeneous_ws
 @abstract Convert a point represented by standard projective (homogeneous)
           coordinates (X/Z,Y/Z) to affine coordinates.

 @param ws  Workspace.
 @param cp  Curve parameters.
 @param r   The resulting affine point R.
 @param s   The projective input point S.
*/
CC_WARN_RESULT CC_NONNULL_ALL
int ccec_affinify_homogeneous_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_affine_point_t r,
                                 ccec_const_projective_point_t s);

/* accept a projective point S and output the x coordinate only of its affine representation. */
CC_WARN_RESULT
int ccec_affinify_x_only(ccec_const_cp_t cp, cc_unit* sx, ccec_const_projective_point_t s);

CC_WARN_RESULT
int ccec_affinify_x_only_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *sx,
                            ccec_const_projective_point_t s);

/*
 @function   ccec_affinify_points_ws
 @abstract   Compute the affine representation of multiple points simultaneously.

 @param      ws       Workspace
 @param      cp       Curve parameter
 @param      npoints  Number of elliptic curve points
 @param      t        Output buffer of affine points
 @param      s        Input buffer of projective points
 @returns    CCERR_OK if no error, an error code otherwise
 */
CC_WARN_RESULT
int ccec_affinify_points_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_size npoints, ccec_affine_point_t *t, ccec_projective_point_t const* s);

/* Take an x coordinate and recompute the corresponding point. No particular convention for y.  */
CC_WARN_RESULT
int ccec_affine_point_from_x_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_affine_point_t r, const cc_unit *x);

/* Return true if the point is on the curve. Requires curve with a=-3 */
/* Z must be initialized. Set to 1 for points in affine representation */
CC_WARN_RESULT
bool ccec_is_point(ccec_const_cp_t cp, ccec_const_projective_point_t s);

CC_WARN_RESULT
bool ccec_is_point_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_const_projective_point_t s);

// Returns true if the point is the point at infinity
CC_WARN_RESULT
bool ccec_is_point_at_infinity(ccec_const_cp_t cp, ccec_const_projective_point_t s);

/* accept an affine point S = (Sx,Sy) and return true if it is on the curve, (i.e., if SY2 = SX3 − 3SX.SZ^4 + bSZ^6 (mod p)), otherwise return false. */
CC_WARN_RESULT
bool ccec_is_point_projective_ws(cc_ws_t ws, ccec_const_cp_t cp,
                                 ccec_const_projective_point_t s);

/* Validate the affine point with respect to the curve information */
CC_WARN_RESULT
int ccec_validate_point_and_projectify_ws(cc_ws_t ws,
                                        ccec_const_cp_t cp,
                                        ccec_projective_point_t r,
                                        ccec_const_affine_point_t public_point,
                                        struct ccrng_state *masking_rng);

/* Validate the private scalar with respect to the curve information */
CC_WARN_RESULT
int ccec_validate_scalar(ccec_const_cp_t cp, const cc_unit* k);

/*
 @function   ccec_double_ws
 @abstract   Computes R := 2 * S, with no constraints on S.

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      r        Projective output point
 @param      s        Projective input point
 */
void ccec_double_ws(cc_ws_t ws,
                    ccec_const_cp_t cp,
                    ccec_projective_point_t r,
                    ccec_const_projective_point_t s);

/*
 @function   ccec_full_add_ws
 @abstract   Computes R := S + T, with no constraints on either S or T.

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      r        Projective output point
 @param      s        First projective input point
 @param      t        Second projective input point
 */
void ccec_full_add_ws(cc_ws_t ws,
                      ccec_const_cp_t cp,
                      ccec_projective_point_t r,
                      ccec_const_projective_point_t s,
                      ccec_const_projective_point_t t);

/*
 @function   ccec_full_sub_ws
 @abstract   Computes R := S - T, with no constraints on either S or T.

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      r        Projective output point
 @param      s        First projective input point
 @param      t        Second projective input point
 */
void ccec_full_sub_ws(cc_ws_t ws,
                      ccec_const_cp_t cp,
                      ccec_projective_point_t r,
                      ccec_const_projective_point_t s,
                      ccec_const_projective_point_t t);

/*
 @function   ccec_full_add_normalized_ws
 @abstract   Computes R := S + T, requires T ≠ O and z(T) = 1.

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      r        Projective output point
 @param      s        First projective input point
 @param      t        Second projective input point
 */
CC_NONNULL_ALL
void ccec_full_add_normalized_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_projective_point_t r,
                                 ccec_const_projective_point_t s,
                                 ccec_const_projective_point_t t);

/*
 @function   ccec_full_sub_normalized_ws
 @abstract   Computes R := S - T, requires T ≠ O and z(T) = 1.

 @param      ws       Workspace
 @param      cp       Curve parameters
 @param      r        Projective output point
 @param      s        First projective input point
 @param      t        Second projective input point
 */
CC_NONNULL_ALL
void ccec_full_sub_normalized_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 ccec_projective_point_t r,
                                 ccec_const_projective_point_t s,
                                 ccec_const_projective_point_t t);

/*
 @function   ccec_add_normalized_ws
 @abstract   Computes R := S + T (or S - T).
             Requires S ≠ O, T ≠ O, and z(T) = 1.

 @discussion S and T must be two distinct, non-infinite, projective points.
             T must be a normalized point with its z-coordinate equal to 1.
             Cost: 4S + 12M + 10add/sub + 1div2.

 @param      ws        Workspace
 @param      cp        Curve parameters
 @param      r         Projective output point
 @param      s         First projective input point
 @param      t         Second projective input point
 @param      negate_t  Whether to negate T before adding to S.
 */
CC_NONNULL_ALL
void ccec_add_normalized_ws(cc_ws_t ws,
                            ccec_const_cp_t cp,
                            ccec_projective_point_t r,
                            ccec_const_projective_point_t s,
                            ccec_const_projective_point_t t,
                            bool negate_t);

/*!
 @function   ccec_mult_blinded_ws
 @abstract   Blinded scalar multiplication, r := d * S.

 @discussion Uses Euclidean scalar splitting to compute
             r := ⌊d / mask⌋ * mask * S + (d mod mask) * S,
             where mask is a random 32-bit mask.

 @param      ws          Workspace
 @param      cp          Curve parameter
 @param      R           Output point d * S
 @param      d           Scalar d (bitlen(d) must be <= bitlen(q))
 @param      S           Input point in Jacobian projective representation
 */
int ccec_mult_blinded_ws(cc_ws_t ws,
                         ccec_const_cp_t cp,
                         ccec_projective_point_t R,
                         const cc_unit *d,
                         ccec_const_projective_point_t S,
                         struct ccrng_state *rng);

/*!
 @function   ccec_mult_ws
 @abstract   Scalar multiplication, r := d * S.

 @discussion Runs in constant time, dependent on dbitlen.

             DO NOT USE when the scalar d is secret (and not blinded).

 @param      ws          Workspace
 @param      cp          Curve parameter
 @param      r           Output point d.s
 @param      d           Scalar d
 @param      dbitlen     Bit length of scalar d (must be <= bitlen(q))
 @param      s           Input point in Jacobian projective representation
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccec_mult_ws(cc_ws_t ws,
                 ccec_const_cp_t cp,
                 ccec_projective_point_t r,
                 const cc_unit *d,
                 size_t dbitlen,
                 ccec_const_projective_point_t s);

/* accept two projective points S, T , two integers 0 ≤ d0, d1 < p, and set R equal to the projective point d0S + d1T. */
CC_WARN_RESULT
int ccec_twin_mult(ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   const cc_unit *d0,
                   ccec_const_projective_point_t s,
                   const cc_unit *d1,
                   ccec_const_projective_point_t t);

CC_WARN_RESULT
int ccec_twin_mult_ws(cc_ws_t ws,
                      ccec_const_cp_t cp,
                      ccec_projective_point_t r,
                      const cc_unit *d0,
                      ccec_const_projective_point_t s,
                      const cc_unit *d1,
                      ccec_const_projective_point_t t);

/* Debugging */
void ccec_alprint(ccec_const_cp_t cp, const char *label, ccec_const_affine_point_t s);
void ccec_plprint(ccec_const_cp_t cp, const char *label, ccec_const_projective_point_t s);

void ccec_print_cp(ccec_const_cp_t cp);
void ccec_print_scalar(ccec_const_cp_t cp, const char *label, cc_unit const* scalar);
void ccec_print_affine_point(ccec_const_cp_t cp, const char *label, ccec_const_affine_point_t p);
void ccec_print_projective_point_ws(cc_ws_t ws, ccec_const_cp_t cp, const char *label, ccec_const_projective_point_t p);
void ccec_print_projective_point(ccec_const_cp_t cp, const char *label, ccec_const_projective_point_t p);

void ccec_print_sig(const char *label, size_t count, const uint8_t *s);

/*
 * EC key generation
 */
CC_WARN_RESULT
int ccec_generate_scalar_fips_retry_ws(cc_ws_t ws, ccec_const_cp_t cp, struct ccrng_state *rng, cc_unit *k);

/*!
 @function   ccec_generate_scalar_legacy
 @abstract   Generate a random scalar k (private key) with legacy method

 @param      cp             Curve parameters
 @param      entropy_nbytes Byte length of entropy
 @param      entropy        Entropy for the scalar k
 @param      k              scalar of size ccec_cp_n(cp)
 @returns    CCERR_OK if no error, an error code otherwise.

 @warning    These functions are only used for legacy purpose, to reconstruct existing keys, as the behavior cannot be changed.
             These functions MUST NOT be used in new applications.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_generate_scalar_legacy(ccec_const_cp_t cp, size_t entropy_nbytes, const uint8_t *entropy, cc_unit *k);

CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_generate_scalar_legacy_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t entropy_nbytes, const uint8_t *entropy, cc_unit *k);

/*!
 @function   ccec_generate_scalar_fips_extrabits
 @abstract   Generate a random scalar k (private key) per FIPS methodology
        Slower than the "TestingCandidates" method
 Behavior can not be changed

 @param      cp             Curve parameters
 @param      entropy_len    Byte length of entropy
                            Minimum: ccec_scalar_fips_extrabits_min_entropy_len(cp)
                            Maximum: 2*byte length of order of cp
 @param      entropy        Entropy for the scalar k
 @param      k              scalar of size ccec_cp_n(cp)
 @returns    0 if no error, an error code otherwise.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_generate_scalar_fips_extrabits(ccec_const_cp_t cp,
                                        size_t entropy_len,
                                        const uint8_t *entropy,
                                        cc_unit *k);

CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_generate_scalar_fips_extrabits_ws(cc_ws_t ws,
                                           ccec_const_cp_t cp,
                                           size_t entropy_len,
                                           const uint8_t *entropy,
                                           cc_unit *k);

/*!
 @function   ccec_scalar_fips_extrabits_min_entropy_len
 @abstract   Return the minimum size of the entropy to be passed to
        ccec_generate_scalar_fips_extrabits

 @param      cp             Curve parameters
 @returns    minimal value for entropy_len
 */
CC_WARN_RESULT
size_t ccec_scalar_fips_extrabits_min_entropy_len(ccec_const_cp_t cp);

/*!
 @function   ccec_make_pub_from_priv
 @abstract   The public key from the input scalar k (private key)
         This internal function does not perform the consistent check
         Which guarantees that the key is valid.
 @param      cp             Curve parameters
 @param      masking_rng    For internal countermeasures
 @param      k              scalar of size ccec_cp_n(cp), in range [1..q-1] and with no statistical bias.
 @param      key            Resulting public key
 @param      generator      Generator point / NULL if default
 @returns    0 if no error, an error code otherwise.
 */
CC_WARN_RESULT
int ccec_make_pub_from_priv(ccec_const_cp_t cp,
                            struct ccrng_state *masking_rng,
                            const cc_unit *k,
                            ccec_const_affine_point_t generator,
                            ccec_pub_ctx_t key);

CC_WARN_RESULT
int ccec_make_pub_from_priv_ws(cc_ws_t ws,
                               ccec_const_cp_t cp,
                               struct ccrng_state *masking_rng,
                               const cc_unit *k,
                               ccec_const_affine_point_t generator,
                               ccec_pub_ctx_t key);

/*!
 @function   ccec_generate_key_internal_legacy_ws
 @abstract   Generate key pair for compatiblity purposes or deterministic keys
            NOT RECOMMENDED. This internal function does not perform the consistent check
            Which guarantees that the key is valid.

 @param      ws     Workspace
 @param      cp     Curve parameters
 @param      rng    For internal countermeasures
 @param      key    Resulting key pair

 @returns    0 if no error, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccec_generate_key_internal_legacy_ws(cc_ws_t ws,
                                         ccec_const_cp_t cp,
                                         struct ccrng_state *rng,
                                         ccec_full_ctx_t key);

/*!
 @function   ccec_generate_key_fips_ws

 @abstract   Guarantees FIPS compliant key pair. RECOMMENDED
             Use a non deterministic amount of random bytes

 @param      ws        Workspace
 @param      cp        Curve Parameters
 @param      rng       Random for the key generation as well as consistency signature
 @param      key       Full key containing the newly generated key pair

 @return    CCERR_OK if no error, an error code otherwise.
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccec_generate_key_fips_ws(cc_ws_t ws, ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key);

/* FIPS compliant and more secure */
/*!
 @function   ccec_generate_key_internal_fips
 @abstract   Follows FIPS guideline and more secure.
    This internal function does not perform the consistent check
    which guarantees that the key is valid (required by FIPS).
 @param      cp      Curve parameters
 @param      rng     key generation and internal countermeasures
 @param      key     Resulting key pair
 @return     0 if no error, an error code otherwise.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_generate_key_internal_fips(ccec_const_cp_t cp,
                                    struct ccrng_state *rng,
                                    ccec_full_ctx_t key);

CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_generate_key_internal_fips_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       struct ccrng_state *rng,
                                       ccec_full_ctx_t key);

/*!
 @function   ccec_generate_key_deterministic_ws

 @abstract   Generate a key pair from the provided entropy buffer.
             Requires cryptographic DRBG/KDF prior to calling.

 @param      ws             Workspace
 @param      cp             Curve Parameters
 @param      entropy_len    Length in byte of the entropy buffer
 @param      entropy        Pointer to the entropy buffer of size entropy_len
 @param      rng            Real random for the signature and internal countermeasures
 @param      flags          Bitmask: options as explained below
 @param      key            Full key containing the newly generated key pair

 @return    CCERR_OK if no error, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccec_generate_key_deterministic_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       size_t entropy_len,
                                       const uint8_t *entropy,
                                       struct ccrng_state *rng,
                                       uint32_t flags,
                                       ccec_full_ctx_t key);

/*!
 @function   ccec_pairwise_consistency_check_ws
 @abstract   Performs a sign/verify roundtrip to check a given EC key pair
             for consistency.

 @param      ws        Workspace
 @param      full_key  EC key pair to check
 @param      rng       For blinding and random values

 @returns    0 if no error, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccec_pairwise_consistency_check_ws(cc_ws_t ws,
                                       ccec_full_ctx_t full_key,
                                       struct ccrng_state *rng);

/*!
 @function   ccecdh_pairwise_consistency_check
 @abstract   Does a DH with a constant key to confirm the newly generated key is
    correct.
 @param      full_key            Resulting key pair
 @param      base           Base point (Pass NULL for generator)
 @param      rng            For key generation and internal countermeasures
 @returns    0 if no error, an error code otherwise.
 */
CC_WARN_RESULT
CC_NONNULL((1, 3))
int ccecdh_pairwise_consistency_check(ccec_full_ctx_t full_key,
                                      ccec_const_affine_point_t base,
                                      struct ccrng_state *rng);

CC_WARN_RESULT
CC_NONNULL((1, 2, 4))
int ccecdh_pairwise_consistency_check_ws(cc_ws_t ws,
                                         ccec_full_ctx_t full_key,
                                         ccec_const_affine_point_t base,
                                         struct ccrng_state *rng);

/*
 * EC Digital Signature - ECDSA
 */

/*!
 @function   ccec_verify_msg_ws

 @abstract   Verify a DER encoded signature given an input message.

 @param      ws                 Workspace
 @param      key                EC Public Key
 @param      di                 Hash context
 @param      msg_len            Length of message
 @param      msg                Message buffer
 @param      sig_len            Length of signature
 @param      sig                Signature buffer
 @param      fault_canary_out   OPTIONAL cc_fault_canary_t

 @return     CCERR_VALID_SIGNATURE if the signature is valid.
             Any other return code represents an invalid signature.
*/
CC_WARN_RESULT
CC_NONNULL((1, 2, 3, 5, 7))
int ccec_verify_msg_ws(cc_ws_t ws,
                       ccec_pub_ctx_t key,
                       const struct ccdigest_info *di,
                       size_t msg_len,
                       const uint8_t *msg,
                       size_t sig_len,
                       const uint8_t *sig,
                       cc_fault_canary_t fault_canary_out);

/*!
 @function   ccec_verify_internal_ws
 @abstract   ECDSA signature verification, writing to fault_canary_out.

 @param      ws                 Workspace
 @param      key                Public key
 @param      digest_len         Byte length of the digest
 @param      digest             Pointer to the digest
 @param      r                  Pointer to input buffer for r
 @param      s                  Pointer to input buffer for s
 @param      fault_canary_out   Output of type cc_fault_canary_t
 in big-endian format.

 @returns    CCERR_VALID_SIGNATURE if signature is valid.
            CCERR_INVALID_SIGNATURE if signature is invalid.
            Other error codes indicating verification failure.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_verify_internal_ws(cc_ws_t ws,
                            ccec_pub_ctx_t key,
                            size_t digest_len,
                            const uint8_t *digest,
                            const cc_unit *r,
                            const cc_unit *s,
                            cc_fault_canary_t fault_canary_out);

/*!
 @function   ccec_verify_internal_with_base_ws
 @abstract   Same as ccec_verify_internal_ws(), but allows passing a custom
             base point or generator. Used for testing.
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccec_verify_internal_with_base_ws(cc_ws_t ws,
                                      ccec_pub_ctx_t key,
                                      size_t digest_len,
                                      const uint8_t *digest,
                                      const cc_unit *r,
                                      const cc_unit *s,
                                      ccec_const_affine_point_t base,
                                      cc_fault_canary_t fault_canary_out);

/*!
 @function   ccec_extract_rs_ws

 @abstract   Extract the r and/or s components from a signature.

 @param      ws       Workspace
 @param      key      Public EC key
 @param      sig_len  Length of the signature buffer
 @param      sig      Input signature buffer
 @param      r        Optional output buffer of size ccec_signature_r_s_size(key)
 @param      s        Optional output buffer of size ccec_signature_r_s_size(key)

 @discussion Either `r` or `s` may be NULL and will not be output when this is the case.

 @return     CCERR_OK if no error, an error code otherwise.
*/
CC_WARN_RESULT
CC_NONNULL((1, 2, 4))
int ccec_extract_rs_ws(cc_ws_t ws,
                       ccec_pub_ctx_t key,
                       size_t sig_len,
                       const uint8_t *sig,
                       uint8_t *r,
                       uint8_t *s);

/*!
 @function   ccec_sign_msg_ws
 @abstract   Given a message, compute its digest using the provided hash
             algorithm and sign it, returning the signature in DER format.

 @param      ws       Workspace
 @param      key      Full EC key
 @param      di       Hash context
 @param      msg_len  Input message length
 @param      msg      Message buffer
 @param      sig_len  Length of signature buffer (must be initialized with the length of the output signature buffer)
 @param      sig      Output signature buffer
 @param      rng      RNG handle for internal countermeasures

 @return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int ccec_sign_msg_ws(cc_ws_t ws,
                     ccec_full_ctx_t key,
                     const struct ccdigest_info *di,
                     size_t msg_len,
                     const uint8_t *msg,
                     size_t *sig_len,
                     uint8_t *sig,
                     struct ccrng_state *rng);

/*!
 @function   ccec_sign_internal_ws
 @abstract   ECDSA signature creation.
 @param      ws             Workspace
 @param      key            Public key
 @param      digest_len     Byte length of the digest
 @param      digest         Pointer to the digest
 @param      r              Pointer to output buffer for r
 @param      s              Pointer to output buffer for s
 @param      rng            RNG
 @returns    0 if no error, an error code otherwise.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_sign_internal_ws(cc_ws_t ws,
                          ccec_full_ctx_t key,
                          size_t digest_len,
                          const uint8_t *digest,
                          cc_unit *r,
                          cc_unit *s,
                          struct ccrng_state *rng);

/*!
 @function   ccec_sign_internal_inner_ws
 @abstract   Inner loop of ECDSA signature creation.
             Computes r := x(k * G) (mod q) and
                      s := (e + xr)k^-1 (mod q).

 @param      ws   Workspace.
 @param      cp   Curve parameters.
 @param      e    H(msg) (mod q).
 @param      x    Private signing key x.
 @param      k    Ephemeral key k.
 @param      G    Base point G.
 @param      m    Multiplicative mask m.
 @param      r    Pointer to output buffer for r.
 @param      s    Pointer to output buffer for s.
 @param      rng  RNG

 @returns    0 if no error, an error code otherwise.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_sign_internal_inner_ws(cc_ws_t ws,
                                ccec_const_cp_t cp,
                                const cc_unit *e,
                                const cc_unit *x,
                                const cc_unit *k,
                                ccec_const_projective_point_t G,
                                const cc_unit *m,
                                cc_unit *r,
                                cc_unit *s,
                                struct ccrng_state *rng);

/*!
 @function   ccec_diversify_twin_scalars
 @abstract   Derives to scalars u,v from the given entropy.

 entropy_len must be a multiple of two, greater or equal to
 2 * ccec_diversify_min_entropy_len(). The entropy must be
 chosen from a uniform distribution, e.g. random bytes,
 the output of a DRBG, or the output of a KDF.

 @param  ws          Input:  Workspace
 @param  cp          Input:  Curve parameters
 @param  u           Output: Scalar u
 @param  v           Output: Scalar v
 @param  entropy_len Input:  Length of entropy
 @param  entropy     Input:  Entropy used to derive scalars u,v

 @result 0 iff successful

 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_diversify_twin_scalars_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   cc_unit *u,
                                   cc_unit *v,
                                   size_t entropy_len,
                                   const uint8_t *entropy);

/*
 * RFC6637 wrap/unwrap
 */

#define ccec_rfc6637_ecdh_public_key_id    18
#define ccec_rfc6637_ecdsa_public_key_id   19

#define ccpgp_digest_sha256            8
#define ccpgp_digest_sha384            9
#define ccpgp_digest_sha512            10

#define ccpgp_cipher_aes128            7
#define ccpgp_cipher_aes192            8
#define ccpgp_cipher_aes256            9

struct ccec_rfc6637 {
    const char *name;
    const uint8_t kdfhash_id;
    const struct ccdigest_info * (*CC_SPTR(ccec_rfc6637, difun))(void);
    const uint8_t kek_id;
    const size_t keysize;
};

struct ccec_rfc6637_curve {
    const uint8_t *curve_oid;
    uint8_t public_key_alg;
};

extern const struct ccec_rfc6637 ccec_rfc6637_sha256_kek_aes128;
extern const struct ccec_rfc6637 ccec_rfc6637_sha512_kek_aes256;

void
ccec_rfc6637_kdf(const struct ccdigest_info *di,
                 const struct ccec_rfc6637_curve *curve,
                 const struct ccec_rfc6637 *wrap,
                 size_t epkey_size, const void *epkey,
                 size_t fingerprint_size, const void *fingerprint,
                 void *hash);

CC_WARN_RESULT
size_t
ccec_rfc6637_wrap_pub_size(ccec_pub_ctx_t public_key,
                           unsigned long flags);

CC_NONNULL_ALL CC_WARN_RESULT
int ccec_rfc6637_wrap_core_ws(cc_ws_t ws,
                              ccec_pub_ctx_t public_key,
                              ccec_full_ctx_t ephemeral_key,
                              void *wrapped_key,
                              unsigned long flags,
                              uint8_t symm_alg_id,
                              size_t key_len,
                              const void *key,
                              const struct ccec_rfc6637_curve *curve,
                              const struct ccec_rfc6637_wrap *wrap,
                              const uint8_t *fingerprint,
                              struct ccrng_state *rng);

CC_WARN_RESULT
uint16_t
pgp_key_checksum(size_t key_len, const uint8_t *key);

/*!
 @function   ccec_verify_strict
 @abstract   ECDSA signature verification using strict parsing DER signature.
 @param      key         Public key
 @param      digest_len  Byte length of the digest
 @param      digest      Pointer to the digest
 @param      sig_len     Byte length of the signature
 @param      sig         Pointer to signature
 @param      valid       Pointer to output boolean.
 *valid=true if the input {r,s} is valid.
 @returns    0 if no error, an error code otherwise.
 */
CC_WARN_RESULT
int ccec_verify_strict(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                       size_t sig_len, const uint8_t *sig, bool *valid);

CC_WARN_RESULT
int ccecdh_compute_shared_secret_ws(cc_ws_t ws,
                                    ccec_full_ctx_t private_key,
                                    ccec_pub_ctx_t public_key,
                                    size_t *computed_shared_secret_len,
                                    uint8_t *computed_shared_secret,
                                    struct ccrng_state *masking_rng);

/*!
 @function   ccec_validate_pub_ws
 @abstract   Perform validation of the public key

 @param ws   Workspace
 @param key  Public Key

 @returns    0 if the public key is valid, an error code otherwise.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_validate_pub_ws(cc_ws_t ws, ccec_pub_ctx_t key);

/*!
 @function   ccecdh_generate_key_ws
 @abstract   Key generation per FIPS186-4, used for ephemeral ECDH key pairs.
             Performs an ECDH consistency check.
 @param      ws             Workspace
 @param      cp             Curve parameters
 @param      rng            For key generation and internal countermeasures
 @param      key            Resulting key pair
 @return    CCERR_OK if no error, an error code otherwise.
 */
CC_WARN_RESULT
CC_NONNULL_ALL
int ccecdh_generate_key_ws(cc_ws_t ws, ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key);



#pragma mark-- Import / Export

/*!
 @function   ccec_import_affine_point
 @abstract   Import an affine point encoded with a specific format
 @param      ws             The workspace
 @param      cp             Curve parameters
 @param      format         The encoding format of the affine point
 @param      in_nbytes      The size of the input buffer
 @param      in             The input buffer
 @param      point          A pointer to the affine point
 @return     CCERR_OK if no error, an error code otherwise
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccec_import_affine_point_ws(cc_ws_t ws, ccec_const_cp_t cp, int format, size_t in_nbytes, const uint8_t *in, ccec_affine_point_t point);

CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_compact_import_pub_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_compressed_x962_import_pub_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_import_pub_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

CC_WARN_RESULT
CC_NONNULL_ALL
int ccec_x963_import_pub_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

/*!
 @function   ccec_compact_transform_key_ws

 @abstract   Follow instructions from https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
             to make a key compatible with the compact export format.

 @param      ws      Workspace
 @param      key     Input/Output full key
 */
CC_NONNULL_ALL
void ccec_compact_transform_key_ws(cc_ws_t ws, ccec_full_ctx_t key);

/*!
 @function   ccec_x963_import_priv_ws

 @abstract   Import the full key (private and public part of the key)
             with x9.63 format.

 @param      ws      Workspace
 @param      cp      Curve parameter
 @param      in_len  Byte length of the key to import
 @param      in      Key to import in x9.63 format
 @param      key     Output full key

 @return    CCERR_OK if no error, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccec_x963_import_priv_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key);

#pragma mark--Split key generation

#define ccec_generate_key_ctx_n(_key_) ((_key_)->n)
#define ccec_generate_key_ctx_state(_key_) ((_key_)->state)
#define ccec_generate_key_ctx_r(_key_) ((cc_unit *) (_key_)->ccn)
#define ccec_generate_key_ctx_s(_key_) ((cc_unit *) ((_key_)->ccn + (_key_)->n))
#define ccec_generate_key_ctx_fk(_key_) ((ccec_full_ctx_t) &(_key_)->ccn[2 * (_key_)->n])

enum {
    CCEC_GENERATE_KEY_START = 0,
    CCEC_GENERATE_KEY_COMPACT_TRANSFORM = 1,
    CCEC_GENERATE_KEY_SIGN = 2,
    CCEC_GENERATE_KEY_VERIFY = 3,
    CCEC_GENERATE_KEY_COMPLETE = 4,
};

/*!
 @function ccec_compact_generate_key_checksign_ws
 @param rng RNG for key generation
 @param key A `generate key` context.
 @return CCERR_OK if no error, an error code otherwise.
 @discussion This function is called by ccec_compact_generate_key_step.
 */
int ccec_compact_generate_key_checksign_ws(cc_ws_t ws, struct ccrng_state *rng, ccec_generate_key_ctx_t key);

/*!
 @function ccec_compact_generate_key_checkverify_and_extract_ws
 @param key A `generate key` context.
 @param fkey The output full key context
 @return CCERR_OK if no error, an error code otherwise.
 @discussion This function is called by ccec_compact_generate_key_step.
 */
int ccec_compact_generate_key_checkverify_and_extract_ws(cc_ws_t ws, ccec_generate_key_ctx_t key, ccec_full_ctx_t *fkey);

#endif /* _CORECRYPTO_CCEC_INTERNAL_H_ */
