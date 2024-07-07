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

#ifndef _CORECRYPTO_CCEC_PRIV_H_
#define _CORECRYPTO_CCEC_PRIV_H_

#include <corecrypto/ccec.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cczp.h>

/*!
@function   ccec_generate_blinding_keys
@abstract   Generate a blinding and unblinding key.
           unblinding_key * (blinding_key * A)) == A, where A is a public key.

@param      cp               Curve parameters
@param      rng              RNG instance
@param      blinding_key     Result ccec_full_ctx_t blinding key
@param      unblinding_key   Result ccec_full_ctx_t unblinding key
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL_ALL
int ccec_generate_blinding_keys(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t blinding_key, ccec_full_ctx_t unblinding_key);

/*!
@function   ccec_blind
@abstract   Blind an input public key
 
@param      rng              RNG instance
@param      blinding_key     ccec_full_ctx_t blinding key
@param      pub              Input public key to blind
@param      blinded_pub      Output blinded public key
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL_ALL
int ccec_blind(struct ccrng_state *rng, const ccec_full_ctx_t blinding_key, const ccec_pub_ctx_t pub, ccec_pub_ctx_t blinded_pub);

/*!
@function   ccec_unblind
@abstract   Unblind an input public key
 
@param      rng                RNG instance
@param      unblinding_key     ccec_full_ctx_t unblinding key
@param      pub                Input public key to unblind
@param      unblinded_pub      Output unblinded public key
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL_ALL
int ccec_unblind(struct ccrng_state *rng, const ccec_full_ctx_t unblinding_key, const ccec_pub_ctx_t pub, ccec_pub_ctx_t unblinded_pub);

/* Debugging */
void ccec_print_full_key(const char *label, ccec_full_ctx_t key);
void ccec_print_public_key(const char *label, ccec_pub_ctx_t key);

/*!
 @function   ccec_compact_transform_key
 @abstract   Follow instructions from https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
  to make a key compatible with the compact export format.
 @param      key     Input/Output full key
 @return    0 if no error, an error code otherwise.
 */
int ccec_compact_transform_key(ccec_full_ctx_t key);

/*!
 @function   ccec_is_compactable_pub
 @abstract   Outputs whether the public key is compactable as per
             https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 @param      key     Input public key (with affine coordinates)
 @return     true if compactable, false otherwise.
 */
CC_WARN_RESULT
bool ccec_is_compactable_pub(ccec_pub_ctx_t key);

//imports the x and y from the in array in big-endian, sets z to 1
CC_NONNULL((1, 3, 4))
int ccec_raw_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);
//imports the ecc private key k, and sets x an y to all ones.
CC_NONNULL((1, 3, 4))
int ccec_raw_import_priv_only(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key);

/*!
@function   ccec_extract_rs
@abstract   Extract the r and/or s components from a signature.
@param      key      Public EC key
@param      sig_len  Length of the signature buffer
@param      sig      Input signature buffer
@param      r        Optional output buffer of size ccec_signature_r_s_size(key)
@param      s        Optional output buffer of size ccec_signature_r_s_size(key)
@discussion Either `r` or `s` may be NULL and will not be output when this is the case.
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL((1,3))
int ccec_extract_rs(ccec_pub_ctx_t key, size_t sig_len, const uint8_t *sig, uint8_t *r, uint8_t *s);

#if CC_PRIVATE_CRYPTOKIT
/// Generates a scalar without bias, compliant with the FIPS-186-4 testing routing.
/// Returns CCERR_OK on success, error value otherwise.
/// @param cp Curve parameters
/// @param rng RNG instance
/// @param k Resulting scalar k
int ccec_generate_scalar_fips_retry(ccec_const_cp_t cp, struct ccrng_state *rng, cc_unit *k);

/// Performs addition r = s + t between two curve points in projective form.
/// Returns CCERR_OK on success, error value otherwise.
/// @param cp Curve parameters
/// @param r The resulting point
/// @param s Curve point of the addition operation
/// @param t Curve point of the addition operation
int ccec_full_add(ccec_const_cp_t cp,
                  ccec_projective_point_t r,
                  ccec_const_projective_point_t s,
                  ccec_const_projective_point_t t);

/// Performs subtraction r = s - t between two curve points in projective form.
/// Returns CCERR_OK on success, error value otherwise.
/// @param cp Curve parameters
/// @param r The resulting point
/// @param s Curve point of the subtraction operation
/// @param t Curve point of the subtraction operation
int ccec_full_sub(ccec_const_cp_t cp,
                  ccec_projective_point_t r,
                  ccec_const_projective_point_t s,
                  ccec_const_projective_point_t t);

/// Computes the multiplication of a scalar with a curve point (r = d*s)
/// Returns CCERR_OK on success, error value otherwise.
/// @param cp Curve parameters
/// @param r The result of the multiplication, in projective form
/// @param d A scalar in the following range 1 ≤ d < q
/// @param s The curve point being multiplied by the scalar, in projective form.
/// @param masking_rng Masking RNG instance
int ccec_mult_blinded(ccec_const_cp_t cp,
                      ccec_projective_point_t r,
                      const cc_unit *d,
                      ccec_const_projective_point_t s,
                      struct ccrng_state *masking_rng);

/// Projectifies an affine point.
/// Returns CCERR_OK on success, error value otherwise.
/// @param cp Curve parameters
/// @param r Resulting point with projective coordinates
/// @param s Affine point
/// @param masking_rng Masking RNG instance
int ccec_projectify(ccec_const_cp_t cp, ccec_projective_point_t r,
                    const ccec_const_affine_point_t s, struct ccrng_state *masking_rng);

/// Converts projective point into affine point.
/// Returns CCERR_OK on success, error value otherwise.
/// @param cp Curve parameters
/// @param r The resulting affine point
/// @param s The projective point
int ccec_affinify(ccec_const_cp_t cp, ccec_affine_point_t r, ccec_const_projective_point_t s);

#endif

#pragma mark--Import/export

// For all representations, the point at infinity is a single zero octet
enum {
    CCEC_FORMAT_UNCOMPRESSED = 1,  // ANSI X9.63: (04 || X || Y) and (04 || X || Y || K)
    CCEC_FORMAT_HYBRID = 2,        // ANSI X9.63: (NN || X || Y) and (NN || X || Y || K) with NN = 06 or 07
    CCEC_FORMAT_COMPRESSED = 3,    // ANSI X9.62: (NN || X) with NN = 02 or 03
    CCEC_FORMAT_COMPACT = 4,       // https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/: (X)
};

/*!
 @function   ccec_import_affine_point
 @abstract   Import an affine point encoded with a specific format
 @param      cp             Curve parameters
 @param      format         The encoding format of the affine point
 @param      in_nbytes      The size of the input buffer
 @param      in             The input buffer
 @param      point          A pointer to the affine point
 @return     CCERR_OK if no error, an error code otherwise
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccec_import_affine_point(ccec_const_cp_t cp, int format, size_t in_nbytes, const uint8_t *in, ccec_affine_point_t point);

/*!
 @function   ccec_export_affine_point
 @abstract   Export an affine point encoded with a specific format
 @param      cp             Curve parameters
 @param      format         The encoding format of the affine point
 @param      point          A pointer to the affine point
 @param      out_nbytes     The size of the output buffer (need to be initialized with the size of the buffer out, of size at least ccec_export_affine_point_size())
 @param      out            The output buffer
 @return     CCERR_OK if no error, an error code otherwise; *out_nbytes will be set to the size of the encoded point
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccec_export_affine_point(ccec_const_cp_t cp, int format, ccec_const_affine_point_t point, size_t *out_nbytes, uint8_t *out);

/*!
 @function   ccec_export_affine_point_size
 @abstract   Upper bound on the size of an affine point encoded with a specific format
 @param      cp             Curve parameters
 @param      format         The encoding format of the affine point
 @return     the size of the encoded point, or 0 in case of error.
 */
CC_NONNULL_ALL
size_t ccec_export_affine_point_size(ccec_const_cp_t cp, int format);

#pragma mark--Split key generation

// In some situations we want to allow generating a key in multiple steps.
// To do so safely we make make the full key context opaque to callers and
// only "release" it when all necessary function calls are made.

struct ccec_generate_key_ctx {
    cc_size n;
    uint8_t state;
    CC_ALIGNED(16) cc_unit ccn[];
};

typedef struct ccec_generate_key_ctx* ccec_generate_key_ctx_t;

/*!
 @function ccec_compact_generate_key_init
 @abstract Initialize compact key generation across multiple calls. See below for details.

 @param cp Curve Parameters
 @param rng RNG for key generation
 @param key A `generate key` context. Note that this context need not be initialized with `ccec_ctx_init`.

 @return CCERR_OK if no error, an error code otherwise.

 @discussion This is the first in a series of calls to generate a compact key. After initializing this context,
 `ccec_compact_generate_key_step` may be called multiple times until an error is returned OR the full key
 context is returned. See `ccec_compact_generate_key_step` for more details.
 */
int ccec_compact_generate_key_init(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_generate_key_ctx_t key);

/*!
 @function ccec_compact_generate_key_step
 @abstract Perform a single step of compact key generation.

 @param rng RNG for key generation
 @param key A `generate key` context initialized with `ccec_compact_generate_key_init`
 @param fullkey An ouptut key containing the generated compact key.

 @discussion Repeated calls to this function will perform the key generation steps. Each call will return `CCERR_OK` on success and a failure otherwise. Subsequent calls should NOT be made if an error is returned. The output parameter `fullkey` will be NULL until the key generation process is complete.
 */
int ccec_compact_generate_key_step(struct ccrng_state *rng, ccec_generate_key_ctx_t key, ccec_full_ctx_t *fullkey);

#define ccec_generate_key_ctx_size(_size_) (sizeof(struct ccec_generate_key_ctx) + ccec_full_ctx_size(_size_) + 2 * (_size_))

#define ccec_generate_key_ctx_decl_cp(_cp_, _name_) cc_ctx_decl(struct ccec_generate_key_ctx, ccec_generate_key_ctx_size(ccec_ccn_size(_cp_)), _name_)

#define ccec_generate_key_ctx_clear_cp(_cp_, _name_) cc_clear(ccec_generate_key_ctx_size(_cp_), _name_)

#endif /* _CORECRYPTO_CCEC_PRIV_H_ */
