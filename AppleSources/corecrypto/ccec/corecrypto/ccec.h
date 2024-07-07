/* Copyright (c) (2010-2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCEC_H_
#define _CORECRYPTO_CCEC_H_
#include <corecrypto/ccasn1.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_fault_canary.h>

CC_PTRCHECK_CAPABLE_HEADER()


/* An ec_point. A ccec_projective_point_t is a point with x,y and z.
   A ccec_affine_point_t only has x and y. */

struct ccec_projective_point {
    cc_unit xyz[1];
} CC_ALIGNED(8);
typedef struct ccec_projective_point ccec_projective_point;

// A structure for holding the curve parameters.
struct ccec_cp {
    __CCZP_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(CCN_UNIT_SIZE);

struct ccec_affine_point {
    cc_unit xyz[1];
} CC_ALIGNED(8);
typedef struct ccec_affine_point ccec_affine_point;
typedef ccec_projective_point* ccec_projective_point_t;
typedef ccec_affine_point* ccec_affine_point_t;

typedef const struct ccec_affine_point* ccec_const_affine_point_t;
typedef const struct ccec_projective_point* ccec_const_projective_point_t;

typedef const struct ccec_cp* ccec_const_cp_t;

/* Use ccec_full_ctx_decl to declare full ecc context */
struct ccec_full_ctx {
    ccec_const_cp_t cp;
    CC_ALIGNED(16) struct ccec_projective_point point[];
} CC_ALIGNED(16);

struct ccec_pub_ctx {
    ccec_const_cp_t cp;
    CC_ALIGNED(16) struct ccec_projective_point point[];
} CC_ALIGNED(16);

typedef struct ccec_full_ctx* ccec_full_ctx_t;
typedef struct ccec_pub_ctx* ccec_pub_ctx_t;
CC_INLINE ccec_pub_ctx_t ccec_ctx_public(ccec_full_ctx_t fk) {
    return (ccec_pub_ctx_t) fk;
}


/* Return the size of an ccec_full_ctx where each ccn is _size_ bytes. */
#define ccec_full_ctx_size(_size_)  (sizeof(struct ccec_full_ctx) + 4 * (_size_))
#define ccec_pub_ctx_size(_size_)   (sizeof(struct ccec_pub_ctx) + 3 * (_size_))

#define ccec_full_ctx_ws(_n_) ccn_nof_size(ccec_full_ctx_size(ccn_sizeof_n(_n_)))
#define ccec_pub_ctx_ws(_n_) ccn_nof_size(ccec_pub_ctx_size(ccn_sizeof_n(_n_)))

/* declare full and public context, when curve paramters cp are not known and will be assigned later*/
#define ccec_full_ctx_decl(_size_, _name_)  cc_ctx_decl(struct ccec_full_ctx, ccec_full_ctx_size(_size_), _name_)
#define ccec_full_ctx_clear(_size_, _name_) cc_clear(ccec_full_ctx_size(_size_), _name_)
#define ccec_pub_ctx_decl(_size_, _name_)   cc_ctx_decl(struct ccec_pub_ctx, ccec_pub_ctx_size(_size_), _name_)
#define ccec_pub_ctx_clear(_size_, _name_)  cc_clear(ccec_pub_ctx_size(_size_), _name_)

/* declare full and public context, when curve paramters cp are known */
#define ccec_full_ctx_decl_cp(_cp_, _name_)  ccec_full_ctx_decl(ccec_ccn_size(_cp_), _name_)
#define ccec_full_ctx_clear_cp(_cp_, _name_) ccec_full_ctx_clear(ccec_ccn_size(_cp_), _name_)
#define ccec_pub_ctx_decl_cp(_cp_, _name_)   ccec_pub_ctx_decl(ccec_ccn_size(_cp_), _name_)
#define ccec_pub_ctx_clear_cp(_cp_, _name_)  ccec_pub_ctx_clear(ccec_ccn_size(_cp_), _name_)

/* lvalue accessors to ccec_ctx fields. (only a ccec_full_ctx_t has K). */

    /* Callers must use this macro to initialze a ccec_full_ctx or
    ccec_pub_ctx before using most of the macros in this file. */
#define ccec_ctx_cp(KEY)     ((KEY)->cp)
#define ccec_ctx_init(_cp_, _key_) ((_key_)->cp = (_cp_))
#define ccec_ctx_point(KEY)  ((KEY)->point) // The public key as a projected point on the curve.
#define ccec_ctx_n(KEY)      (ccec_ctx_cp(KEY)->n) // Return count (n) of a ccn for cp.
#define ccec_ctx_prime(KEY)  (ccec_ctx_cp(KEY)->ccn)

CC_INLINE cc_size ccec_cp_n(ccec_const_cp_t cp) { return cp->n; }
CC_INLINE cczp_const_t ccec_cp_zp(ccec_const_cp_t cp){ return (cczp_const_t)cp; }
#define ccec_cp_p(_cp_)       ((_cp_)->ccn)
#define ccec_cp_b(_cp_)       ((_cp_)->ccn + 1 + 2 * ccec_cp_n(_cp_))
#define ccec_cp_g(_cp_)       ((const ccec_affine_point *)(ccec_cp_b(_cp_) + ccec_cp_n(_cp_)))
#define ccec_cp_zq(_cp_)      ((cczp_const_t)((_cp_)->ccn + 1 + ccec_cp_n(_cp_) * 5))

#define ccec_ctx_x(KEY)      (ccec_ctx_point(KEY)->xyz) // The  x, y and z of the public key as a projected point on the curve.
#define ccec_ctx_y(KEY)      (ccec_ctx_point(KEY)->xyz+ 1 * ccec_ctx_n(KEY))
#define ccec_ctx_z(KEY)      (ccec_ctx_point(KEY)->xyz+ 2 * ccec_ctx_n(KEY))


/***************************************************************************/
/* EC Sizes                                                                */
/***************************************************************************/

/* Return the length of the prime for cp in bits. */
#define ccec_cp_prime_bitlen(_cp_) (cczp_bitlen(ccec_cp_zp(_cp_)))
/* Return the sizeof the prime for cp. */
#define ccec_cp_prime_size(_cp_) ((ccec_cp_prime_bitlen(_cp_)+7)/8)

/* Return the length of the order for cp in bits. */
#define ccec_cp_order_bitlen(_cp_) (cczp_bitlen(ccec_cp_zq(_cp_)))
/* Return the length of the order for cp in bytes. */
#define ccec_cp_order_size(_cp_) ((ccec_cp_order_bitlen(_cp_)+7)/8)

/* Return the ec keysize in bits. */
#define ccec_ctx_bitlen(KEY) (ccec_cp_prime_bitlen(ccec_ctx_cp(KEY)))
/* Return the ec keysize in bytes. */
#define ccec_ctx_size(KEY) (ccec_cp_prime_size(ccec_ctx_cp(KEY)))




/* Return sizeof a ccn for cp. */
CC_INLINE
size_t ccec_ccn_size(ccec_const_cp_t cp) {
    return ccn_sizeof_n(ccec_cp_n(cp));
}

/* The k of a full key which makes up the private key.
   It is only accessible through full key
 */
CC_INLINE
cc_unit * cc_indexable ccec_ctx_k( ccec_full_ctx_t key) {
    // key->point is a pointer to a projective point.
    ccec_projective_point_t key_point = (ccec_projective_point_t)cc_unsafe_forge_bidi_indexable(key->point, sizeof(struct ccec_projective_point));
    // key_point->points contains the coordinates x, y, z, and are followed by k. All values are n-limbs.
    cc_unit *points = (cc_unit *)cc_unsafe_forge_bidi_indexable(key_point->xyz, ccn_sizeof_n(4 * ccec_ctx_n(key)));
    // Return the pointer for the value k, of size n * sizeof(cc_unit).
    return (cc_unit *)cc_unsafe_forge_bidi_indexable(points + 3 * ccec_ctx_n(key), ccn_sizeof_n(ccec_ctx_n(key)));
}

CC_INLINE
ccec_pub_ctx_t ccec_ctx_pub( ccec_full_ctx_t key) {
    return (ccec_pub_ctx_t) key;
}


/***************************************************************************/
/* EC Curve Parameters                                                     */
/***************************************************************************/

CC_CONST ccec_const_cp_t ccec_cp_192(void);
CC_CONST ccec_const_cp_t ccec_cp_224(void);
CC_CONST ccec_const_cp_t ccec_cp_256(void);
CC_CONST ccec_const_cp_t ccec_cp_384(void);
CC_CONST ccec_const_cp_t ccec_cp_521(void);

/***************************************************************************/
/* EC Wrap Params                                                          */
/***************************************************************************/

struct ccec_rfc6637_curve;
struct ccec_rfc6637_wrap;
struct ccec_rfc6637_unwrap;

extern const struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha256_kek_aes128;
extern const struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha512_kek_aes256;
extern const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha256_kek_aes128;
extern const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha512_kek_aes256;
extern const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p256;
extern const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p521;

/***************************************************************************/
/* EC Key Generation                                                       */
/***************************************************************************/

/*!
 @function   ccec_generate_key
 @abstract   Default - Currently invokes the FIPS version
    The behavior this function is not deterministic,
    the number of random bytes it consumes may vary
 @param      cp        Curve Parameters
 @param      rng       Random for the key generation as well as consistency signature
 @param      key       Full key containing the newly generated key pair
 @return    CCERR_OK if no error, an error code otherwise.
 */

CC_NONNULL((1, 2, 3))
int ccec_generate_key(ccec_const_cp_t cp, struct ccrng_state *rng,
                      ccec_full_ctx_t key);

/*!
 @function   ccec_generate_key_legacy
 @abstract   NOT recommended: For legacy purposes in order to re-generate
    deterministic keys previously generated.
    2 * ccn_sizeof(ccec_cp_order_bitlen(cp)) of random bytes needed
 @param      cp        Curve Parameters
 @param      rng       Random for the key generation as well as consistency signature
 @param      key       Full key containing the newly generated key pair
 @return    CCERR_OK if no error, an error code otherwise.
 */

CC_NONNULL((1, 2, 3))
int ccec_generate_key_legacy(ccec_const_cp_t cp,  struct ccrng_state *rng,
                             ccec_full_ctx_t key);

/*!
 @function   ccec_generate_key_fips
 @abstract   Guarantees FIPS compliant key pair. RECOMMENDED
    Use a non deterministic amount of random bytes
 @param      cp        Curve Parameters
 @param      rng       Random for the key generation as well as consistency signature
 @param      key       Full key containing the newly generated key pair
 @return    CCERR_OK if no error, an error code otherwise.
 */
CC_NONNULL_ALL
int ccec_generate_key_fips(ccec_const_cp_t cp,  struct ccrng_state *rng,
                           ccec_full_ctx_t key);

/*!
 @function   ccec_compact_generate_key
 @abstract   Generate a compact key pair according to
    https://tools.ietf.org/html/draft-jivsov-ecc-compact-05 and follows FIPS guideline
 @param      cp        Curve Parameters
 @param      rng       Random for the key generation as well as consistency signature
 @param      key       Full key containing the newly generated key pair
 @return     CCERR_OK if no error, an error code otherwise.
 */

/* Based on FIPS compliant version. Output a compact key */
/* Use a non deterministic amount of random bytes */
CC_NONNULL((1, 2, 3))
int ccec_compact_generate_key(ccec_const_cp_t cp,  struct ccrng_state *rng,
                              ccec_full_ctx_t key);

#define CCEC_GENKEY_DETERMINISTIC_FIPS     0b00001
/* FIPS consumes all of the entropy and requires a minimum of ceiling(qbitlen+64 / 8) bytes of entropy.
 It computes the secret key in [1,q-1] as (("entropy" mod (q-1)) + 1). "Entropy" is processed as a big endian number.
 Provided the entropy is FIPS compliant and no other option is set this method is FIPS compliant.
 If COMPACT option is used, the key is not strictly FIPS compliant */

#define CCEC_GENKEY_DETERMINISTIC_LEGACY   0b00100
/* LEGACY requires a minimum of ccn_sizeof_n(n) byte of entropy, but ignores bytes after ccn_sizeof_n(n) */
/* Use them in the same sequence as the output of ccrng_generate that is used in ccec_generate_legacy */

#define CCEC_GENKEY_DETERMINISTIC_COMPACT  0b01001 // ((1<<3) | CCEC_GENKEY_DETERMINISTIC_FIPS)
/* generate key that is compatible with compact export format. Compatible with all of the options above */

#define CCEC_GENKEY_DETERMINISTIC_SECBKP   0b11001 // ((1<<4) | CCEC_GENKEY_DETERMINISTIC_COMPACT)
/* Compatibility flag for Secure Backup generated keys */

/*!
 @function   ccec_generate_key_deterministic
 @abstract   Generate a key pair from the provided entropy buffer.
             requires cryptographic DRBG/KDF prior to calling
 @param      cp             Curve Parameters
 @param      entropy_len    Length in byte of the entropy buffer
 @param      entropy        Pointer to the entropy buffer of size entropy_len
 @param      rng            Real random for the signature and internal countermeasures
 @param      flags          Bitmask: options as explained below
 @param      key            Full key containing the newly generated key pair
 @return    CCERR_OK if no error, an error code otherwise.
 */
CC_NONNULL_ALL
int ccec_generate_key_deterministic(ccec_const_cp_t cp,
                                    size_t entropy_len,
                                    const uint8_t *cc_counted_by(entropy_len) entropy,
                                    struct ccrng_state *rng, // For masking and signature
                                    uint32_t flags,
                                    ccec_full_ctx_t key);    // Revisioning of the DRBG

/*!
 @function   ccecdh_generate_key
 @abstract   Key generation per FIPS186-4, used for ephemeral ECDH key pairs.
             Performs an ECDH consistency check.
 @param      cp             Curve parameters
 @param      rng            For key generation and internal countermeasures
 @param      key            Resulting key pair
 @return    CCERR_OK if no error, an error code otherwise.
 */
int ccecdh_generate_key(ccec_const_cp_t cp,  struct ccrng_state *rng, ccec_full_ctx_t key);


/***************************************************************************/
/* EC SIGN/VERIFY  (ECDSA)                                                 */
/***************************************************************************/

/*!
@function   ccec_sign_max_size
@param      cp Curve parameters
@return The maximum buffer size needed to hold a signature for curve.
*/
CC_INLINE CC_PURE CC_NONNULL((1))
size_t ccec_sign_max_size(ccec_const_cp_t cp) {
    /* tag + 2 byte len + 2 * (tag + 1 byte len + optional leading zero + ccec_cp_prime_size) */
    return 3 + 2 * (3 + ccec_cp_prime_size(cp));
}

/*!
@function   ccec_sign
@abstract   Sign a provided digest and return the signature in DER format.

@param      key         Full EC key
@param      digest_len  Length of digest
@param      digest      Digest buffer
@param      sig_len     Length of signature (must be initialized with the length of the output signature buffer)
@param      sig         Output signature buffer
@param      rng         RNG handle for internal countermeasures

@return     CCERR_OK if no error, an error code otherwise.

@discussion The returned signature's length may be less than the provided buffer size. The actual
 size is reflected in `sig_len` after the call.  If the signature does not fit in the output signature buffer, the function returns
 CCERR_BUFFER_TOO_SMALL and `sig_len` is updated with the expected signature length.
*/
CC_NONNULL((1, 3, 4, 5, 6))
int ccec_sign(ccec_full_ctx_t key, size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
              size_t *sig_len, uint8_t *cc_unsafe_indexable sig, struct ccrng_state *rng);

/*!
@function   ccec_sign_msg
@abstract   Given a message, compute its digest using the provided hash algorithm and sign it, returning the
           signature in DER format.

@param      key      Full EC key
@param      di       Hash context
@param      msg_len  Input message length
@param      msg      Message buffer
@param      sig_len  Length of signature buffer (must be initialized with the length of the output signature buffer)
@param      sig      Output signature buffer
@param      rng      RNG handle for internal countermeasures

@return     CCERR_OK if no error, an error code otherwise.

@discussion The returned signature's length may be less than the provided buffer size. The actual
 size is reflected in `sig_len` after the call. If the signature does not fit in the output signature buffer, the function returns
 CCERR_BUFFER_TOO_SMALL and `sig_len` is updated with the expected signature length.
*/
CC_NONNULL_ALL
int ccec_sign_msg(ccec_full_ctx_t key,
                  const struct ccdigest_info *di,
                  size_t msg_len, const uint8_t *cc_counted_by(msg_len) msg,
                  size_t *sig_len, uint8_t *cc_unsafe_indexable sig,
                  struct ccrng_state *rng);

/*!
@function   ccec_verify
@abstract   Verify a DER encoded signature given an input digest.

@param      key         EC Public Key
@param      digest_len  Length of digest
@param      digest      Digest buffer
@param      sig_len     Length of signature buffer
@param      sig         Signature buffer
@param      valid       Boolean indicating signature status (correct / incorrect)

@return     CCERR_OK if no error, an error code otherwise.
 
@discussion Both the return value and parameter `valid` must be checked. If the signature is valid,
 the return value will be CCERR_OK and valid will be set to True. If the signature is invalid, valid will
 be set to False. If there was some internal error, the return value will not be CCERR_OK (and valid
 will be set to False).
*/
CC_NONNULL((1, 3, 5, 6))
int ccec_verify(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                size_t sig_len, const uint8_t *cc_counted_by(sig_len) sig,  bool *valid);

/*!
@function   ccec_verify_msg
@abstract   Verify a DER encoded signature given an input message.

@param      key                EC Public Key
@param      di                 Hash context
@param      msg_len            Length of message
@param      msg                Message buffer
@param      sig_len            Length of signature
@param      sig                Signature buffer
@param      fault_canary_out   OPTIONAL cc_fault_canary_t (see discussion)

@return     CCERR_VALID_SIGNATURE if the signature is valid. Any other return code represents an invalid
 signature.
 
@discussion Unlike `ccec_verify`, only the return value needs to be checked to determine if
 a signature is valid. If `fault_canary_out` is not NULL and the signature is valid, CCEC_FAULT_CANARY will
 be written to fault_canary_out. Callers can then securely compare this output value with CCEC_FAULT_CANARY using
 CC_FAULT_CANARY_EQUAL as an additional check of signature validity. When CC_FAULT_CANARY_EQUAL returns True,
 the signature is valid otherwise it is not. If the signature *is* valid and CC_FAULT_CANARY_EQUAL returns false,
 this may indicate a potentially injected computational fault.
*/
CC_NONNULL((1, 2, 4, 6))
int ccec_verify_msg(ccec_pub_ctx_t key,
                    const struct ccdigest_info *di,
                    size_t msg_len, const uint8_t *cc_counted_by(msg_len) msg,
                    size_t sig_len, const uint8_t *cc_counted_by(sig_len) sig,
                    cc_fault_canary_t fault_canary_out);

/*!
@function   ccec_verify_digest
@abstract   Verify a DER encoded signature given an input digest.

@param      key                EC Public Key
@param      digest_len         Length of digest
@param      digest             Digest buffer
@param      sig_len            Length of signature
@param      sig                Signature buffer
@param      fault_canary_out   OPTIONAL cc_fault_canary_t (see discussion)

@return     CCERR_VALID_SIGNATURE is the signature is valid. Any other return code represents an invalid
 signature.
 
@discussion Unlike `ccec_verify`, only the return value needs to be checked to determine if
a signature is valid. If `fault_canary_out` is not NULL and the signature is valid, CCEC_FAULT_CANARY will
be written to fault_canary_out. Callers can then securely compare this output value with CCEC_FAULT_CANARY using
CC_FAULT_CANARY_EQUAL as an additional check of signature validity. When CC_FAULT_CANARY_EQUAL returns True,
the signature is valid otherwise it is not. If the signature *is* valid and CC_FAULT_CANARY_EQUAL returns false,
this may indicate a potentially injected computational fault.

*/
CC_NONNULL((1, 3, 5))
int ccec_verify_digest(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                       size_t sig_len, const uint8_t *cc_counted_by(sig_len) sig, cc_fault_canary_t fault_canary_out);

/*
  Raw signature, big endian, padded to the key size.
 */
/*!
@function   ccec_signature_r_s_size

@param      key  EC Public Key

@return     The size of a buffer needed to store one of the signature components (i.e. `r` or `s`).
*/
CC_NONNULL((1))
size_t
ccec_signature_r_s_size(ccec_pub_ctx_t key);

/*!
@function   ccec_sign_composite
@abstract   Sign a provided digest and return the signature in raw format.

@param      key         Full EC key
@param      digest_len  Length of digest
@param      digest      Digest buffer
@param      sig_r       Output `r` component of the signature of size ccec_signature_r_s_size(ccec_ctx_pub(key))
@param      sig_s       Output `s` component of the signature of size ccec_signature_r_s_size(ccec_ctx_pub(key))
@param      rng         RNG handle for internal countermeasures

@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL((1, 3, 4, 5, 6))
int ccec_sign_composite(ccec_full_ctx_t key, size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                        uint8_t *cc_unsafe_indexable sig_r, uint8_t *cc_unsafe_indexable sig_s,
                        struct ccrng_state *rng);

/*!
@function   ccec_sign_composite_msg
@abstract   Sign a provided message using the specified hash function and return the signature in raw format.

@param      key      Full EC key
@param      di       Hash function
@param      msg_len  Input message length
@param      msg      Message buffer
@param      sig_r    Output `r` component of the signature of size ccec_signature_r_s_size(ccec_ctx_pub(key))
@param      sig_s    Output `s` component of the signature of size ccec_signature_r_s_size(ccec_ctx_pub(key))
@param      rng      RNG handle for internal countermeasures

@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL((1, 2, 4, 5, 6, 7))
int ccec_sign_composite_msg(ccec_full_ctx_t key, const struct ccdigest_info *di,
                            size_t msg_len, const uint8_t *cc_counted_by(msg_len) msg,
                            uint8_t *cc_unsafe_indexable sig_r, uint8_t *cc_unsafe_indexable sig_s,
                            struct ccrng_state *rng);

/*!
@function   ccec_verify_composite
@abstract   Verify a signature given the digest and raw signature components.

@param      key         EC Public Key
@param      digest_len  Length of digest
@param      digest      Digest buffer
@param      sig_r       Input signature component `r`
@param      sig_s       Input signature component `s`
@param      valid       Boolean indicating signature status (correct / incorrect)
 
@return     CCERR_OK if no error, an error code otherwise.
 
@discussion Both the return value and parameter `valid` must be checked. If the signature is valid,
 the return value will be CCERR_OK and valid will be set to True. If the signature is invalid, valid will
 be set to False. If there was some internal error, the return value will not be CCERR_OK (and valid
 will be set to False).
*/
CC_NONNULL((1, 3, 4, 5, 6))
int ccec_verify_composite(ccec_pub_ctx_t key, size_t digest_len,
                          const uint8_t *cc_counted_by(digest_len) digest,
                          const uint8_t *cc_unsafe_indexable sig_r,
                          const uint8_t *cc_unsafe_indexable sig_s, bool *valid);

/*!
@function   ccec_verify_composite_msg
@abstract   Verify a signature given the message, using the provided hash context, and raw signature components.

@param      key                EC Public Key
@param      di                 Hash context
@param      msg_len            Input message length
@param      msg                Message buffer
@param      sig_r              Input signature component `r`
@param      sig_s              Input signature component `s`
@param      fault_canary_out   OPTIONAL cc_fault_canary_t (see discussion)

@return     CCERR_VALID_SIGNATURE is the signature is valid. Any other return code represents an invalid
signature.

@discussion Unlike `ccec_verify_composite`, only the return value needs to be checked to determine if
a signature is valid. If `fault_canary_out` is not NULL and the signature is valid, CCEC_FAULT_CANARY will
be written to fault_canary_out. Callers can then securely compare this output value with CCEC_FAULT_CANARY using
CC_FAULT_CANARY_EQUAL as an additional check of signature validity. When CC_FAULT_CANARY_EQUAL returns True,
the signature is valid otherwise it is not. If the signature *is* valid and CC_FAULT_CANARY_EQUAL returns false,
this may indicate a potentially injected computational fault.
*/
CC_NONNULL((1, 2, 4, 5, 6))
int ccec_verify_composite_msg(ccec_pub_ctx_t key, const struct ccdigest_info *di,
                              size_t msg_len, const uint8_t *cc_counted_by(msg_len) msg,
                              const uint8_t *cc_unsafe_indexable sig_r,
                              const uint8_t *cc_unsafe_indexable sig_s,
                              cc_fault_canary_t fault_canary_out);

/*!
@function   ccec_verify_composite_digest
@abstract   Verify a signature given the digest and raw signature components.

@param      key                EC Public Key
@param      digest_len         Input digest length
@param      digest             Digest buffer
@param      sig_r              Input signature component `r`
@param      sig_s              Input signature component `s`
@param      fault_canary_out   OPTIONAL cc_fault_canary_t (see discussion)
 
@return     CCERR_VALID_SIGNATURE is the signature is valid. Any other return code represents an invalid
signature.
 
@discussion Unlike `ccec_verify`, only the return value needs to be checked to determine if
a signature is valid. If `fault_canary_out` is not NULL and the signature is valid, CCEC_FAULT_CANARY will
be written to fault_canary_out. Callers can then securely compare this output value with CCEC_FAULT_CANARY using
CC_FAULT_CANARY_EQUAL as an additional check of signature validity. When CC_FAULT_CANARY_EQUAL returns True,
the signature is valid otherwise it is not. If the signature *is* valid and CC_FAULT_CANARY_EQUAL returns false,
this may indicate a potentially injected computational fault.
*/
CC_NONNULL((1, 3, 4, 5))
int ccec_verify_composite_digest(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                                 const uint8_t *cc_unsafe_indexable sig_r,
                                 const uint8_t *cc_unsafe_indexable sig_s,
                                 cc_fault_canary_t fault_canary_out);

/***************************************************************************/
/* EC Diffie-Hellman                                                       */
/***************************************************************************/

/*
   Deprecated. Do not use.
   Migrate existing calls to ccecdh_compute_shared_secret
 */

/*!
 @function   ccec_compute_key
 @abstract   DEPRECATED. Use ccecdh_compute_shared_secret.
 */

CC_NONNULL((1, 2, 3, 4))
int ccec_compute_key(ccec_full_ctx_t private_key, ccec_pub_ctx_t public_key,
                     size_t *computed_key_len, uint8_t *cc_unsafe_indexable computed_key)
cc_deprecate_with_replacement("ccecdh_compute_shared_secret", 13.0, 10.15, 13.0, 6.0, 4.0);

/*!
 @function   ccecdh_compute_shared_secret
 @abstract   Elliptic Curve Diffie-Hellman
 from ANSI X9.63 and NIST SP800-56A, section 5.7.1.2

 @param  private_key                Input: EC private key
 @param  public_key                 Input: EC public key
 @param  computed_shared_secret_len Input: Size of allocation for computed_shared_secret.
 Output: Effective size of data in computed_shared_secret
 @param  computed_shared_secret     Output: DH shared secret
 @param  masking_rng                Input: Handle on RNG to be used for the randomization of the computation

 @result 0 iff successful

 @discussion The shared secret MUST be transformed with a KDF function or at
 least Hash (SHA-256 or above) before being used.
 It shall not be used directly as a key.
 */

CC_NONNULL((1, 2, 3, 4))
int ccecdh_compute_shared_secret(ccec_full_ctx_t private_key,
                                 ccec_pub_ctx_t public_key,
                                 size_t *computed_shared_secret_len,
                                 uint8_t *cc_unsafe_indexable computed_shared_secret,
                                 struct ccrng_state *masking_rng);

/***************************************************************************/
/* EC WRAP/UNWRAP                                                          */
/***************************************************************************/

/*
 * Use rfc6637 style PGP wrapping for using EC keys
 */

CC_NONNULL((1))
size_t ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key,
                                  unsigned long flags,
                                  size_t key_len);

/*
 * When CCEC_RFC6637_COMPACT_KEYS flag is used, the wrapping is NOT
 * compatible with RFC6637 so make sure the peer supports this mode
 * before using it.  It currently saves half of the public key size
 * which for P256 is 32 bytes which end up being about 1/4 of the
 * wrapping size.
 * Macros are bit masks
 */
#define CCEC_RFC6637_COMPACT_KEYS                 1
#define CCEC_RFC6637_DEBUG_KEYS                   2
#define CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS      4

/*!
 @function   ccec_rfc6637_wrap_key
 @abstract   Key wraping based on rfc6637

 @param  public_key     Input:  EC public key
 @param  wrapped_key    Output: Buffer for the wrapped key of length ccec_rfc6637_wrap_key_size
 @param  flags          Input:  Option flags
 @param  algid          Input:  Algorithm id
 @param  key_len         Input:  Length of the key to wrap (<=37 bytes)
 @param  key            Input:  Pointer to the key to wrap
 @param  curve          Input:  Definiton of the curve
 @param  wrap          Input:  Definiton of the wrap
 @param  fingerprint    Input:  Point to a 20byte buffer used as fingerprint during wrapping.
 @param  rng            Input:  Handle on a RNG for ephemeral key generation and computation randomization

 @result 0 iff successful

 @discussion
    This implementation hides the length of the key to wrap.
    It only supports wrapping keys up to 37bytes.
 */
CC_NONNULL((1, 2, 6, 7, 8, 9, 10))
int
ccec_rfc6637_wrap_key(ccec_pub_ctx_t public_key,
                          void  *cc_unsafe_indexable wrapped_key,
                          unsigned long flags,
                          uint8_t algid,
                          size_t key_len,
                          const void *cc_sized_by(key_len) key,
                          const struct ccec_rfc6637_curve *curve,
                          const struct ccec_rfc6637_wrap *wrap,
                          const uint8_t *cc_counted_by(20) fingerprint,
                          struct ccrng_state *rng);

/*!
 @function   ccec_diversify_pub
 @abstract   diversified public key with scalar r.
 r = entropy mod (q-1)) + 1, where entropy is interpreted as big endian.

 entropy_len must be greater or equal to ccec_diversify_min_entropy_len
 the entropy must be a well uniformly distributed number, such as random byte,
 output of a DRBG or output of a KDF.

 @param  cp                      Input:  Curve parameter
 @param  pub_key                 Input:  Original public key P.
 @param  entropy_len             Input:  byte length of the entropy
 @param  entropy                 Input:  point to the entropy
 @param  masking_rng             Input:  Random for randomizing the computation
 @param  diversified_generator   Output: New generator  (r.G).
 @param  diversified_pub_key     Output: New public key (r.P).

 @result 0 iff unwrapping was successful

 @discussion
 Diversified keys is the process of multiplying the generator and the public key
 by a same random number.
 This does not preserve properties of the key with respect to compact format
 However, this method is valid with compact points when using ECDH and when only X coordinate is used
 Therefore this is valid with ccec_rfc6637 wrap / unwrap.

 Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 */
int ccec_diversify_pub(ccec_const_cp_t cp,
                       ccec_pub_ctx_t pub_key,
                       size_t entropy_len,
                       const uint8_t *cc_counted_by(entropy_len) entropy,
                       struct ccrng_state *masking_rng,
                       ccec_pub_ctx_t  diversified_generator,
                       ccec_pub_ctx_t  diversified_pub_key
                       );

/*!
 @function   ccec_diversify_min_entropy_len
 @abstract   Minimum length of entropy to be passed to ccec_diversify_pub

 @param  cp                      Input:  Curve parameter

 @result Minimal entropy length in bytes to be used in ccec_diversify_pub

 */
size_t ccec_diversify_min_entropy_len(ccec_const_cp_t cp);

/*!
 @function   ccec_diversify_pub_twin
 @abstract   Diversifies a given public key by deriving two scalars u,v from
             the given entropy and computing u.P + v.G, with G being the
             generator of the given curve.

 entropy_len must be a multiple of two, greater or equal to
 2 * ccec_diversify_min_entropy_len(). The entropy must be
 chosen from a uniform distribution, e.g. random bytes,
 the output of a DRBG, or the output of a KDF.

 @param  cp          Input:  Curve parameters
 @param  pub         Input:  Original public key P
 @param  entropy_len Input:  Length of entropy
 @param  entropy     Input:  Entropy used to derive scalars u,v
 @param  masking_rng Input:  Random for randomizing the computation
 @param  pub_out     Output: Diversified public key (u.P + v.G)

 @result 0 iff successful

 */
CC_NONNULL((1, 2, 4, 5, 6))
int ccec_diversify_pub_twin(ccec_const_cp_t cp,
                            const ccec_pub_ctx_t pub,
                            size_t entropy_len,
                            const uint8_t *cc_counted_by(entropy_len) entropy,
                            struct ccrng_state *masking_rng,
                            ccec_pub_ctx_t pub_out);

/*!
 @function   ccec_diversify_priv_twin
 @abstract   Computes a delegate private key by deriving two scalars u,v from
             the given entropy and computing d' = (d * u + v) and the public
             point d' * G; G being the generator of the given curve.

 entropy_len must be a multiple of two, greater or equal to
 2 * ccec_diversify_min_entropy_len(). The entropy must be
 chosen from a uniform distribution, e.g. random bytes,
 the output of a DRBG, or the output of a KDF.

 @param  cp          Input:  Curve parameters
 @param  d           Input:  Original private key
 @param  entropy_len Input:  Length of entropy
 @param  entropy     Input:  Entropy used to derive scalars u,v
 @param  masking_rng Input:  Random for randomizing the computation
 @param  full        Output: Delegate private key (where d' = d*u + v)

 @result 0 iff successful

 */
CC_NONNULL((1, 2, 4, 5, 6))
int ccec_diversify_priv_twin(ccec_const_cp_t cp,
                             const cc_unit *cc_unsafe_indexable d,
                             size_t entropy_len,
                             const uint8_t *cc_counted_by(entropy_len) entropy,
                             struct ccrng_state *masking_rng,
                             ccec_full_ctx_t full);

/*!
 @function   ccec_rfc6637_wrap_key_diversified
 @abstract   Key wraping based on rfc6637

 @param  generator      Input:  Generator, represented as a public key
 @param  public_key     Input:  EC public key
 @param  wrapped_key    Output: Buffer for the wrapped key of length ccec_rfc6637_wrap_key_size
 @param  flags          Input:  Option flags
 @param  symm_alg_id          Input:  Algorithm id
 @param  key_len         Input:  Length of the key to wrap (<=38 bytes)
 @param  key            Input:  Pointer to the key to wrap
 @param  curve          Input:  Definiton of the curve
 @param  wrap           Input:  Definiton of the wrap
 @param  fingerprint    Input:  Point to a 20byte buffer used as fingerprint during wrapping.
 @param  rng            Input:  Handle on a RNG for ephemeral key generation and computation randomization

 @result 0 iff successful

 @discussion
    Diversified keys is the process of multiplying the generator and the public key
    by a same number.
    This implementation hides the length of the key to wrap.
    It only supports wrapping keys up to 37bytes.
 */

CC_NONNULL((1, 2, 3, 7, 8, 9, 10, 11))
int
ccec_rfc6637_wrap_key_diversified(ccec_pub_ctx_t generator,
                                  ccec_pub_ctx_t public_key,
                                  void *cc_unsafe_indexable wrapped_key,
                                  unsigned long flags,
                                  uint8_t symm_alg_id,
                                  size_t key_len,
                                  const void *cc_sized_by(key_len) key,
                                  const struct ccec_rfc6637_curve *curve,
                                  const struct ccec_rfc6637_wrap *wrap,
                                  const uint8_t *cc_counted_by(20) fingerprint,
                                  struct ccrng_state *rng);

/*!
 @function   ccec_rfc6637_unwrap_key
 @abstract   Key unwraping based on rfc6637

 @param  private_key        Input:  Private key to unwrap the key
 @param  key_len            Input/Output:  Size of the allocated buffer / size of the key
 @param  key                Output: Buffer for the unwrapped key
 @param  flags              Input:  Option flags
 @param  symm_key_alg       Output: Algorithm id
 @param  curve              Input:  Definiton of the curve
 @param  unwrap               Input:  Definiton of the unwrap
 @param  fingerprint        Input:  Point to a 20byte buffer used as fingerprint during wrapping.
 @param  wrapped_key_len    Input:  Size in byte of the wrapped key
 @param  wrapped_key        Input:  Pointer to the wrapped key

 @result 0 iff successful

 @discussion
 Diversified keys is the process of multiplying the generator and the public key
 by a same number.
 */
CC_NONNULL((1, 2, 3, 5, 6, 7, 8, 10))
int
ccec_rfc6637_unwrap_key(ccec_full_ctx_t private_key,
                            size_t *key_len,
                            void *cc_unsafe_indexable key,
                            unsigned long flags,
                            uint8_t *symm_key_alg,
                            const struct ccec_rfc6637_curve *curve,
                            const struct ccec_rfc6637_unwrap *unwrap,
                            const uint8_t *cc_counted_by(20) fingerprint,
                            size_t wrapped_key_len,
                            const void  *cc_sized_by(wrapped_key_len) wrapped_key);

/***************************************************************************/
/* EC Import/Export                                                        */
/***************************************************************************/

CC_NONNULL((1, 3, 4))
int ccec_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *cc_counted_by(in_len) in, ccec_pub_ctx_t key);

/* Return the sizeof a buffer needed to export a public key for a set of curve parameters. */
CC_INLINE CC_NONNULL((1))
size_t ccec_export_pub_size_cp(ccec_const_cp_t cp) {
    return 1 + 2 * ccec_cp_prime_size(cp);
}

/* Return the sizeof a buffer needed to export a public key to. */
CC_INLINE CC_NONNULL((1))
size_t ccec_export_pub_size(const ccec_pub_ctx_t key) {
    return ccec_export_pub_size_cp(ccec_ctx_cp(key));
}

/*!
 @function   ccec_export_pub
 @abstract   Export a public key in the uncompressed format
 @param      out            The output buffer (must be ccec_export_pub_size(key) bytes long)
 @param      key            A pointer to the public key
 @return     CCERR_OK if no error, an error code otherwise
 */
CC_NONNULL((1, 2))
int ccec_export_pub(const ccec_pub_ctx_t key, void *out);

/* ---------------------------------*/
/* x963							    */
/* ---------------------------------*/

/* Export 9.63 */
CC_INLINE CC_NONNULL((2))
size_t ccec_x963_export_size(const int fullkey, const ccec_pub_ctx_t key){
    return (((ccec_ctx_bitlen(key)+7)/8) * ((fullkey == 1) + 2)) + 1;
}

CC_INLINE CC_CONST CC_NONNULL((2))
size_t ccec_x963_export_size_cp(const int fullkey, ccec_const_cp_t cp){
    return (((ccec_cp_prime_bitlen(cp)+7)/8) * ((fullkey == 1) + 2)) + 1;
}

/*!
 @function   ccec_x963_export
 @abstract   Export a key in the uncompressed format
 @param      fullkey        0 to export only the public key, 1 to export the fullkey
 @param      out            The output buffer (must be ccec_x963_export_size(fullkey, key) bytes long)
 @param      key            A pointer to the full key
 @return     CCERR_OK if no error, an error code otherwise
 */
CC_NONNULL((2, 3))
int ccec_x963_export(const int fullkey, void *out, const ccec_full_ctx_t key);

/* Import 9.63 */
size_t ccec_x963_import_pub_size(size_t in_len);

CC_NONNULL((1, 3, 4))
/* Import an EC public key with x9.63 format */
int ccec_x963_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *cc_counted_by(in_len) in, ccec_pub_ctx_t key);

size_t ccec_x963_import_priv_size(size_t in_len);

CC_NONNULL((1, 3, 4))
/* Import the full key (private and public part of the key) with x9.63 format */
int ccec_x963_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *cc_counted_by(in_len) in, ccec_full_ctx_t key);
/* ---------------------------------*/
/* Compact						    */
/* ---------------------------------*/

/*!
 @function   ccec_compact_export
 @abstract   Export the full or public part (x coordinate) of a full key (x and scalar)

 @param  fullkey        Input: Flag indicating if private scalar is to be serialized or omitted
 @param  out            Output: Pointer to output buffer, length must be consistent with ccec_compact_export_size
 @param  key            Input:  EC full key (private and public components)

 @return CCERR_OK if successful, an error code otherwise
 
 @discussion Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 */

CC_NONNULL((2, 3))
int ccec_compact_export(const int fullkey, void *cc_unsafe_indexable out, const ccec_full_ctx_t key);

/*!
 @function   ccec_compact_export_pub
 @abstract   Export the public part (x coordinate)

 @param  out Output: Pointer to output buffer, written length is ccec_compact_export_size or ccec_compact_export_size_cp with fullkey==0
 @param  key Input:  EC public key

 @return CCERR_OK if successful, an error code otherwise
 
 @discussion Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 */
CC_NONNULL_ALL
int ccec_compact_export_pub(void *cc_unsafe_indexable out, const ccec_pub_ctx_t key);

/*!
 @function   ccec_compact_export_size_cp
 @abstract   Return the size necessary to export a key, either public or private

 @param  fullkey  Input: Flag indicating if private scalar is to be serialized or omitted
 @param  cp       Input:  EC curve parameters

 Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 */
CC_INLINE CC_NONNULL((2))
size_t ccec_compact_export_size_cp(const int fullkey, ccec_const_cp_t cp){
    return (ccec_cp_prime_size(cp) * ((fullkey == 1) + 1));
}

/*!
 @function   ccec_compact_export_size
 @abstract   Return the size necessary to export a key, either public or private

 @param  fullkey  Input: Flag indicating if private scalar is to be serialized or omitted
 @param  key      Input: EC public key, use "ccec_ctx_pub(key)" to use from a full key

 Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 */
CC_INLINE CC_NONNULL((2))
size_t ccec_compact_export_size(const int fullkey, const ccec_pub_ctx_t key){
    return ccec_compact_export_size_cp(fullkey,ccec_ctx_cp(key));
}

/* Import Compact
 The public key is the x coordinate, in big endian, of length the byte length of p
 No preambule byte */

size_t ccec_compact_import_pub_size(size_t in_len);

CC_NONNULL_ALL
int ccec_compact_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *cc_counted_by(in_len) in, ccec_pub_ctx_t key);

size_t ccec_compact_import_priv_size(size_t in_len);

CC_NONNULL_ALL
int ccec_compact_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *cc_counted_by(in_len) in, ccec_full_ctx_t key);

/* ---------------------------------*/
/* Compressed                       */
/* ---------------------------------*/
/*!
@function       ccec_compressed_x962_import_pub
@abstract       Import a compressed public key
@param cp       curve parameters for the key
@param in_len   length in bytes of the input buffer with compressed key
@param key      ccec public key context to hold resulting key. Will be initialized with cp.
@result         CCERR_OK on success, error otherwise.
*/
CC_NONNULL_ALL
int ccec_compressed_x962_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *cc_counted_by(in_len) in, ccec_pub_ctx_t key);

/*!
@function   ccec_compressed_x962_export_pub
@abstract   export a key in x962 compressed format
@param key  key to export
@param out  buffer to place compressed key, should be of size returned by ccec_compressed_x962_export_pub_size
@result     CCERR_OK on success, error otherwise.
*/
CC_NONNULL_ALL
int ccec_compressed_x962_export_pub(const ccec_pub_ctx_t key, uint8_t *out);

/*!
@function   ccec_compressed_x962_export_pub_size
@abstract   The number of bytes needed to hold a compressed key for curve defined by cp
@param cp   The curve parameters for the curve with respect to which you want to export a key
@result     The number of bytes needed to hold a compressed key.
!*/
CC_NONNULL_ALL
size_t ccec_compressed_x962_export_pub_size(ccec_const_cp_t cp);

/* ---------------------------------*/
/* DER (RFC 5915)                   */
/* ---------------------------------*/

/* Export EC priv to DER (RFC 5915) */
CC_NONNULL((1))
size_t ccec_der_export_priv_size(const ccec_full_ctx_t key, ccoid_t key_oid, int include_public);

CC_NONNULL((1, 5))
int ccec_der_export_priv(const ccec_full_ctx_t key, ccoid_t key_oid, int include_public, size_t out_len, void *cc_sized_by(out_len) out);

/* import EC priv from DER (RFC 5915) */

CC_NONNULL((2, 4))
int ccec_der_import_priv_keytype(size_t len, const uint8_t *cc_counted_by(len) data, ccoid_t *oid, size_t *n);

CC_NONNULL((1, 3, 4))
int ccec_der_import_priv(ccec_const_cp_t cp, size_t length, const uint8_t *cc_counted_by(length) data, ccec_full_ctx_t full_key);

/* ---------------------------------*/
/* DER (custom) for diversified keys*/
/* ---------------------------------*/

/*!
 @function   ccec_der_export_diversified_pub_size
 @abstract   DER export of a diversified public key

 @param  diversified_generator Input:  Generator, represented as a public key
 @param  diversified_key       Input:  EC public key
 @param  flags                 Input:  Option flags (compact keys)

 @result sizeof a buffer needed to exported public key if successful, 0 otherwise.

 @discussion
 Diversified keys is the process of multiplying the generator and the public key
 by a same number.

 Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/

 */
size_t ccec_der_export_diversified_pub_size(
                                            const ccec_pub_ctx_t  diversified_generator,
                                            const ccec_pub_ctx_t  diversified_key,
                                            unsigned long flags);
/*!
 @function   ccec_der_export_diversified_pub
 @abstract   DER export of a diversified public key

 @param  diversified_generator Input:  Generator, represented as a public key
 @param  diversified_key       Input:  EC public key
 @param  flags                 Input:  Option flags (compact keys)
 @param  der_len               Input:  Size of the destination buffer
 @param  der                   Output: Pointer to the destination buffer, must be ccec_export_pub_size(key) bytes long.

 @result NULL is error, pointer in the der buffer otherwise.

 @discussion
 Diversified keys is the process of multiplying the generator and the public key
 by a same number.

 Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 */
uint8_t *ccec_der_export_diversified_pub(
                                    const ccec_pub_ctx_t  diversified_generator,
                                    const ccec_pub_ctx_t  diversified_key,
                                    unsigned long flags,
                                    size_t der_len, uint8_t *cc_counted_by(der_len) der);

/*!
 @function   ccec_der_import_diversified_pub
 @abstract   DER import of a diversified public key

 @param  cp          Input:  Curve parameters
 @param  length               Input:  Size of the input buffer
 @param  data                   Input: Pointer to the input buffer long.
 @param  outflags              Output:  Output flags telling how the data was parsed.
 @param  diversified_generator Output:  Diversified generator, represented as a public key
 @param  diversified_key       Output:  Diversified EC public key
 
 @result 0 iff unwrapping was successful

 @discussion
 Diversified keys is the process of multiplying the generator and the public key
 by a same number. Currently the only valid output flag is CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS.
 The generator and the public point a required to be encoded in the same format, either standard
 or compact format. Mixing form is not allowed and that output is never generated
 by ccec_der_export_diversified_pub.

 Compact here refers to https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
 */
int ccec_der_import_diversified_pub(
                                    ccec_const_cp_t cp,
                                    size_t length, const uint8_t *cc_counted_by(length) data,
                                    int *outflags,
                                    ccec_pub_ctx_t  diversified_generator,
                                    ccec_pub_ctx_t  diversified_key);

/***************************************************************************/
/* EC Construction and Validation                                          */
/***************************************************************************/

CC_NONNULL((1))
int ccec_get_pubkey_components(ccec_pub_ctx_t key, size_t *nbits,
                           uint8_t *cc_unsafe_indexable x, size_t *xsize,
                           uint8_t *cc_unsafe_indexable y, size_t *ysize);

CC_NONNULL((1))
int ccec_get_fullkey_components(ccec_full_ctx_t key, size_t *nbits,
                            uint8_t *cc_unsafe_indexable x, size_t *xsize,
                            uint8_t *cc_unsafe_indexable y, size_t *ysize,
                            uint8_t *cc_unsafe_indexable d, size_t *dsize);

CC_NONNULL((3,5,6))
int ccec_make_pub(size_t nbits,
                  size_t xlength, const uint8_t *cc_counted_by(xlength) x,
                  size_t ylength, const uint8_t *cc_counted_by(ylength) y,
                  ccec_pub_ctx_t key);

CC_NONNULL((8))
int ccec_make_priv(size_t nbits,
                   size_t xlength, const uint8_t *cc_counted_by(xlength) x,
                   size_t ylength, const uint8_t *cc_counted_by(ylength) y,
                   size_t klength, const uint8_t *cc_counted_by(klength) k,
                   ccec_full_ctx_t key);

/*!
 @function   ccec_validate_pub
 @abstract   Perform validation of the public key
 @param  key elliptic curve public key
 @result true if the key is valid
 @discussion
 Perform the public key validation from FIPS: x,y are within range and
 the point is on the curve. Point at infinity is considered as invalid here.
 */
CC_NONNULL((1))
bool ccec_validate_pub(ccec_pub_ctx_t key);

int ccec_keysize_is_supported(size_t keysize);

ccec_const_cp_t ccec_get_cp(size_t keysize);

CC_NONNULL((1, 2))
bool ccec_pairwise_consistency_check(const ccec_full_ctx_t full_key, struct ccrng_state *rng);

ccec_const_cp_t ccec_curve_for_length_lookup(size_t keylen, ...);

#endif /* _CORECRYPTO_CCEC_H_ */
