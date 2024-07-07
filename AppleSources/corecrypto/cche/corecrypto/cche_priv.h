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

#ifndef _CORECRYPTO_CCHE_PRIV_H_
#define _CORECRYPTO_CCHE_PRIV_H_

#include <stdint.h>
#include <corecrypto/ccrng.h>

CC_PTRCHECK_CAPABLE_HEADER()

#if CC_PRIVATE_CRYPTOKIT

// MARK: - EncryptionParams

/// Encryption parameters
typedef enum {
    // @warning - insecure; use for testing only
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_8_LOGQ_5x18_LOGT_5 = 0,
    // @warning - insecure; use for testing only
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_512_LOGQ_4x60_LOGT_20 = 1,
    // below parameters satisfy post-quantum 128-bit security
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_13 = 2,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_42 = 3,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_30 = 4,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_29 = 5,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_5 = 6,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_24 = 7,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_29_60_60_LOGT_15 = 8,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_40_60_60_LOGT_26 = 9,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_28_60_60_LOGT_20 = 10,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_16_33_33_LOGT_4 = 11,
    // @warning - insecure; use for testing only
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_16_LOGQ_60_LOGT_15 = 12,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_6 = 13,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_16 = 14,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_17 = 15,
    CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_4 = 16,
    // Note, if adding extra parameters, consider adding any new moduli to `predefined_min_primitive_roots`
} cche_predefined_encryption_params_t;

/// @brief Number of predefined encryption parameters
#define CCHE_PREDEFINED_ENCRYPTION_PARAMS_COUNT 17

/// @brief Number of predefined encryption parameters that support SIMD encoding/decoding
#define CCHE_PREDEFINED_ENCRYPTION_PARAMS_SIMD_COUNT 11

/// HE scheme
typedef enum {
    CCHE_SCHEME_UNSPECIFIED = 0, // Unspecified
    CCHE_SCHEME_BFV = 1,         // Brakerski-Fan-Vercauteren
    CCHE_SCHEME_BGV = 2,         // Brakerski-Gentry-Vaikuntanathan
} cche_scheme_t;

/// @brief Number of supported HE schemes
#define CCHE_SCHEMES_COUNT 2

/// @brief Get the plaintext modulus
/// @param enc_params The encryption parameters
/// @return plaintext modulus
uint64_t cche_encryption_params_plaintext_modulus(cche_predefined_encryption_params_t enc_params);

/// @brief Get the polynomial degree
/// @param enc_params The encryption parameters
/// @return polynomial degree
uint32_t cche_encryption_params_polynomial_degree(cche_predefined_encryption_params_t enc_params);

/// @brief Get the number of coefficient moduli
/// @param enc_params The encryption parameters
/// @return number of coefficient moduli
size_t cche_encryption_params_coefficient_nmoduli(cche_predefined_encryption_params_t enc_params);

/// @brief Get the coefficient moduli
/// @param nmoduli number of slots in the `moduli` buffer
/// @param moduli buffer to store the coefficient moduli
/// @param enc_params The encryption parameters
CC_NONNULL_ALL
void cche_encryption_params_coefficient_moduli(size_t nmoduli,
                                               uint64_t *cc_counted_by(nmoduli) moduli,
                                               cche_predefined_encryption_params_t enc_params);

// MARK: - ParamContext

/// This holds all the parameters and the precomputed polynomial contexts
/// 1. cche_encrypt_params
/// 2. polynomial context chain (ccpolyzp_po2cyc_ctx_chain)
/// 3. plaintext polynomial context (ccpolyzp_po2cyc_ctx)
/// 4. encoding index array (poly_modulus_degree uint32_t indices)
/// 5. decryption context (cche_decrypt_ctx)
/// 6. cipher-plain contexts array
typedef struct cche_param_ctx *cche_param_ctx_t;
typedef const struct cche_param_ctx *cche_param_ctx_const_t;

/// @brief Returns the number of bytes required to allocate a context with the given encryption parameters
/// @param enc_params Encryption parameters
CC_NONNULL_ALL CC_PURE size_t cche_param_ctx_sizeof(cche_predefined_encryption_params_t enc_params);

/// @brief Initializes a parameter context with encryption parameters
/// @param param_ctx The context to initialize
/// @param he_scheme The HE scheme for the encryption parameters
/// @param encryption_params The encryption parameters for the parameter context
/// @return `CCERR_OK` if parameter context initialized successfully
/// @details Performs pre-computations for using the parameter context; should be called before use in BFV/BGV operations
CC_NONNULL_ALL CC_WARN_RESULT int
cche_param_ctx_init(cche_param_ctx_t param_ctx, cche_scheme_t he_scheme, cche_predefined_encryption_params_t encryption_params);

/// @brief Get the HE scheme
/// @param param_ctx The parameter context
CC_NONNULL_ALL CC_PURE cche_scheme_t cche_param_ctx_he_scheme(cche_param_ctx_const_t param_ctx);

/// @brief Returns whether or not a parameter context supports SIMD encoding and decoding
/// @param param_ctx The parameter context
CC_NONNULL_ALL CC_PURE bool cche_param_ctx_supports_simd_encoding(cche_param_ctx_const_t param_ctx);

/// @brief Get the plaintext modulus
/// @param param_ctx The context
CC_NONNULL_ALL CC_PURE uint64_t cche_param_ctx_plaintext_modulus(cche_param_ctx_const_t param_ctx);

/// @brief Get the polynomial degree
/// @param param_ctx The context
CC_NONNULL_ALL CC_PURE uint32_t cche_param_ctx_polynomial_degree(cche_param_ctx_const_t param_ctx);

/// @brief Get the number of moduli in the key context
/// @param param_ctx The context
CC_NONNULL_ALL CC_PURE uint32_t cche_param_ctx_key_ctx_nmoduli(cche_param_ctx_const_t param_ctx);

/// @brief Get the number of moduli in the top-level ciphertext context
/// @param param_ctx The context
CC_NONNULL_ALL CC_PURE uint32_t cche_param_ctx_ciphertext_ctx_nmoduli(cche_param_ctx_const_t param_ctx);

/// @brief Get the coefficient moduli
/// @param param_ctx The context
CC_NONNULL_ALL CC_PURE const uint64_t *cche_param_ctx_coefficient_moduli(cche_param_ctx_const_t param_ctx);

/// @brief Get the number of bytes needed to store one polynomial in the key context
/// @param param_ctx The context
CC_NONNULL_ALL CC_PURE size_t cche_param_ctx_key_ctx_poly_nbytes(cche_param_ctx_const_t param_ctx);

/// @brief Compute the inverse of `x` mod plaintext modulus
/// @param inverse The inverse will be stored here
/// @param param_ctx The context
/// @param x The element to invert; a single 64-bit integer that may exceed the plaintext modulus
/// @return `CCERR_OK` if operation was successful.
CC_NONNULL_ALL CC_WARN_RESULT int
cche_param_ctx_plaintext_modulus_inverse(uint64_t *inverse, cche_param_ctx_const_t param_ctx, uint64_t x);

// MARK: - RngSeed

/// RNG Seed
struct cche_rng_seed;
typedef struct cche_rng_seed *cche_rng_seed_t;
typedef const struct cche_rng_seed *cche_rng_seed_const_t;

/// @brief Get RNG seed size
/// @return Number of bytes required to hold the RNG seed
CC_WARN_RESULT CC_CONST size_t cche_rng_seed_sizeof(void);

// MARK: - SecretKey

/// Represent a secret key as a polynomial in evaluation format.
struct cche_secret_key;
typedef struct cche_secret_key *cche_secret_key_t;
typedef const struct cche_secret_key *cche_secret_key_const_t;

/// @brief Return the number of bytes required to allocate a secret key with the given parameter context
/// @param param_ctx The parameter context that determines the secret key size.
CC_NONNULL_ALL CC_PURE size_t cche_secret_key_sizeof(cche_param_ctx_const_t param_ctx);

/// @brief Generate a new secret key
/// @param secret_key The secret key to generate
/// @param param_ctx The parameter context
/// @param rng The random number generator to use
/// @return `CCERR_OK` if key was successfully generated
CC_NONNULL_ALL CC_WARN_RESULT int
cche_secret_key_generate(cche_secret_key_t secret_key, cche_param_ctx_const_t param_ctx, struct ccrng_state *rng);

/// @brief Generate a new secret key from seed
/// @param secret_key The secret key to generate
/// @param param_ctx The parameter context
/// @param seed The random number seed to use
/// @return `CCERR_OK` if key was successfully generated
CC_NONNULL_ALL CC_WARN_RESULT int
cche_secret_key_generate_from_seed(cche_secret_key_t secret_key, cche_param_ctx_const_t param_ctx, cche_rng_seed_const_t seed);

// MARK: - Plaintext

/// Plaintext object
/// Contains a plaintext polynomial
typedef struct cche_plaintext *cche_plaintext_t;
typedef const struct cche_plaintext *cche_plaintext_const_t;

/// @brief Get plaintext size for a polynomial ctx
/// @param param_ctx The parameter context
/// @return Number of bytes required to hold the plaintext object
CC_NONNULL_ALL CC_WARN_RESULT CC_PURE size_t cche_plaintext_sizeof(cche_param_ctx_const_t param_ctx);

/// Plaintext object in Double CRT form
/// Contains a plaintext polynomial in evaluation form that is already in a suitable RNS base for multiplication with a
/// ciphertext.
typedef struct cche_dcrt_plaintext *cche_dcrt_plaintext_t;
typedef const struct cche_dcrt_plaintext *cche_dcrt_plaintext_const_t;

/// @brief Get Double CRT plaintext size for a polynomial ctx
/// @param param_ctx The parameter context
/// @param nmoduli Number of moduli in the RNS representation
/// @return Number of bytes required to hold the plaintext object
CC_NONNULL_ALL CC_WARN_RESULT CC_PURE size_t cche_dcrt_plaintext_sizeof(cche_param_ctx_const_t param_ctx, uint32_t nmoduli);

/// @brief Encodes a plaintext into a Double-CRT plaintext
/// @param r The destination Double-CRT plaintext
/// @param ptext The plaintext to encode
/// @param param_ctx The parameter context
/// @param nmoduli The number of moduli the resulting Double-CRT plaintext will have. This must be the same as the number of
/// moduli in the ciphertext that this Double-CRT plaintext can be multiplied with.
/// @return `CCERR_OK` if successful.
CC_NONNULL_ALL CC_WARN_RESULT int cche_dcrt_plaintext_encode(cche_dcrt_plaintext_t r,
                                                             cche_plaintext_const_t ptext,
                                                             cche_param_ctx_const_t param_ctx,
                                                             uint32_t nmoduli);

// MARK: - Encoding / Decoding

/// @brief Encodes a vector of unsigned coefficients values into a plaintext
/// @param ptext The plaintext to encode to; should be allocated via CCHE_PLAINTEXT_ALLOC_WS
/// @param param_ctx The parameter context
/// @param nvalues The number of values to encode; should be at most N
/// @param values The vector of coefficients to encode; each value should be in `[0, plaintext_modulus - 1]`.
/// @details Leaks `nvalues` through timing. Leaks the index of any out-of-range value, through error.
/// Encodes the polynomial `f(x) = values[0] + values[1] x + values_{N_1} x^{N-1}`, padding
/// with 0 coefficients if fewer than `N` values are provided.
/// @return `CCERR_OK` if successful, `CCERR_PARAMETER` on invalid input values
CC_NONNULL_ALL CC_WARN_RESULT int cche_encode_poly_uint64(cche_plaintext_t ptext,
                                                          cche_param_ctx_const_t param_ctx,
                                                          uint32_t nvalues,
                                                          const uint64_t *cc_counted_by(nvalues) values);

/// @brief Encodes a vector of unsigned values into a plaintext's SIMD slots.
/// @param ptext The plaintext to encode to; should be allocated via CCHE_PLAINTEXT_ALLOC_WS
/// @param nvalues The number of values to encode; should be at most N
CC_NONNULL_ALL CC_WARN_RESULT int cche_encode_simd_uint64(cche_plaintext_t ptext,
                                                          cche_param_ctx_const_t param_ctx,
                                                          uint32_t nvalues,
                                                          const uint64_t *cc_counted_by(nvalues) values);

/// @brief Encodes a vector of signed values into a plaintext's SIMD slots.
/// @param ptext The plaintext to encode to; should be allocated via CCHE_PLAINTEXT_ALLOC_WS
/// @param nvalues The number of values to encode; should be at most N
/// @param values The values to encode; each value should be in [-(plaintext_modulus >> 1), (plaintext_modulus - 1) >> 1)]
/// @details Leaks `nvalues` through timing. Leaks the index of any out-of-range value, through error.
/// @return `CCERR_OK` if successful, `CCERR_PARAMETER` on invalid input values
CC_NONNULL_ALL CC_WARN_RESULT int cche_encode_simd_int64(cche_plaintext_t ptext,
                                                         cche_param_ctx_const_t param_ctx,
                                                         uint32_t nvalues,
                                                         const int64_t *cc_counted_by(nvalues) values);

/// @brief Decodes a plaintext to a vector of its unsigned coefficient values
/// @param nvalues The number of values to decode
/// @param values Will store the decoded values; each value should be in [0, plaintext_modulus - 1].
/// @param ptext The plaintext to decode
/// @details Leaks `nvalues` through timing. Leaks the index of any out-of-range value, through error.
/// The plaintext polynomial `f(x) = a_0 + a_1 x + ... + a_{N-1} x^{N-1}` will be stored in values as
/// `values[0] = a_0, values[1] = a_1, ..., values[nvalues - 1] = a_{nvalues - 1}`.
/// @return `CCERR_OK` if successful
CC_NONNULL_ALL CC_WARN_RESULT int
cche_decode_poly_uint64(uint32_t nvalues, uint64_t *cc_counted_by(nvalues) values, cche_plaintext_const_t ptext);

/// @brief Decodes a plaintext's SIMD slots to a vector of unsigned values
/// @param nvalues The number of values to decode
/// @param values Will store the decoded values; each value should be in [0, plaintext_modulus - 1].
/// @param ptext The plaintext to decode
/// @details Leaks `nvalues` through timing. Leaks the index of any out-of-range value, through error.
/// @return `CCERR_OK` if successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_decode_simd_uint64(cche_param_ctx_const_t param_ctx,
                                                          uint32_t nvalues,
                                                          uint64_t *cc_counted_by(nvalues) values,
                                                          cche_plaintext_const_t ptext);

/// @brief Decodes a plaintext's SIMD slots to a vector of signed values
/// @param nvalues The number of values to decode
/// @param values Will store the decoded values; each value should be in
/// `[-(plaintext_modulus >> 1), (plaintext_modulus - 1) >>1)]`
/// @param ptext The plaintext to decode
/// @details Leaks `nvalues` through timing. Leaks the index of any out-of-range value, through error.
/// @return `CCERR_OK` if successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_decode_simd_int64(cche_param_ctx_const_t param_ctx,
                                                         uint32_t nvalues,
                                                         int64_t *cc_counted_by(nvalues) values,
                                                         cche_plaintext_const_t ptext);

// MARK: - Ciphertext

/// Ciphertext object
/// Contains polynomials in coefficient format with the same context
struct cche_ciphertext_coeff;
typedef struct cche_ciphertext_coeff *cche_ciphertext_coeff_t;
typedef const struct cche_ciphertext_coeff *cche_ciphertext_coeff_const_t;

/// Ciphertext object
/// Contains polynomials in evaluation format with the same context
struct cche_ciphertext_eval;
typedef struct cche_ciphertext_eval *cche_ciphertext_eval_t;
typedef const struct cche_ciphertext_eval *cche_ciphertext_eval_const_t;

/// Default number of RLWE polynomials in a freshly encrypted ciphertext
/// This number may increase with ciphertext-ciphertext multiplication
CC_PURE uint32_t cche_ciphertext_fresh_npolys(void);

/// Default correction factor for a freshly encrypted ciphertext
CC_PURE uint64_t cche_ciphertext_fresh_correction_factor(void);

/// @brief Get ciphertext size for a polynomial ctx
/// @param param_ctx The parameter context
/// @param nmoduli The number of moduli
/// @param npolys The number of polynomials that the ciphertext has
/// @return Number of bytes required to hold the ciphertext object
CC_NONNULL_ALL CC_WARN_RESULT CC_PURE size_t cche_ciphertext_sizeof(cche_param_ctx_const_t param_ctx,
                                                                    uint32_t nmoduli,
                                                                    uint32_t npolys);

/// @brief Get the correction factor for a ciphertext
/// @param ctext The ciphertext
CC_NONNULL_ALL CC_WARN_RESULT CC_PURE uint64_t cche_ciphertext_correction_factor(cche_ciphertext_coeff_const_t ctext);

/// @brief Performs the forward NTT on each polynomial in the ciphertext
/// @param ctext The input/output ciphertext; the output ciphertext can be cast to cche_ciphertext_eval_t
/// @return `CCERR_OK` if successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_fwd_ntt(cche_ciphertext_coeff_t ctext);

/// @brief Performs the inverse NTT on each polynomial in the ciphertext
/// @param ctext The input/output ciphertext; the output ciphertext can be cast to cche_ciphertext_coeff_t
/// @return `CCERR_OK` if successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_inv_ntt(cche_ciphertext_eval_t ctext);

// MARK: - Ciphertext serialization / deserialization

/// @brief Number of bytes needed to serialize a ciphertext in coefficient format
/// @param ctext Ciphertext to serialize
/// @param nskip_lsbs i'th entry contains the number of least significant bits to omit from each serialized coefficient of the
/// i'th polynomial; if NULL, no bits are omitted
/// @return Number of bytes needed to hold a serialized version of `ctext`
CC_NONNULL((1))
CC_WARN_RESULT size_t cche_serialize_ciphertext_coeff_nbytes(cche_ciphertext_coeff_const_t ctext, const uint32_t *nskip_lsbs);

/// @brief Number of bytes needed to serialize a ciphertext in evaluation format
/// @param ctext Ciphertext to serialize
/// @return Number of bytes needed to hold a serialized version of `ctext`
CC_NONNULL_ALL CC_WARN_RESULT size_t cche_serialize_ciphertext_eval_nbytes(cche_ciphertext_eval_const_t ctext);

/// @brief Number of bytes needed to serialize the first polynomial of a ciphertext in coefficient format
/// @param ctext Ciphertext to serialize
/// @return Number of bytes needed to hold a serialized version of `ctext` first polynomial
/// @details The seeded serialization of a ciphertext is the serialization of the first polynomial of the ciphertext and the seed
/// to regenerate the second polynomial of the ciphertext.
CC_NONNULL_ALL CC_WARN_RESULT size_t cche_serialize_seeded_ciphertext_coeff_nbytes(cche_ciphertext_coeff_const_t ctext);

/// @brief Number of bytes needed to serialize the first polynomial of a ciphertext in evaluation format
/// @param ctext Ciphertext to serialize
/// @return Number of bytes needed to hold a serialized version of `ctext` first polynomial
/// @details The seeded serialization of a ciphertext is the serialization of the first polynomial of the ciphertext and the seed
/// to regenerate the second polynomial of the ciphertext.
CC_NONNULL_ALL CC_WARN_RESULT size_t cche_serialize_seeded_ciphertext_eval_nbytes(cche_ciphertext_eval_const_t ctext);

/// @brief Computes the maximum allowed number of LSBs to skip when serializing a ciphertext
/// @param nskip_lsbs i'th entry will store the maximum number of LSBs to skip for the i'th ciphertext polynomial
/// @param ctext Ciphertext to serialize
CC_NONNULL_ALL void cche_serialize_ciphertext_coeff_max_nskip_lsbs(uint32_t *nskip_lsbs, cche_ciphertext_coeff_const_t ctext);

/// @brief Serialize a ciphertext in coefficient format
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext
/// @param ctext The ciphertext to serialize; Must have less than 2^16 polynomials.
/// @param nskip_lsbs i'th entry contains the number of least significant bits to omit from each serialized coefficient of the
/// i'th polynomial. Should be `NULL` for ciphertexts with > 1 coefficient modulus.
/// @return `CCERR_OK` if the operation is successful
/// @details BFV decryption is unlikely to rely on the LSBs of the polynomials, so the LSBs may be omitted for more compact
/// serialization.
CC_NONNULL((2, 3))
CC_WARN_RESULT int cche_serialize_ciphertext_coeff(size_t nbytes,
                                                   uint8_t *cc_counted_by(nbytes) bytes,
                                                   cche_ciphertext_coeff_const_t ctext,
                                                   const uint32_t *nskip_lsbs);

/// @brief Serialize a ciphertext in evaluation format
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext
/// @param ctext The ciphertext to serialize; Must have less than 2^16 polynomials.
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL_ALL CC_WARN_RESULT int
cche_serialize_ciphertext_eval(size_t nbytes, uint8_t *cc_counted_by(nbytes) bytes, cche_ciphertext_eval_const_t ctext);

/// @brief Deserialize a ciphertext in coefficient format
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must be initialized with `cche_ciphertext_coeff_init`
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// @param param_ctx The parameter context
/// @param nmoduli Number of moduli in the ciphertext context
/// @param npolys Number of polynomials in the ciphertext
/// @param correction_factor  The ciphertext correction factor
/// @param nskip_lsbs i'th entry contains the number of least significant bits to omit from each serialized coefficient of the
/// i'th polynomial. If NULL, assumes no LSB bits are omitted.
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL((1, 3, 4))
CC_WARN_RESULT int cche_deserialize_ciphertext_coeff(cche_ciphertext_coeff_t ctext,
                                                     size_t nbytes,
                                                     const uint8_t *cc_counted_by(nbytes) bytes,
                                                     cche_param_ctx_const_t param_ctx,
                                                     uint32_t nmoduli,
                                                     uint32_t npolys,
                                                     uint64_t correction_factor,
                                                     const uint32_t *cc_counted_by(npolys) nskip_lsbs);

/// @brief Deserialize a ciphertext in evaluation format
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must be initialized with `cche_ciphertext_eval_init`
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// /// @param param_ctx The parameter context
/// @param nmoduli Number of moduli in the ciphertext context
/// @param npolys Number of polynomials in the ciphertext
/// @param correction_factor  The ciphertext correction factor
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_deserialize_ciphertext_eval(cche_ciphertext_eval_t ctext,
                                                                   size_t nbytes,
                                                                   const uint8_t *cc_counted_by(nbytes) bytes,
                                                                   cche_param_ctx_const_t param_ctx,
                                                                   uint32_t nmoduli,
                                                                   uint32_t npolys,
                                                                   uint64_t correction_factor);

/// @brief Serialize the first polynomial of a ciphertext in coefficient format
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext polynomial
/// @param ctext The ciphertext whose first polynomial to serialize
/// @return `CCERR_OK` if the operation is successful
/// @details The seeded serialization of a ciphertext is the serialization of the first polynomial of the ciphertext and the seed
/// to regenerate the second polynomial of the ciphertext.
CC_NONNULL_ALL CC_WARN_RESULT int
cche_serialize_seeded_ciphertext_coeff(size_t nbytes, uint8_t *cc_counted_by(nbytes) bytes, cche_ciphertext_coeff_const_t ctext);

/// @brief Serialize the first polynomial of a ciphertext in evaluation format
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext polynomial
/// @param ctext The ciphertext whose first polynomial to serialize
/// @return `CCERR_OK` if the operation is successful
/// @details The seeded serialization of a ciphertext is the serialization of the first polynomial of the ciphertext and the seed
/// to regenerate the second polynomial of the ciphertext.
CC_NONNULL_ALL CC_WARN_RESULT int
cche_serialize_seeded_ciphertext_eval(size_t nbytes, uint8_t *cc_counted_by(nbytes) bytes, cche_ciphertext_eval_const_t ctext);

/// @brief Deserialize a ciphertext in coefficient format using a seed
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must have `cche_ciphertext_fresh_npolys()`
/// polynomials.
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// @param seed The seed to regenerate the second polynomial.
/// @param correction_factor  The ciphertext correction factor
/// @return `CCERR_OK` if the operation is successful
/// @details The bytes array is assumed to contain the serialization of the first polynomial and the second polynomial of the
/// ciphertext is represented by the seed.
CC_NONNULL_ALL CC_WARN_RESULT int cche_deserialize_seeded_ciphertext_coeff(cche_ciphertext_coeff_t ctext,
                                                                           size_t nbytes,
                                                                           const uint8_t *cc_counted_by(nbytes) bytes,
                                                                           cche_rng_seed_const_t seed,
                                                                           cche_param_ctx_const_t param_ctx,
                                                                           uint32_t nmoduli,
                                                                           uint64_t correction_factor);

/// @brief Deserialize a ciphertext in evalutation format using a seed
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must have `cche_ciphertext_fresh_npolys()`
/// polynomials.
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// @param seed The seed to regenerate the second polynomial.
/// @param correction_factor  The ciphertext correction factor
/// @return `CCERR_OK` if the operation is successful
/// @details The bytes array is assumed to contain the serialization of the first polynomial and the second polynomial of the
/// ciphertext is represented by the seed.
CC_NONNULL_ALL CC_WARN_RESULT int cche_deserialize_seeded_ciphertext_eval(cche_ciphertext_eval_t ctext,
                                                                          size_t nbytes,
                                                                          const uint8_t *cc_counted_by(nbytes) bytes,
                                                                          cche_rng_seed_const_t seed,
                                                                          cche_param_ctx_const_t param_ctx,
                                                                          uint32_t nmoduli,
                                                                          uint64_t correction_factor);

// MARK: - Encrypt / Decrypt

/// @brief Symmetric encryption
/// @param ctext The ciphertext where to store the encrypted plaintext, must be allocated with `cche_ciphertext_fresh_npolys()`
/// polynomials
/// @param ptext The plaintext to encrypt.
/// @param param_ctx The parameter context where to get the polynomial context from
/// @param secret_key The secret key to use for the encryption
/// @param nmoduli The number of moduli that should be in the ciphertext context
/// @param seed if nonnull, then the seed used for generating `a` will be stored here.
/// @param rng The base rng to use for seed generation
/// @return `CCERR_OK` if operation was successful
/// @details Ciphertext is a tuple: `(-(as + delta * m + e), a)`, where `a` is uniformly random polynomial, `s` is the secret key,
/// `delta = floor(q / t)`, `m` is the plaintext and `e` is sampled from the error distribution.  If the seed pointer is nonnull,
/// the function additionally stores the seed to generate `a`.
CC_NONNULL((1, 2, 3, 4, 7))
CC_WARN_RESULT int cche_encrypt_symmetric(cche_ciphertext_coeff_t ctext,
                                          cche_plaintext_const_t ptext,
                                          cche_param_ctx_const_t param_ctx,
                                          cche_secret_key_const_t secret_key,
                                          uint32_t nmoduli,
                                          cche_rng_seed_t seed,
                                          struct ccrng_state *rng);

/// @brief Decrypt a ciphertext
/// @param ptext The polynomial where plaintext is written to
/// @param ctext The ciphertext to decrypt
/// @param secret_key The secret key to decrypt with
/// @return `CCERR_OK` if operation was successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_decrypt(cche_plaintext_t ptext,
                                               cche_param_ctx_const_t param_ctx,
                                               cche_ciphertext_coeff_const_t ctext,
                                               cche_secret_key_const_t secret_key);

// MARK: - Relinearization key

/// @brief Stores a relinearization key.
/// @details A relinearization key is a form of public key, derived from a secret key, used to perform key-switching.
/// Key-switching transforms a ciphertext encrypted under a secret key to a ciphertext encrypted under a different (related)
/// secret key. Specifically, given a secret key `s`, the relinearization key is used to transform a ciphertext encrypted from
/// `s^2` to a ciphertext encrypted under `s`. This allows transformation of a 3-polynomial ciphertext arising from
/// ciphertext-ciphertext multiplication to a regular 2-polynomial ciphertext.
struct cche_relin_key;
typedef struct cche_relin_key *cche_relin_key_t;
typedef const struct cche_relin_key *cche_relin_key_const_t;

/// @brief Returns the number of bytes required to allocate a relinearization key
/// @param param_ctx Parameter context
CC_WARN_RESULT CC_NONNULL_ALL CC_PURE size_t cche_relin_key_sizeof(cche_param_ctx_const_t param_ctx);

/// @brief Generates a relinearization key
/// @param relin_key Relinearization key to generate; should be initialized with `CCHE_RELIN_KEY_ALLOC_WS`
/// @param secret_key Secret key to use to derive the relinearization key
/// @param param_ctx Parameter context
/// @param nseeds Number of seeds in the seeds buffer; must be set to 0 if `seeds` is NULL
/// @param seeds Optionally, a buffer to an array of RNG seeds that will store the seed for the second polynomial of ciphertexts
/// @param rng The base rng to use for seed generation
/// @return CCERR_OK if successful
/// @details Let `q_ks` denote the key-switching modulus, `s_B(x) = secret_key` denote the target secret key, and `s_A(x) =
/// s_B(x)^2` denote the source secret key. The generated relinearization key will enable key-switching from `s_A` to `s_B`. Also
/// let `Q_i = q_0 * ... * q_i`. Given a parameter context of `L > 1` RNS moduli, the relinearization key consists of `L - 1`
/// two-polynomial ciphertexts:
/// ([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `\tilde{P})_{Q_i}(s_A)_j = [s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{Q_i}` and
/// `\tilde{Q_j} = q_j`.
CC_WARN_RESULT CC_NONNULL((1, 2, 3, 6)) int cche_relin_key_generate(cche_relin_key_t relin_key,
                                                                    cche_secret_key_const_t secret_key,
                                                                    cche_param_ctx_const_t param_ctx,
                                                                    uint32_t nseeds,
                                                                    uint8_t *cc_counted_by(nseeds) seeds,
                                                                    struct ccrng_state *rng);

/// @brief Saves a relinearization key ciphertexts' first polynomials
/// @param nbytes_poly0s The number of bytes than can be stored in the `poly0s` buffer
/// @param poly0s The buffer where to serialize the first component of each ciphertext
/// @param relin_key The relinearization key to save
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_relin_key_save(uint32_t nbytes_poly0s, uint8_t *poly0s, cche_relin_key_const_t relin_key);

/// @brief Loads a relinearization key
/// @param relin_key Relinearization key to load; should be initialized with `CCHE_RELIN_KEY_ALLOC_WS`
/// @param param_ctx Parameter context
/// @param nbytes_poly0s The number of bytes than are stored in the `poly0s` buffer
/// @param poly0s An array of pointers to serialized bytes of the first polynomial of the ciphertexts
/// @param nbytes_seeds Number of bytes in the seeds buffer
/// @param seeds Array of RNG seeds that store the seed for the second polynomial of ciphertexts
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_relin_key_load(cche_relin_key_t relin_key,
                                                      cche_param_ctx_const_t param_ctx,
                                                      uint32_t nbytes_poly0s,
                                                      const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                                                      uint32_t nbytes_seeds,
                                                      const uint8_t *cc_counted_by(nbytes_seeds) seeds);

// MARK: - GaloisKey

/// @brief Stores a Galois key for several Galois elements.
/// @details A Galois key is a form of public key, derived from a secret key, used to perform key-switching.
/// Key-switching transforms a ciphertext encrypted under a secret key to a ciphertext encrypted under a different (related)
/// secret key. Specifically, given a Galois element `gal`, a Galois key enables key switching from secret key polynomial
/// `s(x^{gal})` to secret poly polnomial `s(x)`. Each Galois element must be odd in [3, 2N - 1].
///
/// At a high level, the Galois key can be thought of as an encryption of `s(x^{gal})` using `s(x)`. However, for better
/// noise growth, we use a different formulation to generate the Galois key, namely hybrid RNS key-switching with
/// `\alpha = 1` key-switching modulus. Let `q_ks` denote the key-switching modulus, `s_B(x) = secret_key` denote the
/// target secret key, and `s_A(x) = s_B(x^{galois_elt})` denote the source secret key. The generated Galois key will
/// enable key-switching from `s_A` to `s_B`.
///
/// Also let `Q_i = q_0 * ... * q_i` for `0 <= i < L - 1`.
/// Then, given a parameter context of `L > 1` RNS moduli, the Galois key consists of `L - 1` two-polynomial ciphertexts:
/// `([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `\tilde{P})_{Q_i}(s_A)_j = [s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{Q_i}` and
/// `\tilde{Q_j} = q_j`.
struct cche_galois_key;
typedef struct cche_galois_key *cche_galois_key_t;
typedef const struct cche_galois_key *cche_galois_key_const_t;

/// @brief Returns the number of bytes required to allocate a Galois key
/// @param param_ctx Parameter context
/// @param ngalois_elts Number of Galois elements in the Galois key
CC_WARN_RESULT CC_NONNULL_ALL CC_PURE size_t cche_galois_key_sizeof(cche_param_ctx_const_t param_ctx, uint32_t ngalois_elts);

/// @brief Generates a Galois key
/// @param galois_key Galois key to generate; should be initialized with `CCHE_GALOIS_KEY_ALLOC_WS`
/// @param ngalois_elts Number of Galois elements in the Galois key
/// @param galois_elts List of Galois elements; each should be unique and odd in [3, 2N - 1]
/// @param secret_key Secret key to use to derive the Galois key
/// @param param_ctx Parameter context
/// @param nseeds Number of seeds in the seeds buffer; must be set to 0 if `seeds` is NULL
/// @param seeds Optionally, a buffer to an array of RNG seeds that will store the seed for the second polynomial of ciphertexts
/// @param rng The base rng to use for seed generation
/// @return CCERR_OK if successful
/// @details We use hybrid RNS key-switching with `\alpha = 1` key-switching modulus
/// Let `q_ks` denote the key-switching modulus, `s_B(x) = secret_key` denote the target secret key, and `s_A(x) =
/// s_B(x^{galois_elt})` denote the source secret key. The generated Galois key will enable key-switching from `s_A` to `s_B`.
/// Also let `Q_i = q_0 * ... * q_i`. Given a parameter context of `L > 1` RNS moduli, the Galois key consists of `L - 1`
/// two-polynomial ciphertexts:
/// ([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `\tilde{P})_{Q_i}(s_A)_j = [s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{Q_i}` and
/// `\tilde{Q_j} = q_j`.
CC_WARN_RESULT CC_NONNULL((1, 3, 4, 5, 8)) int cche_galois_key_generate(cche_galois_key_t galois_key,
                                                                        uint32_t ngalois_elts,
                                                                        const uint32_t *cc_counted_by(ngalois_elts) galois_elts,
                                                                        cche_secret_key_const_t secret_key,
                                                                        cche_param_ctx_const_t param_ctx,
                                                                        uint32_t nseeds,
                                                                        uint8_t *cc_counted_by(nseeds) seeds,
                                                                        struct ccrng_state *rng);

/// @brief Saves a Galois key ciphertexts' first polynomials
/// @param nbytes_poly0s The number of bytes than can be stored in the `poly0s` buffer
/// @param poly0s The buffer where to serialize the first component of each ciphertext
/// @param galois_key The galois key to save
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int
cche_galois_key_save(uint32_t nbytes_poly0s, uint8_t *poly0s, cche_galois_key_const_t galois_key);

/// @brief Loads a Galois key
/// @param galois_key Galois key to load; should be initialized with `CCHE_GALOIS_KEY_ALLOC_WS`
/// @param ngalois_elts Number of Galois elements in the Galois key
/// @param galois_elts List of Galois elements; each should be unique and odd in [3, 2N - 1]
/// @param param_ctx Parameter context
/// @param nbytes_poly0s The number of bytes than are stored in the `poly0s` buffer
/// @param poly0s An array of pointers to serialized bytes of the first polynomial of the ciphertexts
/// @param nbytes_seeds Number of bytes in the seeds buffer
/// @param seeds Array of RNG seeds that store the seed for the second polynomial of ciphertexts
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_galois_key_load(cche_galois_key_t galois_key,
                                                       uint32_t ngalois_elts,
                                                       const uint32_t *galois_elts,
                                                       cche_param_ctx_const_t param_ctx,
                                                       uint32_t nbytes_poly0s,
                                                       const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                                                       uint32_t nbytes_seeds,
                                                       const uint8_t *cc_counted_by(nbytes_seeds) seeds);

/// @brief Computes the Galois element for a left rotation of the plaintext rows
/// @param galois_elt Will store the Galois element
/// @param step The number of slots by which to rotate left; must be in [1, N - 1]
/// @param degree The polynomial modulus degree
/// @return CCERR_OK if successful
/// @details Not constant time; the step and Galois element are considered public
CC_WARN_RESULT CC_NONNULL_ALL int
cche_ciphertext_galois_elt_rotate_rows_left(uint32_t *galois_elt, uint32_t step, uint32_t degree);

/// @brief Computes the Galois element for a right rotation of the plaintext rows
/// @param galois_elt Will store the Galois element
/// @param step The number of slots by which to rotate right; must be in [1, N - 1]
/// @param degree The polynomial modulus degree
/// @return CCERR_OK if successful
/// @details Not constant time; the step and Galois element are considered public
CC_WARN_RESULT CC_NONNULL_ALL int
cche_ciphertext_galois_elt_rotate_rows_right(uint32_t *galois_elt, uint32_t step, uint32_t degree);

/// @brief Computes the Galois element for a column rotation of the plaintext
/// @param galois_elt Will store the Galois element
/// @param degree The polynomial modulus degree
/// @return CCERR_OK if successful
/// @details Not constant time; the Galois element is considered public
CC_WARN_RESULT CC_NONNULL_ALL int cche_ciphertext_galois_elt_swap_columns(uint32_t *galois_elt, uint32_t degree);

/// @brief Performs the Galois automorphism `f(x) -> f(x^{galois_elt})` on an encrypted message
/// @param r The output ciphertext
/// @param ctext The input ciphertext; should not overlap with or equal r.
/// @param galois_elt The Galois element
/// @param galois_key The Galois key; should contain the Galois element
/// @details If the original ciphertext encrypts the polynomial f(x), the resulting ciphertext will encrypt the message
/// f(x^{galois_elt}), encrypted under the same secret key.
/// @return `CCERR_OK` if successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_ciphertext_apply_galois(cche_ciphertext_coeff_t r,
                                                               cche_ciphertext_coeff_const_t ctext,
                                                               uint32_t galois_elt,
                                                               cche_galois_key_const_t galois_key);

// MARK: - Decomposing ciphertext to plaintexts

/// @brief Returns the number of plaintext polynomials required to decompose a ciphertext when skipping least significant bits
/// @param ctext The ciphertext to decompose
/// @param skip_lsbs If NULL do not skip any bits, else skip `[poly_idx * nmoduli + rns_idx]` least significant bits from each
/// coefficient
/// @details The returned number of plaintext polynomials required to decompose the ciphertext polynomials with enough precision
/// for a lossless re-composition.
CC_NONNULL((1))
uint32_t cche_ciphertext_coeff_decompose_nptexts(
    cche_ciphertext_coeff_const_t ctext,
    const uint32_t *cc_counted_by(ctext->npoly *cche_ciphertext_coeff_ctx(ctext)->dims.nmoduli) skip_lsbs);

/// @brief Composes a ciphertext from a plaintext array skipping least significant bits
/// @param ctext Will store the composed ciphertext; should be initialized (e.g. with cche_ciphertext_coeff_init)
/// @param nptexts Number of plaintexts
/// @param ptexts Array of pointers to plaintexts
/// @param nmoduli Number of moduli in the ciphertext
/// @param correction_factor Correction factor for the composed ciphertext
/// @param param_ctx Parameter context
/// @param skip_lsbs If NULL do not skip any bits, else skip `[poly_idx * nmoduli + rns_idx]` least significant bits from each
/// coefficient
/// @return `CCERR_OK` if ciphertext was successfully composed
/// @details Each coefficient of the ciphertext is composed from the word decomposition
/// `[x % w, (x >> w) % w, (x >> 2 * w) % w, ...]` with base `w = 2^{floor{log_2{t}}`, where `t` is the plaintext modulus. This
/// decomposition is created via `cche_ciphertext_coeff_decompose`.
CC_NONNULL((1, 3, 4))
CC_WARN_RESULT
int cche_ciphertext_coeff_compose(cche_ciphertext_coeff_t ctext,
                                  uint32_t nptexts,
                                  cche_plaintext_const_t *cc_counted_by(nptexts) ptexts,
                                  cche_param_ctx_const_t param_ctx,
                                  uint32_t nmoduli,
                                  uint64_t correction_factor,
                                  const uint32_t *cc_counted_by(cche_ciphertext_fresh_npolys() * nmoduli) skip_lsbs);

/// @brief Decomposes a ciphertext into plaintext polynomials skipping least significant bits
/// @param nptexts Number of plaintexts
/// @param ptexts Array of pointers to plaintexts
/// @param ctext The ciphertext to decompose
/// @param skip_lsbs If NULL do not skip any bits, else skip `[poly_idx * nmoduli + rns_idx]` least significant bits from each
/// coefficient
/// @return `CCERR_OK` if ciphertext is successfully decomposed
/// @details Performs word decomposition on each coefficient in the ciphertext using base `w = 2^{floor{log_2{t}}`,
/// where t is the plaintext modulus. That is, each ciphertext polynomial's coefficient x is decomposed as
/// `[x % w, (x >> w) % w, (x >> 2 * w) % w, ...]` with enough factors to correctly reconstruct the ciphertext using
/// `cche_ciphertext_coeff_compose`.
/// Leaks the ciphertext number of polynomials and context through timing
CC_NONNULL((2, 3))
CC_WARN_RESULT int
cche_ciphertext_coeff_decompose(uint32_t nptexts,
                                cche_plaintext_t *cc_counted_by(nptexts) ptexts,
                                cche_ciphertext_coeff_const_t ctext,
                                const uint32_t *cc_counted_by(ctext->npoly *cche_ciphertext_coeff_ctx(ctext)->dims.nmoduli)
                                    skip_lsbs);

// MARK: - Converting bytes to coefficients

/// @brief Convert a sequence of bytes to a sequence of `ccrns_int` where each coefficient holds `bits_per_coeff` bits
/// @param ncoeffs The number of coefficients
/// @param coeffs Converted coefficients will be written here
/// @param nbytes Number of bytes to convert
/// @param bytes The array of bytes to convert to coefficients
/// @param bits_per_coeff Number of bits that can be encoded in one coefficient
/// @details `ncoeffs` and `nbytes` must be related to each other. Either `ncoeffs` = number of coefficients to hold `nbytes`
/// bytes or `nbytes` = number of bytes to hold `ncoeff` coefficients.
CC_NONNULL_ALL CC_WARN_RESULT int cche_bytes_to_coeffs(size_t ncoeffs,
                                                       uint64_t *cc_counted_by(ncoeffs) coeffs,
                                                       size_t nbytes,
                                                       const uint8_t *cc_counted_by(nbytes) bytes,
                                                       size_t bits_per_coeff);

/// @brief Convert a sequence of coefficients into a sequence of bytes, where each coefficient holds `bits_per_coeff` bits
/// @param nbytes Number of bytes
/// @param bytes Converted bytes will be written here
/// @param ncoeffs The number of coefficients to convert
/// @param coeffs Coefficients to convert
/// @param bits_per_coeff Number of bits that are encoded in one coefficient
/// @details `ncoeffs` and `nbytes` must be related to each other. Either `ncoeffs` = number of coefficients to hold `nbytes`
/// bytes or `nbytes` = number of bytes to hold `ncoeff` coefficients.
CC_NONNULL_ALL CC_WARN_RESULT int cche_coeffs_to_bytes(size_t nbytes,
                                                       uint8_t *cc_counted_by(nbytes) bytes,
                                                       size_t ncoeffs,
                                                       const uint64_t *cc_counted_by(ncoeffs) coeffs,
                                                       size_t bits_per_coeff);

// MARK: - Operations

/// @brief Adds a plaintext to a ciphertext
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The plaintext
/// @return `CCERR_OK` if operation was successful
/// @details `ctext` must have exactly `cche_ciphertext_fresh_npolys()` polynomials. And `r` must be have the same context and
/// shape as `ctext`.
CC_NONNULL_ALL CC_WARN_RESULT int
cche_ciphertext_plaintext_add(cche_ciphertext_coeff_t r, cche_ciphertext_coeff_const_t ctext, cche_plaintext_const_t ptext);

/// @brief Multiplies a ciphertext with a plaintext
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The plaintext
/// @return `CCERR_OK` if the operation was successful
/// @details `r` and `ctext` should not overlap, unless `r == ctext`
CC_NONNULL_ALL CC_WARN_RESULT int
cche_ciphertext_coeff_plaintext_mul(cche_ciphertext_coeff_t r, cche_ciphertext_coeff_const_t ctext, cche_plaintext_const_t ptext);

/// @brief Multiplies a ciphertext with a Double-CRT plaintext
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The Double-CRT plaintext
/// @return `CCERR_OK` if the operation was successful
/// @details `r` and `ctext` should not overlap, unless `r == ctext`
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_coeff_dcrt_plaintext_mul(cche_ciphertext_coeff_t r,
                                                                           cche_ciphertext_coeff_const_t ctext,
                                                                           cche_dcrt_plaintext_const_t ptext);

/// @brief Multiplies a ciphertext with a plaintext
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The plaintext
/// @return `CCERR_OK` if the operation was successful
/// @details `r` and `ctext` should not overlap, unless `r == ctext`
CC_NONNULL_ALL CC_WARN_RESULT int
cche_ciphertext_eval_plaintext_mul(cche_ciphertext_eval_t r, cche_ciphertext_eval_const_t ctext, cche_plaintext_const_t ptext);

/// @brief Multiplies a ciphertext with a Double-CRT plaintext
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The Double-CRT plaintext
/// @return `CCERR_OK` if the operation was successful
/// @details `r` and `ctext` should not overlap, unless `r == ctext`
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_eval_dcrt_plaintext_mul(cche_ciphertext_eval_t r,
                                                                          cche_ciphertext_eval_const_t ctext,
                                                                          cche_dcrt_plaintext_const_t ptext);

#endif /* #if CC_PRIVATE_CRYPTOKIT */

#endif /* _CORECRYPTO_CCHE_PRIV_H_ */
