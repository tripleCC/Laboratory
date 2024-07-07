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

#ifndef _CORECRYPTO_CCHE_INTERNAL_H_
#define _CORECRYPTO_CCHE_INTERNAL_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccn.h>
#include "cc_memory.h"
#include "cc_workspaces.h"
#include <corecrypto/cche_priv.h>
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_random.h"
#include "cche_param_ctx.h"
#include "cche_decrypt_ctx.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Get the coefficient moduli
#define CCHE_ENCRYPT_PARAMS_COEFF_MODULI_CONST(params) ((const ccrns_int *)(params)->moduli)

/// @brief Returns the number of cc_units required to store cche_encrypt_params
/// @param nmoduli Number of moduli
CC_INLINE cc_size cche_encrypt_params_nof_n(uint32_t nmoduli)
{
    // struct storage, rounded up to nearest number of cc_units
    cc_size rv = cc_ceiling(sizeof_struct_cche_encrypt_params() + nmoduli * sizeof(ccrns_int), sizeof_cc_unit());
    return rv;
}

/// @brief Copies encryption parameters `dest := src`
/// @param dest The destination encryption parmeters; should be allocated with the same `nmoduli` as the source.
/// @param src The source encryption parameters
CC_NONNULL_ALL CC_INLINE void cche_encrypt_params_copy(cche_encrypt_params_t dest, cche_encrypt_params_const_t src)
{
    cc_memcpy(dest, src, ccn_sizeof_n(cche_encrypt_params_nof_n(src->nmoduli)));
}

/// @brief Returns the encryption parameters from predefined encryption parameters
/// @warning The HE scheme of the returned paramters is unspecified.
cche_encrypt_params_const_t cche_encrypt_params_get(cche_predefined_encryption_params_t params);

/// Represent a secret key as a polynomial in evaluation format.
/// Must have the same bit representation as  ccpolyzp_po2cyc_eval, to enable pointer casting.
struct cche_secret_key {
    __CCPOLYZP_PO2CYC_ELEMENTS_DEFINITION
};

/// Enables pointer casting between ccpolyzp_po2cyc_eval_t and cche_secret_key_t
cc_static_assert(sizeof(struct ccpolyzp_po2cyc_eval) == sizeof(struct cche_secret_key),
                 "ccpolyzp_po2cyc_eval and cche_secret_key must have same size");

/// @brief Returns the number of cc_units required to allocate a secret key with the given parameter context
/// @param param_ctx Parameter context
CC_NONNULL_ALL CC_INLINE cc_size cche_secret_key_nof_n(cche_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_const_t ctx = cche_param_ctx_encrypt_key_context(param_ctx);
    return ccpolyzp_po2cyc_nof_n(&ctx->dims);
}

/// @brief Allocates memory for a cche_secret_key
/// @param ws Workspace to allocate memory from
/// @param param_ctx The parameter context
/// @return A pointer to the allocated memory
#define CCHE_SECRET_KEY_ALLOC_WS(ws, param_ctx) (cche_secret_key_t) CC_ALLOC_WS(ws, cche_secret_key_nof_n((param_ctx)))

/// @brief Generate a new secret key
/// @param ws Workspace
/// @param secret_key The secret key to generate
/// @param param_ctx The parameter context
/// @param rng The random number generator to use
/// @return CCERR_OK if key was successfully generated
CC_NONNULL_ALL CC_WARN_RESULT int
cche_secret_key_generate_ws(cc_ws_t ws, cche_secret_key_t secret_key, cche_param_ctx_const_t param_ctx, struct ccrng_state *rng);

/// @brief Generate a new secret key from seed
/// @param ws Workspace
/// @param secret_key The secret key to generate
/// @param param_ctx The parameter context
/// @param seed The random number seed to use
/// @return `CCERR_OK` if key was successfully generated
CC_NONNULL_ALL CC_WARN_RESULT int cche_secret_key_generate_from_seed_ws(cc_ws_t ws,
                                                                        cche_secret_key_t secret_key,
                                                                        cche_param_ctx_const_t param_ctx,
                                                                        cche_rng_seed_const_t seed);

#define __CCHE_CIPHERTEXT_ELEMENTS_DEFINITION                          \
    cche_param_ctx_const_t param_ctx; /* reference to parameter ctx */ \
    uint32_t npolys;                  /* number of polynomials*/       \
    ccrns_int correction_factor;      /* correction factor */          \
    cc_unit data[];                   /* storage for `npolys` polynomials */

/// Ciphertext object with polynomials in coefficient format
/// Contains polynomials with the same context
struct cche_ciphertext_coeff {
    __CCHE_CIPHERTEXT_ELEMENTS_DEFINITION
} CC_ALIGNED(CCN_UNIT_SIZE);

/// Ciphertext object with polynomials in evaluation format
/// Contains polynomials with the same context
/// Must have same bit representation as cche_ciphertext_coeff, to enable pointer casting between cche_ciphertext_coeff_t and
/// cche_ciphertext_eval_t
struct cche_ciphertext_eval {
    __CCHE_CIPHERTEXT_ELEMENTS_DEFINITION
} CC_ALIGNED(CCN_UNIT_SIZE);

/// Enables pointer casting between cche_ciphertext_coeff_t and cche_ciphertext_eval_t
/// Useful to avoid ciphertext copies for in-place operations.
cc_static_assert(sizeof(struct cche_ciphertext_coeff) == sizeof(struct cche_ciphertext_eval),
                 "cche_ciphertext_coeff and cche_ciphertext_eval must have same size");

/// @brief Get the polynomial context from a ciphertext in coefficient format
/// @param ctext The ciphertext where to get the context from, must have at least 1 polynomial.
/// @return Polynomial context that the ciphertext has.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t cche_ciphertext_coeff_ctx(cche_ciphertext_coeff_const_t ctext)
{
    cc_assert(ctext->npolys);
    ccpolyzp_po2cyc_coeff_const_t first = (ccpolyzp_po2cyc_coeff_const_t)(ctext->data);
    return first->context;
}

/// @brief Get the polynomial context from a ciphertext in evaluation format
/// @param ctext The ciphertext where to get the context from, must have at least 1 polynomial.
/// @return Polynomial context that the ciphertext has.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t cche_ciphertext_eval_ctx(cche_ciphertext_eval_const_t ctext)
{
    return (ccpolyzp_po2cyc_ctx_const_t)cche_ciphertext_coeff_ctx((cche_ciphertext_coeff_const_t)ctext);
}

/// @brief Get the polynomial from a ciphertext in coefficient format
/// @param ctext The ciphertext where to get the polynomial from
/// @param poly_idx the index of the polynomial to get, must be either 0 or 1
/// @return Polynomial from the ciphertext
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_coeff_t cche_ciphertext_coeff_polynomial(cche_ciphertext_coeff_t ctext,
                                                                                  uint32_t poly_idx)
{
    cc_assert(poly_idx < ctext->npolys);
    ccpolyzp_po2cyc_coeff_t first = (ccpolyzp_po2cyc_coeff_t)(ctext->data);
    cc_size poly_size = ccpolyzp_po2cyc_nof_n(&first->context->dims);
    return (ccpolyzp_po2cyc_coeff_t)((cc_unit *)first + poly_idx * poly_size);
}

/// @brief Get the polynomial from a ciphertext in coefficient format
/// @param ctext The ciphertext where to get the polynomial from
/// @param poly_idx the index of the polynomial to get, must be either 0 or 1
/// @return Polynomial from the ciphertext
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_coeff_const_t cche_ciphertext_coeff_polynomial_const(cche_ciphertext_coeff_const_t ctext,
                                                                                              uint32_t poly_idx)
{
    cc_assert(poly_idx < ctext->npolys);
    ccpolyzp_po2cyc_coeff_const_t first = (ccpolyzp_po2cyc_coeff_const_t)ctext->data;
    cc_size poly_size = ccpolyzp_po2cyc_nof_n(&first->context->dims);
    return (ccpolyzp_po2cyc_coeff_const_t)((const cc_unit *)first + poly_idx * poly_size);
}

/// @brief Get the polynomial from a ciphertext in evaluation format
/// @param ctext The ciphertext where to get the polynomial from
/// @param poly_idx the index of the polynomial to get, must be either 0 or 1
/// @return Polynomial from the ciphertext
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_eval_t cche_ciphertext_eval_polynomial(cche_ciphertext_eval_t ctext, uint32_t poly_idx)
{
    return (ccpolyzp_po2cyc_eval_t)cche_ciphertext_coeff_polynomial((cche_ciphertext_coeff_t)ctext, poly_idx);
}

/// @brief Get the polynomial from a ciphertext in evaluation format
/// @param ctext The ciphertext where to get the polynomial from
/// @param poly_idx the index of the polynomial to get, must be either 0 or 1
/// @return Polynomial from the ciphertext
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_eval_const_t cche_ciphertext_eval_polynomial_const(cche_ciphertext_eval_const_t ctext,
                                                                                            uint32_t poly_idx)
{
    return (ccpolyzp_po2cyc_eval_const_t)cche_ciphertext_coeff_polynomial_const((cche_ciphertext_coeff_const_t)ctext, poly_idx);
}

/// @brief Get ciphertext size for a polynomial ctx
/// @param dims The dimensions of the polynomial context in the ciphertext
/// @param npolys The number of polynomials that the ciphertext has
/// @return Number of cc_units required to hold the ciphertext object
CC_NONNULL_ALL CC_INLINE cc_size cche_ciphertext_nof_n(ccpolyzp_po2cyc_dims_const_t dims, uint32_t npolys)
{
    // struct storage, rounded up to nearest number of cc_units
    cc_size rv = cc_ceiling(sizeof_struct_cche_ciphertext(), sizeof_cc_unit());
    // storage for `npolys` polynomials
    rv += npolys * ccpolyzp_po2cyc_nof_n(dims);
    return rv;
}

/// @brief Allocate memory for a cche_ciphertext_coeff
/// @param poly_ctx The polynomial context that the ciphertext has
/// @param npolys The number of polynomials that the ciphertext has
/// @return A pointer to the allocated memory
#define CCHE_CIPHERTEXT_COEFF_ALLOC_WS(ws, poly_ctx, npolys) \
    ((cche_ciphertext_coeff_t)CC_ALLOC_WS(ws, cche_ciphertext_nof_n(&(poly_ctx)->dims, (npolys))))

/// @brief Allocate memory for a cche_ciphertext_eval
/// @param poly_ctx The polynomial context that the ciphertext has
/// @param npolys The number of polynomials that the ciphertext has
/// @return A pointer to the allocated memory
#define CCHE_CIPHERTEXT_EVAL_ALLOC_WS(ws, poly_ctx, npolys) \
    ((cche_ciphertext_eval_t)(CCHE_CIPHERTEXT_COEFF_ALLOC_WS((ws), (poly_ctx), (npolys))))

/// @brief Copies a ciphertext in coefficient format, r := x
/// @param r The destination ciphertext
/// @param x The source ciphertext
CC_NONNULL_ALL CC_INLINE void cche_ciphertext_coeff_copy(cche_ciphertext_coeff_t r, cche_ciphertext_coeff_const_t x)
{
    ccpolyzp_po2cyc_dims_const_t dims = &cche_ciphertext_coeff_ctx(x)->dims;
    cc_memmove(r, x, CCN_UNIT_SIZE * cche_ciphertext_nof_n(dims, x->npolys));
}

/// @brief Copies a ciphertext in evaluation format, r := x
/// @param r The destination ciphertext
/// @param x The source ciphertext
CC_NONNULL_ALL CC_INLINE void cche_ciphertext_eval_copy(cche_ciphertext_eval_t r, cche_ciphertext_eval_const_t x)
{
    cche_ciphertext_coeff_copy((cche_ciphertext_coeff_t)r, (cche_ciphertext_coeff_const_t)x);
}

/// @brief Get the polynomial from a plaintext in coefficient format
/// @param ptext The plaintext where to get the polynomial from
/// @return Polynomial from the plaintext.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_coeff_t cche_plaintext_polynomial(cche_plaintext_t ptext)
{
    return (ccpolyzp_po2cyc_coeff_t)ptext;
}

/// @brief Get the polynomial from a plaintext in coefficient format
/// @param ptext The plaintext where to get the polynomial from
/// @return Polynomial from the plaintext.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_coeff_const_t cche_plaintext_polynomial_const(cche_plaintext_const_t ptext)
{
    return (ccpolyzp_po2cyc_coeff_const_t)ptext;
}

/// @brief Get the polynomial context
/// @param ptext The plaintext where to get the context from
/// @return Polynomial context that the plaintext has.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t cche_plaintext_ctx(cche_plaintext_const_t ptext)
{
    return cche_plaintext_polynomial_const(ptext)->context;
}

/// @brief Get the plaintext modulus
/// @param ptext The plaintext where to get the modulus from
CC_NONNULL_ALL CC_INLINE ccrns_int cche_plaintext_modulus(cche_plaintext_const_t ptext)
{
    return cche_plaintext_ctx(ptext)->ccrns_q_last.value;
}

/// @brief Get plaintext size for a polynomial ctx
/// @param dims The dimensions of the plaintext's polynomial's context
/// @return Number of cc_units required to hold the plaintext object
CC_NONNULL_ALL CC_INLINE cc_size cche_plaintext_nof_n(ccpolyzp_po2cyc_dims_const_t dims)
{
    // storage for polynomial
    return ccpolyzp_po2cyc_nof_n(dims);
}

/// @brief Allocate memory for a cche_plaintext
/// @param poly_ctx The polynomial context that the plaintext has
/// @return A pointer to the allocated memory
#define CCHE_PLAINTEXT_ALLOC_WS(ws, poly_ctx) (cche_plaintext_t) CC_ALLOC_WS(ws, cche_plaintext_nof_n(&(poly_ctx)->dims))

/// @brief Copies a plaintext, r := x
/// @param r The destination plaintext
/// @param x The source plaintext
CC_NONNULL_ALL CC_INLINE void cche_plaintext_copy(cche_plaintext_t r, cche_plaintext_const_t x)
{
    cc_size size = ccn_sizeof_n(cche_plaintext_nof_n(&cche_plaintext_ctx(x)->dims));
    cc_memmove(r, x, size);
}

/// @brief Get the polynomial context
/// @param ptext The plaintext where to get the context from
/// @return Polynomial context that the plaintext has.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t cche_dcrt_plaintext_ctx(cche_dcrt_plaintext_const_t ptext)
{
    ccpolyzp_po2cyc_coeff_const_t poly = (ccpolyzp_po2cyc_coeff_const_t)ptext;
    return poly->context;
}

/// @brief Get the polynomial from a plaintext in eval format
/// @param ptext The plaintext where to get the polynomial from
/// @return Polynomial from the plaintext.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_eval_t cche_dcrt_plaintext_polynomial(cche_dcrt_plaintext_t ptext)
{
    return (ccpolyzp_po2cyc_eval_t)ptext;
}

/// @brief Get the polynomial from a plaintext in eval format
/// @param ptext The plaintext where to get the polynomial from
/// @return Polynomial from the plaintext.
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_eval_const_t cche_dcrt_plaintext_polynomial_const(cche_dcrt_plaintext_const_t ptext)
{
    return (ccpolyzp_po2cyc_eval_const_t)ptext;
}

/// @brief Get plaintext size for a polynomial ctx
/// @param dims The dimensions of the plaintext's polynomial's context
/// @return Number of cc_units required to hold the ciphertext object
CC_NONNULL_ALL CC_INLINE cc_size cche_dcrt_plaintext_nof_n(ccpolyzp_po2cyc_dims_const_t dims)
{
    // storage for polynomial
    return ccpolyzp_po2cyc_nof_n(dims);
}

/// @brief Allocate memory for a cche_plaintext
/// @param poly_ctx The polynomial context that the plaintext has
/// @return A pointer to the allocated memory
#define CCHE_DCRT_PLAINTEXT_ALLOC_WS(ws, poly_ctx) \
    (cche_dcrt_plaintext_t) CC_ALLOC_WS(ws, cche_dcrt_plaintext_nof_n(&(poly_ctx)->dims))

/// @brief Copies a plaintext, r := x
/// @param r The destination plaintext
/// @param x The source plaintext
CC_NONNULL_ALL CC_INLINE void cche_dcrt_plaintext_copy(cche_dcrt_plaintext_t r, cche_dcrt_plaintext_const_t x)
{
    cc_size size = ccn_sizeof_n(cche_dcrt_plaintext_nof_n(&cche_dcrt_plaintext_ctx(x)->dims));
    cc_memmove(r, x, size);
}

/// @brief Encodes a plaintext into a Double-CRT plaintext
/// @param ws Workspace
/// @param r The destination Double-CRT plaintext
/// @param ptext The plaintext to encode
/// @param cipher_plain_ctx The cipher plain context that defines the number of moduli the resulting Double-CRT plaintext will
/// have.
/// @return `CCERR_OK` if successful.
CC_NONNULL_ALL CC_WARN_RESULT int cche_dcrt_plaintext_encode_ws(cc_ws_t ws,
                                                                cche_dcrt_plaintext_t r,
                                                                cche_plaintext_const_t ptext,
                                                                cche_cipher_plain_ctx_const_t cipher_plain_ctx);

/// @brief Symmetric encryption of zero polynomial
/// @param ws Workspace
/// @param ctext The ciphertext where to store the encrypted zero polynomial, must be allocated with
/// `cche_ciphertext_fresh_npolys()` polynomials
/// @param param_ctx The parameter context where to get the polynomial context from
/// @param secret_key The secret key to use for the encryption
/// @param nmoduli The number of moduli that should be in the ciphertext context
/// @param seed if nonnull, then the seed used for generating `a` will be stored here
/// @param rng The base rng to use for seed generation
/// @return CCERR_OK if operation was successful
/// @details Ciphertext is a tuple: `(-(as + e), a)`, where `a` is uniformly random polynomial, `s` is the secret key and `e` is
/// sampled from the error distribution. If the seed pointer is nonnull, the function additionally stores the seed to generate
/// `a`.
CC_WARN_RESULT CC_NONNULL((1, 2, 3, 4, 7)) int cche_encrypt_zero_symmetric_coeff_ws(cc_ws_t ws,
                                                                                    cche_ciphertext_coeff_t ctext,
                                                                                    cche_param_ctx_const_t param_ctx,
                                                                                    cche_secret_key_const_t secret_key,
                                                                                    uint32_t nmoduli,
                                                                                    cche_rng_seed_t seed,
                                                                                    struct ccrng_state *rng);

/// @brief Symmetric encryption of zero polynomial
/// @param ws Workspace
/// @param ctext The ciphertext where to store the encrypted zero polynomial, must be allocated with
/// `cche_ciphertext_fresh_npolys()` polynomials
/// @param param_ctx The parameter context where to get the polynomial context from
/// @param secret_key The secret key to use for the encryption
/// @param nmoduli The number of moduli that should be in the ciphertext context
/// @param seed if nonnull, then the seed used for generating `a` will be stored here
/// @param rng The base rng to use for seed generation
/// @return CCERR_OK if operation was successful
/// @details Ciphertext is a tuple: `(-(as + e), a)`, where `a` is uniformly random polynomial, `s` is the secret key and `e` is
/// sampled from the error distribution. If the seed pointer is nonnull, the function additionally stores the seed to generate
/// `a`.
CC_WARN_RESULT CC_NONNULL((1, 2, 3, 4, 7)) int cche_encrypt_zero_symmetric_eval_ws(cc_ws_t ws,
                                                                                   cche_ciphertext_eval_t ctext,
                                                                                   cche_param_ctx_const_t param_ctx,
                                                                                   cche_secret_key_const_t secret_key,
                                                                                   uint32_t nmoduli,
                                                                                   cche_rng_seed_t seed,
                                                                                   struct ccrng_state *rng);

/// @brief Symmetric encryption
/// @param ws Workspace
/// @param ctext The ciphertext where to store the encrypted plaintext, must be allocated with `cche_ciphertext_fresh_npolys()`
/// polynomials
/// @param ptext The plaintext to encrypt.
/// @param param_ctx The parameter context where to get the polynomial context from
/// @param secret_key The secret key to use for the encryption
/// @param nmoduli The number of moduli that should be in the ciphertext context
/// @param seed if nonnull, then the seed used for generating `a` will be stored here.
/// @param rng The base rng to use for seed generation
/// @return CCERR_OK if operation was successful
/// @details Ciphertext is a tuple: `(-(as + delta * m + e), a)`, where `a` is uniformly random polynomial, `s` is the secret key,
/// `delta = floor(q / t)`, `m` is the plaintext and `e` is sampled from the error distribution.  If the seed pointer is nonnull,
/// the function additionally stores the seed to generate `a`.
CC_WARN_RESULT CC_NONNULL((1, 2, 3, 4, 5, 8)) int cche_encrypt_symmetric_ws(cc_ws_t ws,
                                                                            cche_ciphertext_coeff_t ctext,
                                                                            cche_plaintext_const_t ptext,
                                                                            cche_param_ctx_const_t param_ctx,
                                                                            cche_secret_key_const_t secret_key,
                                                                            uint32_t nmoduli,
                                                                            cche_rng_seed_t seed,
                                                                            struct ccrng_state *rng);

/// @brief Decrypt a ciphertext
/// @param ws Workspace
/// @param ptext The polynomial where plaintext is written to
/// @param ctext The ciphertext to decrypt
/// @param secret_key The secret key to decrypt with
/// @return CCERR_OK if operation was successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_decrypt_ws(cc_ws_t ws,
                                                  cche_plaintext_t ptext,
                                                  cche_param_ctx_const_t param_ctx,
                                                  cche_ciphertext_coeff_const_t ctext,
                                                  cche_secret_key_const_t secret_key);

// Generator is an integer of order N mod 2N, where N is the poly modulus degree, that spans Z_2N^*
// (odd integers in [1, 2N - 1]) with the integer -1. We use {g_1 = 2N - 1, g_2 = 3} as the generators
// for plaintext row/column slot rotations. We have g2^{n_2} = 1 (mod 2N).
extern const uint32_t cche_encoding_generator_column; // g2

/// @brief Returns the generator for the plaintext slot rows. Also referred to as `g1`
/// @param degree Polynomial modulus degree; must be a power of two.
CC_WARN_RESULT CC_INLINE uint32_t cche_encoding_generator_row(uint32_t degree)
{
    cc_assert(ccpolyzp_po2cyc_is_power_of_two_uint32(degree));
    return 2 * degree - 1;
}

/// @brief Encodes a vector of unsigned coefficients values into a plaintext
/// @param ptext The plaintext to encode to; should be allocated via CCHE_PLAINTEXT_ALLOC_WS
/// @param nvalues The number of values to encode; should be at most N
/// @param values The vector of coefficients to encode; each value should be in [0, plaintext_modulus - 1].
/// @details Leaks nvalues through timing. Leaks the index of any out-of-range value, through error.
/// Encodes the polynomial f(x) = values[0] + values[1] x + values_{N_1} x^{N-1}`, padding
/// with 0 coefficients if fewer than `N` values are provided.
/// @return CCERR_OK if successful, CCERR_PARAMETER on invalid input values
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
/// @details Leaks nvalues through timing. Leaks the index of any out-of-range value, through error.
/// @return CCERR_OK if successful, CCERR_PARAMETER on invalid input values
CC_NONNULL_ALL CC_WARN_RESULT int cche_encode_simd_int64(cche_plaintext_t ptext,
                                                         cche_param_ctx_const_t param_ctx,
                                                         uint32_t nvalues,
                                                         const int64_t *cc_counted_by(nvalues) values);

/// @brief Decodes a plaintext to a vector of its unsigned coefficient values
/// @param nvalues The number of values to decode
/// @param values Will store the decoded values; each value should be in [0, plaintext_modulus - 1].
/// @param ptext The plaintext to decode
/// @details Leaks nvalues through timing. Leaks the index of any out-of-range value, through error.
/// The plaintext polynomial f(x) = a_0 + a_1 x + ... + a_{N-1} x^{N-1} will be stored in values as
/// values[0] = a_0, values[1] = a_1, ..., values[nvalues - 1] = a_{nvalues - 1}.
/// @return CCERR_OK if successful
CC_NONNULL_ALL CC_WARN_RESULT int
cche_decode_poly_uint64(uint32_t nvalues, uint64_t *cc_counted_by(nvalues) values, cche_plaintext_const_t ptext);

/// @brief Decodes a plaintext's SIMD slots to a vector of unsigned values
/// @param ws Workspace
/// @param param_ctx Parameter context
/// @param nvalues The number of values to decode
/// @param values Will store the decoded values; each value should be in [0, plaintext_modulus - 1].
/// @param ptext The plaintext to decode
/// @details Leaks nvalues through timing. Leaks the index of any out-of-range value, through error.
/// @return CCERR_OK if successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_decode_simd_uint64_ws(cc_ws_t ws,
                                                             cche_param_ctx_const_t param_ctx,
                                                             uint32_t nvalues,
                                                             uint64_t *cc_counted_by(nvalues) values,
                                                             cche_plaintext_const_t ptext);

/// @brief Decodes a plaintext's SIMD slots to a vector of signed values
/// @param ws Workspace
/// @param param_ctx Parameter context
/// @param nvalues The number of values to decode
/// @param values Will store the decoded values; each value should be in [-(plaintext_modulus >> 1), (plaintext_modulus - 1) >>
/// 1)]
/// @param ptext The plaintext to decode
/// @details Leaks nvalues through timing. Leaks the index of any out-of-range value, through error.
/// @return CCERR_OK if successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_decode_simd_int64_ws(cc_ws_t ws,
                                                            cche_param_ctx_const_t param_ctx,
                                                            uint32_t nvalues,
                                                            int64_t *cc_counted_by(nvalues) values,
                                                            cche_plaintext_const_t ptext);

/// @brief Adds a plaintext to a ciphertext
/// @param ws Workspace
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The plaintext
/// @details `ctext`, `r` must have exactly `cche_ciphertext_fresh_npolys()` polynomials. And `r` must be have the same context
/// and as `ctext`. `r` and `ctext` should not overlap, unless `r == x`
/// @return `CCERR_OK` if operation was successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_plaintext_add_ws(cc_ws_t ws,
                                                                   cche_ciphertext_coeff_t r,
                                                                   cche_ciphertext_coeff_const_t ctext,
                                                                   cche_plaintext_const_t ptext);

/// @brief Multiplies a ciphertext with a plaintext
/// @param ws Workspace
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The plaintext
/// @return `CCERR_OK` if the operation was successful
/// @details `r` and `ctext` should not overlap, unless `r == ctext`
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_coeff_plaintext_mul_ws(cc_ws_t ws,
                                                                         cche_ciphertext_coeff_t r,
                                                                         cche_ciphertext_coeff_const_t ctext,
                                                                         cche_plaintext_const_t ptext);

/// @brief Multiplies a ciphertext with a plaintext
/// @param ws Workspace
/// @param r The resulting ciphertext will be stored here
/// @param ctext The ciphertext
/// @param ptext The plaintext
/// @return `CCERR_OK` if the operation was successful
/// @details `r` and `ctext` should not overlap, unless `r == ctext`
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_eval_plaintext_mul_ws(cc_ws_t ws,
                                                                        cche_ciphertext_eval_t r,
                                                                        cche_ciphertext_eval_const_t ctext,
                                                                        cche_plaintext_const_t ptext);

/// @brief Performs modulus switching by dropping the last modulus in the ciphertext's context
/// @param ws Workspace
/// @param ctext Ciphertext; should have at least two moduli
/// @return CCERR_OK if modulus switching was successful, CCERR_PARAMETER if the ciphertext's context has fewer than two moduli
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_mod_switch_down_ws(cc_ws_t ws, cche_ciphertext_coeff_t ctext);

/// @brief Performs modulus switching by repeatedly dropping the last modulus in the ciphertext's context until a single modulus
/// remains.
/// @param ws Workspace
/// @param ctext Ciphertext; after this function is called, the ciphertext will have a single modulus in the context
/// @return CCERR_OK if modulus switching was successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_mod_switch_down_to_single_ws(cc_ws_t ws, cche_ciphertext_coeff_t ctext);

/// @brief Scales a ciphertext's correction factor by multiplying with q_last^{-1} mod t
/// @param ctext Ciphertext
/// @param scale Scale by which to adjust the correction factor
/// @return CCERR_OK if scaling was successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_scale_correction_factor(cche_ciphertext_coeff_t ctext,
                                                                          ccrns_mul_modulus_const_t scale);

/// @brief Compute the inverse of `x` mod plaintext modulus
/// @param ws Workspace
/// @param inverse The inverse will be stored here
/// @param param_ctx The context
/// @param x The element to invert; a single 64-bit integer that may exceed the plaintext modulus
/// @return `CCERR_OK` if operation was successful.
CC_NONNULL_ALL CC_WARN_RESULT int
cche_param_ctx_plaintext_modulus_inverse_ws(cc_ws_t ws, uint64_t *inverse, cche_param_ctx_const_t param_ctx, uint64_t x);

#endif /* _CORECRYPTO_CCHE_INTERNAL_H_ */
