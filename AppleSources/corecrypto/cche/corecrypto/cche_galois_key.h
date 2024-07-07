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

#ifndef _CORECRYPTO_CCHE_GALOIS_H_
#define _CORECRYPTO_CCHE_GALOIS_H_

#include "cche_internal.h"

/// @brief Stores a Galois key for several Galois elements.
/// @details A Galois key is a form of public key, derived from a secret key, used to perform key-switching.
/// Key-switching transforms a ciphertext encrypted under a secret key to a ciphertext encrypted under a different (related)
/// secret key. Specifically, given a Galois element `gal`, a Galois key enables key switching from secret key polynomial
/// `s(x^{gal})` to secret poly polnomial `s(x)`. Each Galois element must be odd in [3, 2N - 1].
///
/// At a high level, the Galois key can be thought of as an encryption of `s(x^{gal})` using `s(x)`. However, for better
/// noise growth, we use a different formulation to generate the Galois key, namely hybrid RNS key-switching with
/// `\alpha = 1` key-switching modulus. Let `q_ks` denote the key-switching modulus, `s_B(x) = secret_key` denote the
/// target secret key, and `s_A(x) = s_B(x^{galois_elt})` denote the source secret key. The generated relinearization key will
/// enable key-switching from `s_A` to `s_B`.
///
/// Also let `Q_i = q_0 * ... * q_i` for `0 <= i < L - 1`.
/// Then, given a parameter context of `L > 1` RNS moduli, the relinearization key consists of `L - 1` two-polynomial ciphertexts:
/// `([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `\tilde{P})_{Q_i}(s_A)_j = [s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{Q_i}` and
/// `\tilde{Q_j} = q_j`.
struct cche_galois_key {
    /// Reference to the parameter context
    cche_param_ctx_const_t param_ctx;
    /// Number of Galois elements stored in the Galois key
    uint32_t ngalois_elts;
    // Storage for a Galois key with `ngalois_elts` Galois elements. For each Galois element, stores a vector of L - 1
    // ciphertexts, where L is the number of moduli in the key context. Stored as:
    /// 1) Galois elements (uint32_t array of length `ngalois_elts`)
    /// 2) For each Galois element, a vector of L - 1 ciphertexts, which comprise the Galois key for a single Galois element
    cc_unit data[];
};

/// @brief Returns the Galois elements
/// @param galois_key The Galois key
#define CCHE_GALOIS_KEY_GALOIS_ELTS(galois_key) ((uint32_t *)(galois_key)->data)
#define CCHE_GALOIS_KEY_GALOIS_ELTS_CONST(galois_key) ((const uint32_t *)(galois_key)->data)

/// @brief Returns the ciphertexts in the Galois key
/// @param galois_key The Galois key
#define CCHE_GALOIS_KEY_CIPHERS(galois_key)                                          \
    ((cche_ciphertext_eval_t)(((cc_unit *)CCHE_GALOIS_KEY_GALOIS_ELTS(galois_key)) + \
                              ccn_nof_size(sizeof(uint32_t) * galois_key->ngalois_elts)))
#define CCHE_GALOIS_KEY_CIPHERS_CONST(galois_key)                                                      \
    ((cche_ciphertext_eval_const_t)(((const cc_unit *)CCHE_GALOIS_KEY_GALOIS_ELTS_CONST(galois_key)) + \
                                    ccn_nof_size(sizeof(uint32_t) * galois_key->ngalois_elts)))

/// @brief Returns the number of cc_unit's required to allocate a Galois key
/// @param param_ctx Parameter context
/// @param ngalois_elts Number of Galois elements in the Galois key
CC_WARN_RESULT CC_NONNULL_ALL cc_size cche_galois_key_nof_n(cche_param_ctx_const_t param_ctx, uint32_t ngalois_elts);

/// @brief Allocates memory for a cche_galois_key_t
/// @param ws Workspace to allocate memory from
/// @param param_ctx The parameter context
/// @param ngalois_elts Number of Galois elements
/// @return A pointer to the allocated memory
#define CCHE_GALOIS_KEY_ALLOC_WS(ws, param_ctx, ngalois_elts) \
    (cche_galois_key_t) CC_ALLOC_WS(ws, cche_galois_key_nof_n((param_ctx), (ngalois_elts)))

/// @brief Get the ciphertext associated with a given Galois index
/// @param galois_key Galois key
/// @param galois_elt_idx Index of the Galois element; must be less than `galois_key->ngalois_elts`
/// @param cipher_idx Ciphertext index; must be less than the number of moduli in the key context
/// @return The ciphertext
/// @details The returned ciphertext is `([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `i = cipher_idx` and `s_A = s(x^{galois_elt})`, for secret key polynomial `s(x)`
CC_WARN_RESULT CC_NONNULL_ALL cche_ciphertext_eval_t cche_galois_key_ciphertext(cche_galois_key_t galois_key,
                                                                                uint32_t galois_elt_idx,
                                                                                uint32_t cipher_idx);

/// @brief Get the constant ciphertext associated with a given Galois index
/// @param galois_key Galois key
/// @param galois_elt_idx Index of the Galois element; must be less than `galois_key->ngalois_elts`
/// @param cipher_idx Ciphertext index; must be less than the number of moduli in the key context
/// @return The ciphertext
/// @details The returned ciphertext is `([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `i = cipher_idx` and `s_A = s(x^{galois_elt})`, for secret key polynomial `s(x)`
CC_WARN_RESULT CC_NONNULL_ALL cche_ciphertext_eval_const_t cche_galois_key_ciphertext_const(cche_galois_key_const_t galois_key,
                                                                                            uint32_t galois_elt_idx,
                                                                                            uint32_t cipher_idx);

/// @brief Generates a Galois key
/// @param ws Workspace to allocate memory from
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
CC_WARN_RESULT CC_NONNULL((1, 2, 4, 5, 6)) int cche_galois_key_generate_ws(cc_ws_t ws,
                                                                           cche_galois_key_t galois_key,
                                                                           uint32_t ngalois_elts,
                                                                           const uint32_t *cc_counted_by(ngalois_elts)
                                                                               galois_elts,
                                                                           cche_secret_key_const_t secret_key,
                                                                           cche_param_ctx_const_t param_ctx,
                                                                           uint32_t nseeds,
                                                                           uint8_t *cc_counted_by(nseeds) seeds,
                                                                           struct ccrng_state *rng);

/// @brief Saves a Galois key ciphertext first polynomials
/// @param ws Workspace to allocate memory from
/// @param nbytes_poly0s The number of bytes than can be stored in the `poly0s` buffer
/// @param poly0s The buffer where to serialize the first component of each ciphertext
/// @param galois_key The galois key to save
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int
cche_galois_key_save_ws(cc_ws_t ws, uint32_t nbytes_poly0s, uint8_t *poly0s, cche_galois_key_const_t galois_key);

/// @brief Loads a Galois key
/// @param ws Workspace to allocate memory from
/// @param galois_key Galois key to load; should be initialized with `CCHE_GALOIS_KEY_ALLOC_WS`
/// @param ngalois_elts Number of Galois elements in the Galois key
/// @param galois_elts List of Galois elements; each should be unique and odd in [3, 2N - 1]
/// @param param_ctx Parameter context
/// @param nbytes_poly0s The number of bytes than are stored in the `poly0s` buffer
/// @param poly0s An array of pointers to serialized bytes of the first polynomial of the ciphertexts
/// @param nbytes_seeds Number of bytes in the seeds buffer
/// @param seeds Array of RNG seeds that store the seed for the second polynomial of ciphertexts
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_galois_key_load_ws(cc_ws_t ws,
                                                          cche_galois_key_t galois_key,
                                                          uint32_t ngalois_elts,
                                                          const uint32_t *galois_elts,
                                                          cche_param_ctx_const_t param_ctx,
                                                          uint32_t nbytes_poly0s,
                                                          const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                                                          uint32_t nbytes_seeds,
                                                          const uint8_t *cc_counted_by(nbytes_seeds) seeds);

/// @brief Find a Galois element within a Galois key
/// @param galois_elt_idx Optionally, where to store the index at which the Galois element was found
/// @param galois_elt Galois element
/// @param galois_key The Galois key
/// @return Whether or not the Galois key contains the Galois element
/// @details Not constant-time
CC_WARN_RESULT CC_NONNULL((3)) bool cche_galois_key_find_galois_elt(uint32_t *galois_elt_idx,
                                                                    uint32_t galois_elt,
                                                                    cche_galois_key_const_t galois_key);

/// @brief Performs the Galois automorphism f(x) -> f(x^{galois_elt}) on an encrypted message
/// @param ws Workspace to allocate memory from
/// @param r The output ciphertext
/// @param ctext The input ciphertext; should not overlap with or equal r.
/// @param galois_elt The Galois element
/// @param galois_key The Galois key; should contain the Galois element
/// @details If the original ciphertext encrypts the polynomial f(x), the resulting ciphertext will encrypt the message
/// f(x^{galois_elt}), encrypted under the same secret key.
/// @return CCERR_OK if successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_ciphertext_apply_galois_ws(cc_ws_t ws,
                                                                  cche_ciphertext_coeff_t r,
                                                                  cche_ciphertext_coeff_const_t ctext,
                                                                  uint32_t galois_elt,
                                                                  cche_galois_key_const_t galois_key);

/// @brief Performs in-place ciphertext key switching from `s(x^{galois_elt})` to `s(x)` for secret key polynomial `s(x)`
/// @param ws Workspace to allocate memory from
/// @param r The input/output ciphertext. Will be encrypted under secret key `s(x)`
/// @param galois_elt The Galois element
/// @param galois_key The Galois key; should contain the Galois element
/// @return CCERR_OK if successful
/// @details Uses hybrid RNS key-switching with `\alpha = 1` key-switching modulus
CC_WARN_RESULT CC_NONNULL_ALL int cche_ciphertext_galois_key_switch_ws(cc_ws_t ws,
                                                                       cche_ciphertext_coeff_t r,
                                                                       uint32_t galois_elt,
                                                                       cche_galois_key_const_t galois_key);

/// @brief Left rotates plaintext slots encoded in both of the rows of a ciphertext
/// @param ws Workspace to allocate memory from
/// @param r The result ciphertext; will encrypt the plaintext matrix with rotated slots
/// @param ctext The input ciphertext; encodes a plaintext matrix whose slots are rotated
/// @param step The number of slots to rotate by; must be in [1, N - 1]
/// @param galois_key The Galois key; must contain the Galois element for the step
/// @return CCERR_OK if successful
/// @details Not constant time; the step is considered public
CC_WARN_RESULT CC_NONNULL_ALL int cche_ciphertext_rotate_rows_left_ws(cc_ws_t ws,
                                                                      cche_ciphertext_coeff_t r,
                                                                      cche_ciphertext_coeff_const_t ctext,
                                                                      uint32_t step,
                                                                      cche_galois_key_const_t galois_key);

/// @brief Right rotates plaintext slots encoded in both of the rows of a ciphertext
/// @param ws Workspace to allocate memory from
/// @param r The result ciphertext; will encrypt the plaintext matrix with rotated slots
/// @param ctext The input ciphertext; encodes a plaintext matrix whose slots are rotated
/// @param step The number of slots to rotate by; must be in [1, N - 1]
/// @param galois_key The Galois key; must contain the Galois element for the step
/// @return CCERR_OK if successful
/// @details Not constant time; the step is considered public
CC_WARN_RESULT CC_NONNULL_ALL int cche_ciphertext_rotate_rows_right_ws(cc_ws_t ws,
                                                                       cche_ciphertext_coeff_t r,
                                                                       cche_ciphertext_coeff_const_t ctext,
                                                                       uint32_t step,
                                                                       cche_galois_key_const_t galois_key);

/// @brief Swaps the plaintext slots encoded in each row of a ciphertext
/// @param ws Workspace to allocate memory from
/// @param r The result ciphertext; will encrypt the plaintext matrix with
/// @param ctext The input ciphertext; encodes a plaintext matrix whose slots are rotated
/// @param galois_key The Galois key; must contain the Galois element for the step
/// @return CCERR_OK if successful
/// @details Not constant time. In BFV/BGV, the plaintext can be viewed as a 2 x (N/2) matrix.
/// This function rotates the elements in each column. Since there are only two elements in each
/// column, this simply swaps the two rows.
CC_WARN_RESULT CC_NONNULL_ALL int cche_ciphertext_swap_columns_ws(cc_ws_t ws,
                                                                  cche_ciphertext_coeff_t r,
                                                                  cche_ciphertext_coeff_const_t ctext,
                                                                  cche_galois_key_const_t galois_key);

#endif /* _CORECRYPTO_CCHE_GALOIS_H_ */
