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

#ifndef _CORECRYPTO_CCHE_RELIN_H_
#define _CORECRYPTO_CCHE_RELIN_H_

#include "cche_internal.h"

/// @brief Stores a relinearization key.
/// @details A relinearization key is a form of public key, derived from a secret key, used to perform key-switching.
/// Key-switching transforms a ciphertext encrypted under a secret key to a ciphertext encrypted under a different (related)
/// secret key. Specifically, given a secret key `s`, the relinearization key is used to transform a ciphertext encrypted from
/// `s^2`to a ciphertext encrypted under `s`. This allows transformation of a 3-polynomial ciphertext arising from
/// ciphertext-ciphertext multiplication to a regular 2-polynomial ciphertext.
///
/// At a high level, the relinearization key can be thought of as an encryption of `s(x)^2` using `s(x)`. However, for better
/// noise growth, we use a different formulation to generate the relinearization key, namely hybrid RNS key-switching with
/// `\alpha = 1` key-switching modulus. Let `q_ks` denote the key-switching modulus, `s_B(x) = secret_key` denote the
/// target secret key, and `s_A(x) = s_B(x)^2` denote the source secret key. The generated relinearization key will
/// enable key-switching from `s_A` to `s_B`.
///
/// Also let `Q_i = q_0 * ... * q_i` for `0 <= i < L - 1`.
/// Then, given a parameter context of `L > 1` RNS moduli, the relinearization key consists of `L - 1` two-polynomial ciphertexts:
/// `([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `\tilde{P})_{Q_i}(s_A)_j = [s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{Q_i}` and
/// `\tilde{Q_j} = q_j`.
struct cche_relin_key {
    /// Reference to the parameter context
    cche_param_ctx_const_t param_ctx;
    // Storage for a relinearization key with as a vector of L - 1 ciphertexts in evaluation format, where L is the number of
    // moduli in the key context.
    cc_unit data[];
};

/// @brief Returns the ciphertexts in the relinearization key
/// @param relin_key The relinearization key
#define CCHE_RELIN_KEY_CIPHERS(relin_key) ((cche_ciphertext_eval_t)(relin_key->data))
#define CCHE_RELIN_KEY_CIPHERS_CONST(relin_key) ((cche_ciphertext_eval_const_t)(const cc_unit *)(relin_key->data))

/// @brief Returns the number of cc_unit's required to allocate a relinearization key
/// @param param_ctx Parameter context
CC_WARN_RESULT CC_NONNULL_ALL cc_size cche_relin_key_nof_n(cche_param_ctx_const_t param_ctx);

/// @brief Allocates memory for a cche_relin_key_t
/// @param ws Workspace to allocate memory from
/// @param param_ctx The parameter context
/// @return A pointer to the allocated memory
#define CCHE_RELIN_KEY_ALLOC_WS(ws, param_ctx) (cche_relin_key_t) CC_ALLOC_WS(ws, cche_relin_key_nof_n((param_ctx)))

/// @brief Get the ciphertext at the given index
/// @param relin_key Relinearization key
/// @param cipher_idx Ciphertext index; must be less than the number of moduli in the key context
/// @return The ciphertext
CC_WARN_RESULT CC_NONNULL_ALL cche_ciphertext_eval_t cche_relin_key_ciphertext(cche_relin_key_t relin_key, uint32_t cipher_idx);

/// @brief Get the constant ciphertext at the given index
/// @param relin_key Relinearization key
/// @param cipher_idx Ciphertext index; must be less than the number of moduli in the key context
/// @return The ciphertext
CC_WARN_RESULT CC_NONNULL_ALL cche_ciphertext_eval_const_t cche_relin_key_ciphertext_const(cche_relin_key_const_t relin_key,
                                                                                           uint32_t cipher_idx);

/// @brief Generates a relinearization key
/// @param ws Workspace to allocate memory from
/// @param relin_key Relinearization key to generate; should be initialized with `CCHE_RELIN_KEY_ALLOC_WS`
/// @param secret_key Secret key to use to derive the relinearization key
/// @param param_ctx Parameter context
/// @param nseeds Number of seeds in the seeds buffer; must be set to 0 if `seeds` is NULL
/// @param seeds Optionally, a buffer to an array of RNG seeds that will store the seed for the second polynomial of ciphertexts
/// @param rng The base rng to use for seed generation
/// @return CCERR_OK if successful
/// @details We use hybrid RNS key-switching with `\alpha = 1` key-switching modulus
/// Let `q_ks` denote the key-switching modulus, `s_B(x) = secret_key` denote the target secret key, and `s_A(x) = s_B(x)^2`
/// denote the source secret key. The generated relinearization key will enable key-switching from `s_A` to `s_B`.
/// Also let `Q_i = q_0 * ... * q_i`. Given a parameter context of `L > 1` RNS moduli, the relinearization key consists of `L - 1`
/// two-polynomial ciphertexts:
/// `([q_ks * \tilde{P}_{Q_i}(s_A) - a * s_B]_{q_ks * Q_i} + e, a)_{[Q_i, q_sk]}` where
/// `\tilde{P})_{Q_i}(s_A)_j = [s_A * (Q_i / \tilde{Q}_j) * (Q_i / \tilde{Q_j})^{-1}]_{Q_i}` and
/// `\tilde{Q_j} = q_j`.
CC_WARN_RESULT CC_NONNULL((1, 2, 3, 4)) int cche_relin_key_generate_ws(cc_ws_t ws,
                                                                       cche_relin_key_t relin_key,
                                                                       cche_secret_key_const_t secret_key,
                                                                       cche_param_ctx_const_t param_ctx,
                                                                       uint32_t nseeds,
                                                                       uint8_t *cc_counted_by(nseeds) seeds,
                                                                       struct ccrng_state *rng);

/// @brief Saves a relinearization key ciphertexts' first polynomials
/// @param ws Workspace to allocate memory from
/// @param nbytes_poly0s The number of bytes than can be stored in the `poly0s` buffer
/// @param poly0s The buffer where to serialize the first polynomial of each ciphertext
/// @param relin_key The relinearization key to save
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int
cche_relin_key_save_ws(cc_ws_t ws, uint32_t nbytes_poly0s, uint8_t *poly0s, cche_relin_key_const_t relin_key);

/// @brief Loads a relinearization key
/// @param ws Workspace to allocate memory from
/// @param relin_key Relinearization key to load; should be initialized with `CCHE_RELIN_KEY_ALLOC_WS`
/// @param param_ctx Parameter context
/// @param nbytes_poly0s The number of bytes than are stored in the `poly0s` buffer
/// @param poly0s An array of pointers to serialized bytes of the first polynomial of each ciphertext
/// @param nbytes_seeds Number of bytes in the seeds buffer
/// @param seeds Array of RNG seeds that store the seed for the second polynomial of ciphertexts
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_relin_key_load_ws(cc_ws_t ws,
                                                         cche_relin_key_t relin_key,
                                                         cche_param_ctx_const_t param_ctx,
                                                         uint32_t nbytes_poly0s,
                                                         const uint8_t *cc_counted_by(nbytes_poly0s) poly0s,
                                                         uint32_t nbytes_seeds,
                                                         const uint8_t *cc_counted_by(nbytes_seeds) seeds);

#endif /* _CORECRYPTO_CCHE_RELIN_H_ */
