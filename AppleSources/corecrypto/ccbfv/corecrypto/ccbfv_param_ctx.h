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

#ifndef _CORECRYPTO_CCBFV_PARAM_CTX_H
#define _CORECRYPTO_CCBFV_PARAM_CTX_H

#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccbfv_param_ctx_types.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Returns whether or not two parameter contexts are equal, i.e. `x == y`
CC_NONNULL_ALL bool ccbfv_param_ctx_eq(ccbfv_param_ctx_const_t x, ccbfv_param_ctx_const_t y);

/// @brief Get the encryption paramters
/// @param param_ctx The parameter context object to get the encryption parameters from
CC_INLINE CC_NONNULL_ALL ccbfv_encrypt_params_t ccbfv_param_ctx_encrypt_params(ccbfv_param_ctx_t param_ctx)
{
    return (ccbfv_encrypt_params_t)(param_ctx->data);
}

/// @brief Get the encryption paramters
/// @param param_ctx The parameter context object to get the encryption parameters from
CC_INLINE CC_NONNULL_ALL ccbfv_encrypt_params_const_t ccbfv_param_ctx_encrypt_params_const(ccbfv_param_ctx_const_t param_ctx)
{
    return (ccbfv_encrypt_params_const_t)(param_ctx->data);
}

/// @brief Get the encryption paramters
/// @param param_ctx The parameter context object to get the encryption parameters from
CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_chain_t ccbfv_param_ctx_chain(ccbfv_param_ctx_t param_ctx);

/// @brief Get the encryption paramters
/// @param param_ctx The parameter context object to get the encryption parameters from
CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_chain_const_t ccbfv_param_ctx_chain_const(ccbfv_param_ctx_const_t param_ctx);

/// @brief Get the plaintext polynomial context
/// @param param_ctx The parameter context object to get the plaintext context from
CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_t ccbfv_param_ctx_plaintext_ctx(ccbfv_param_ctx_t param_ctx);

/// @brief Get the plaintext polynomial context
/// @param param_ctx The parameter context object to get the plaintext context from
CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_const_t ccbfv_param_ctx_plaintext_ctx_const(ccbfv_param_ctx_const_t param_ctx);

/// @brief Return the encoding indices
/// @param param_ctx The parameter context object to get the encoding indices from
/// @details Let f(x) = a_0 + a_1x + ... + a_{N-1}x^{N-1} in R_t be the degree N-1 polynomial we encode to
/// represented by its coefficients, i.e. in coefficient format.
/// Let eta be a minimal primitive 2N'th root of unity in R_t, and let alpha_i = eta^{2i + 1}.
/// The invNTT performs the mapping [f(alpha_0), f(alpha_1), ..., f(alpha_{N-1})] -> [a_0, a_1, ..., a_{N-1}] (1)
///                               = [f(eta)    , f(eta^3)  , ..., f(eta^{2N-1})]                              (2)
/// The encoding functions interpret the N input values as a vector of evaluations of f at a different set of
/// points, namely from the 2 x (N/2) grid of values:
/// M_encode [f(eta^1)   , f(eta^{g_2})    , f(eta^{g_2^2})    , ..., f(eta^{g_2^{N/2-1}}),
///           f(eta^{g_1}, f(eta^{g_1 g_2}), f(eta^{g_1 g_2^2}), ..., f(eta^{g_1 g_2^{N/2-1}})]               (3)
/// So, we need a mapping from the index of each power of eta in M_encode to the index of
/// each power of eta in [f(alpha_0), ..., f(alpha_{N-1})], which is this encoding_indices array.
CC_INLINE uint32_t *ccbfv_param_ctx_encoding_indices(ccbfv_param_ctx_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_t plain_ctx = ccbfv_param_ctx_plaintext_ctx(param_ctx);
    cc_unit *rv = (cc_unit *)plain_ctx;
    rv += ccpolyzp_po2cyc_ctx_nof_n(ccbfv_param_ctx_polynomial_degree(param_ctx));
    return (uint32_t *)rv;
}

/// @brief Return the constant encoding indices
/// @param param_ctx The parameter context object to get the encoding indices from
/// @details See ccbfv_param_ctx_encoding_indices for more details
CC_INLINE const uint32_t *ccbfv_param_ctx_encoding_indices_const(ccbfv_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_ctx_const(param_ctx);
    const cc_unit *rv = (const cc_unit *)plain_ctx;
    rv += ccpolyzp_po2cyc_ctx_nof_n(ccbfv_param_ctx_polynomial_degree(param_ctx));
    return (const uint32_t *)rv;
}

/// @brief Returns the number of cc_units required to allocate a context with the given encryption parameters
/// @param enc_params Encryption parameters
CC_NONNULL_ALL cc_size ccbfv_param_ctx_nof_n(ccbfv_encrypt_params_const_t enc_params);

/// @brief Allocates memory for a ccbfv_param_ctx_t
/// @param ws Workspace to allocate memory from
/// @param enc_parms The encryption parameters
/// @return A pointer to the allocated memory
#define CCBFV_PARAM_CTX_ALLOC_WS(ws, enc_parms) (ccbfv_param_ctx_t) CC_ALLOC_WS(ws, ccbfv_param_ctx_nof_n((enc_parms)))

/// @brief Initializes a parameter context with encryption parameters
/// @param ws Workspace
/// @param param_ctx The context to initialize
/// @param encryption_params The encryption parameters for the parameter context
/// @return CCERR_OK parameter context initialized successfully
/// @details Performs pre-computations for using the parameter context; should be called before use in BFV operations
CC_NONNULL_ALL CC_WARN_RESULT int
ccbfv_param_ctx_init_ws(cc_ws_t ws, ccbfv_param_ctx_t param_ctx, ccbfv_encrypt_params_const_t encryption_params);

/// @brief Get the encryption key context
/// @param param_ctx The parameter context to get the encryption key context from
/// @return encryption key context
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t ccbfv_param_ctx_encrypt_key_context(ccbfv_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_chain_const_t chain = ccbfv_param_ctx_chain_const(param_ctx);
    return ccpolyzp_po2cyc_ctx_chain_context_const(chain, chain->dims.nmoduli);
}

/// @brief Get the top-level ciphertext context
/// @param param_ctx The parameter context to get the top-level ciphertext context from
/// @return ciphertext context
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t ccbfv_param_ctx_ciphertext_context(ccbfv_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_chain_const_t chain = ccbfv_param_ctx_chain_const(param_ctx);
    if (chain->dims.nmoduli > 1) {
        return ccpolyzp_po2cyc_ctx_chain_context_const(chain, chain->dims.nmoduli - 1);
    } else {
        return ccpolyzp_po2cyc_ctx_chain_context_const(chain, chain->dims.nmoduli);
    }
}

/// @brief Get the ciphertext context with given number of moduli
/// @param param_ctx The parameter context to get the ciphertext context from
/// @param nmoduli The number of moduli in the context to return
/// @return ciphertext context
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t
ccbfv_param_ctx_ciphertext_context_specific(ccbfv_param_ctx_const_t param_ctx, uint32_t nmoduli)
{
    ccpolyzp_po2cyc_ctx_chain_const_t chain = ccbfv_param_ctx_chain_const(param_ctx);
    return ccpolyzp_po2cyc_ctx_chain_context_const(chain, nmoduli);
}

/// @brief Get the plaintext context
/// @param param_ctx The parameter context to get the plaintext context from
/// @return plaintext context
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t ccbfv_param_ctx_plaintext_context(ccbfv_param_ctx_const_t param_ctx)
{
    return ccbfv_param_ctx_plaintext_ctx_const(param_ctx);
}

/// @brief Get the decryption context
/// @param param_ctx The parameter context to get the decryption context from
/// @return decryption context
CC_INLINE ccbfv_decrypt_ctx_t ccbfv_param_ctx_decrypt_ctx(ccbfv_param_ctx_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_t plain_ctx = ccbfv_param_ctx_plaintext_ctx(param_ctx);
    uint32_t degree = plain_ctx->dims.degree;
    cc_unit *rv = (cc_unit *)ccbfv_param_ctx_encoding_indices(param_ctx);
    rv += ccn_nof_size(sizeof(uint32_t) * degree);
    return (ccbfv_decrypt_ctx_t)(rv);
}

/// @brief Get the decryption context
/// @param param_ctx The parameter context to get the decryption context from
/// @return decryption context
CC_INLINE ccbfv_decrypt_ctx_const_t ccbfv_param_ctx_decrypt_ctx_const(ccbfv_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_ctx_const(param_ctx);
    uint32_t degree = plain_ctx->dims.degree;
    const cc_unit *rv = (const cc_unit *)ccbfv_param_ctx_encoding_indices_const(param_ctx);
    rv += ccn_nof_size(sizeof(uint32_t) * degree);
    return (ccbfv_decrypt_ctx_const_t)(rv);
}

/// @brief Get the cipher-plain context with given number of moduli
/// @param param_ctx The parameter context to get the cipher-plain context from
/// @param nmoduli The number of moduli
/// @return cipher-plain context
CC_INLINE ccbfv_cipher_plain_ctx_t ccbfv_param_ctx_cipher_plain_ctx(ccbfv_param_ctx_t param_ctx, uint32_t nmoduli)
{
    cc_assert(nmoduli > 0 && nmoduli <= ccbfv_param_ctx_encrypt_key_context(param_ctx)->dims.nmoduli);
    cc_unit *rv = (cc_unit *)ccbfv_param_ctx_decrypt_ctx(param_ctx);
    ccpolyzp_po2cyc_ctx_const_t key_context = ccbfv_param_ctx_encrypt_key_context(param_ctx);
    rv += ccbfv_decrypt_ctx_nof_n(&key_context->dims);
    struct ccpolyzp_po2cyc_dims dims = { .degree = ccbfv_param_ctx_polynomial_degree(param_ctx), .nmoduli = 1 };
    for (uint32_t i = 1; i < nmoduli; ++i) {
        dims.nmoduli = i;
        rv += ccbfv_cipher_plain_ctx_nof_n(&dims);
    }
    return (ccbfv_cipher_plain_ctx_t)rv;
}

/// @brief Get the cipher-plain context with given number of moduli
/// @param param_ctx The parameter context to get the cipher-plain context from
/// @param nmoduli The number of moduli
/// @return cipher-plain context
CC_INLINE ccbfv_cipher_plain_ctx_const_t ccbfv_param_ctx_cipher_plain_ctx_const(ccbfv_param_ctx_const_t param_ctx,
                                                                                uint32_t nmoduli)
{
    cc_assert(nmoduli > 0 && nmoduli <= ccbfv_param_ctx_encrypt_key_context(param_ctx)->dims.nmoduli);
    const cc_unit *rv = (const cc_unit *)ccbfv_param_ctx_decrypt_ctx_const(param_ctx);
    ccpolyzp_po2cyc_ctx_const_t key_context = ccbfv_param_ctx_encrypt_key_context(param_ctx);
    rv += ccbfv_decrypt_ctx_nof_n(&key_context->dims);
    struct ccpolyzp_po2cyc_dims dims = { .degree = ccbfv_param_ctx_polynomial_degree(param_ctx), .nmoduli = 1 };
    for (uint32_t i = 1; i < nmoduli; ++i) {
        dims.nmoduli = i;
        rv += ccbfv_cipher_plain_ctx_nof_n(&dims);
    }
    return (ccbfv_cipher_plain_ctx_const_t)rv;
}

#endif /* _CORECRYPTO_CCBFV_PARAM_CTX_H */
