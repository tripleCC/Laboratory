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

#ifndef _CORECRYPTO_CCBFV_PARAM_CTX_TYPES_H
#define _CORECRYPTO_CCBFV_PARAM_CTX_TYPES_H

#include <corecrypto/cc_config.h>
#include <corecrypto/ccbfv_priv.h>
#include "ccpolyzp_po2cyc_internal.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// Number of polynomials in a freshly-encrypted ciphertext
#define CCBFV_CIPHERTEXT_FRESH_NPOLYS 2

/// Encryption parameters
struct ccbfv_encrypt_params {
    /// Plaintext modulus
    ccrns_int plaintext_modulus;
    /// polynomial degree, also known as N
    uint32_t poly_modulus_degree;
    /// Defines the maximum number of LSBs that can be omitted from each polyomial's coefficient when serializing a ciphertext
    /// while maintaing low probability of decryption error.
    uint32_t nskip_lsbs[CCBFV_CIPHERTEXT_FRESH_NPOLYS];
    /// number of coefficient moduli in RNS form
    uint32_t nmoduli;
    /// Variable length array for the coefficient moduli
    ccrns_int moduli[];
};
typedef struct ccbfv_encrypt_params *ccbfv_encrypt_params_t;
typedef const struct ccbfv_encrypt_params *ccbfv_encrypt_params_const_t;

/// @brief Returns whether or not two encryption parameters are equal, i.e. `x == y`
CC_NONNULL_ALL bool ccbfv_encrypt_params_eq(ccbfv_encrypt_params_const_t x, ccbfv_encrypt_params_const_t y);

/// This holds all the parameters and the precomputed polynomial contexts
struct ccbfv_param_ctx {
    /// variable length buffer for
    /// 1. ccbfv_encrypt_params
    /// 2. polynomial context chain (ccpolyzp_po2cyc_ctx_chain)
    /// 3. plaintext polynomial context (ccpolyzp_po2cyc_ctx)
    /// 4. encoding index array (poly_modulus_degree uint32_t indices)
    /// 5. decryption context (ccbfv_decrypt_ctx)
    /// 6. cipher-plain contexts array
    cc_unit data[0]; // 0-length array avoids warning about otherwise empty struct
} CC_ALIGNED(CCN_UNIT_SIZE);

/// This holds precomputed values for decryption
struct ccbfv_decrypt_ctx {
    /// Reference to the parameter context
    ccbfv_param_ctx_const_t param_ctx;
    /// Storage for:
    /// 1) [t, gamma] context chain (ccpolyzp_po2cyc_ctx_chain)
    /// 2) Array of base converters from ciphertext contexts to plaintext context, one for each ciphertext context.
    //     Stored in ascending order of number of moduli, beginning with one modulus (array of ccpolyzp_po2cyc_base_convert)
    cc_unit data[];
};
typedef struct ccbfv_decrypt_ctx *ccbfv_decrypt_ctx_t;
typedef const struct ccbfv_decrypt_ctx *ccbfv_decrypt_ctx_const_t;

/// @brief Returns the number of cc_units required to allocate a decryption context with the given dimensions
/// @param dims Dimensions
cc_size ccbfv_decrypt_ctx_nof_n(ccpolyzp_po2cyc_dims_const_t dims);

/// The precomputed parameters for operations between ciphertext and plaintext
struct ccbfv_cipher_plain_ctx {
    /// Reference to the parameter context
    ccbfv_param_ctx_const_t param_ctx;
    /// The ciphertext context that this cipher-plain context is related to
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx;
    /// q % t
    cc_unit q_mod_t[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    /// (t + 1) / 2
    cc_unit t_half[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    /// Storage for:
    /// 1) Array where i'th entry stores `floor(q / t) % q_i`, where `t` is the plaintext
    /// modulus. Also called `delta` in the literature. Each element has `CCPOLYZP_PO2CYC_NUNITS_PER_COEFF` units.
    /// 2) Array where i'th entry stores `q_i - t`. Each element has `CCPOLYZP_PO2CYC_NUNITS_PER_COEFF` units and is positive,
    /// because `q_i > t`.
    cc_unit data[];
};
typedef struct ccbfv_cipher_plain_ctx *ccbfv_cipher_plain_ctx_t;
typedef const struct ccbfv_cipher_plain_ctx *ccbfv_cipher_plain_ctx_const_t;

/// @brief Returns the number of cc_units required to allocate a cipher-plain context with the given dimensions
/// @param dims Dimensions
CC_INLINE cc_size ccbfv_cipher_plain_ctx_nof_n(ccpolyzp_po2cyc_dims_const_t dims)
{
    cc_size rv = ccn_nof_size(sizeof_struct_ccbfv_cipher_plain_ctx());
    rv += dims->nmoduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    rv += dims->nmoduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return rv;
}

#endif /* _CORECRYPTO_CCBFV_PARAM_CTX_TYPES_H */
