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

#ifndef _CORECRYPTO_CCHE_DECRYPT_CTX_H_
#define _CORECRYPTO_CCHE_DECRYPT_CTX_H_

#include <corecrypto/cc_config.h>
#include "cche_param_ctx_types.h"
#include "cche_param_ctx.h"
#include "ccpolyzp_po2cyc_base_convert.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Get the decryption helper context [t, gamma] chain
/// @param decrypt_ctx The decryption context to get the helper context chain from
#define CCHE_DECRYPT_CTX_T_GAMMA_CTX_CHAIN(decrypt_ctx) ((ccpolyzp_po2cyc_ctx_chain_t)((decrypt_ctx)->data))

/// @brief Get the decryption helper context [t, gamma] chain
/// @param decrypt_ctx The parameter context object to get the helper context chain from
#define CCHE_DECRYPT_CTX_T_GAMMA_CTX_CHAIN_CONST(decrypt_ctx) ((ccpolyzp_po2cyc_ctx_chain_const_t)((decrypt_ctx)->data))

/// @brief Return the base converter from a decryption context to plaintext context
/// @param decrypt_ctx The decryption context to get the base converter from
/// @param nmoduli The number of moduli in the ciphertext context
CC_INLINE CC_NONNULL_ALL ccpolyzp_po2cyc_base_convert_t cche_decrypt_ctx_base_convert(cche_decrypt_ctx_t decrypt_ctx,
                                                                                      uint32_t nmoduli)
{
    cc_assert(nmoduli > 0 && nmoduli <= cche_param_ctx_encrypt_key_context(decrypt_ctx->param_ctx)->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_chain_t decrypt_t_gamma_ctx_chain = CCHE_DECRYPT_CTX_T_GAMMA_CTX_CHAIN(decrypt_ctx);
    cc_unit *rv = (cc_unit *)decrypt_t_gamma_ctx_chain;
    rv += ccpolyzp_po2cyc_ctx_chain_nof_n(&decrypt_t_gamma_ctx_chain->dims);
    for (uint32_t i = 1; i < nmoduli; ++i) {
        rv += ccpolyzp_po2cyc_base_convert_nof_n(i, decrypt_t_gamma_ctx_chain->dims.nmoduli);
    }
    return (ccpolyzp_po2cyc_base_convert_t)(rv);
}

/// @brief Return the base converter from a decryption context to plaintext context
/// @param decrypt_ctx The decryption context to get the base converter from
/// @param nmoduli The number of moduli in the ciphertext context
CC_INLINE CC_NONNULL_ALL ccpolyzp_po2cyc_base_convert_const_t
cche_decrypt_ctx_base_convert_const(cche_decrypt_ctx_const_t decrypt_ctx, uint32_t nmoduli)
{
    cc_assert(nmoduli > 0 && nmoduli <= cche_param_ctx_encrypt_key_context(decrypt_ctx->param_ctx)->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_chain_const_t decrypt_t_gamma_ctx_chain = CCHE_DECRYPT_CTX_T_GAMMA_CTX_CHAIN_CONST(decrypt_ctx);
    const cc_unit *rv = (const cc_unit *)decrypt_t_gamma_ctx_chain;
    rv += ccpolyzp_po2cyc_ctx_chain_nof_n(&decrypt_t_gamma_ctx_chain->dims);
    for (uint32_t i = 1; i < nmoduli; ++i) {
        rv += ccpolyzp_po2cyc_base_convert_nof_n(i, decrypt_t_gamma_ctx_chain->dims.nmoduli);
    }
    return (ccpolyzp_po2cyc_base_convert_const_t)(rv);
}

/// @brief Initialize the decryption context
/// @param ws Workspace
/// @param decrypt_ctx The decryption context to initialize
/// @param param_ctx The parameter context that describes the context
/// @return `CCERR_OK` if initialization succeeds
CC_NONNULL_ALL CC_WARN_RESULT int
cche_decrypt_ctx_init_ws(cc_ws_t ws, cche_decrypt_ctx_t decrypt_ctx, cche_param_ctx_const_t param_ctx);

#endif /* _CORECRYPTO_CCHE_DECRYPT_CTX_H_ */
