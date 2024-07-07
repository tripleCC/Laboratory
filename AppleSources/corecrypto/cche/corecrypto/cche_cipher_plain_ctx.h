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

#ifndef _CORECRYPTO_CCHE_CIPHER_PLAIN_CTX_H
#define _CORECRYPTO_CCHE_CIPHER_PLAIN_CTX_H

#include "cche_param_ctx.h"
#include "cche_decrypt_ctx.h"
#include "ccpolyzp_po2cyc_internal.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Get the delta array where i'th entry stores `floor(q / t) % q_i`, where `t` is the plaintext
/// modulus. Also called `delta` in the literature. Each element has `CCPOLYZP_PO2CYC_NUNITS_PER_COEFF` units.
/// @param cipher_plain_ctx The cipher-plain context to get the delta array from
#define CCHE_CIPHER_PLAIN_CTX_DELTA(cipher_plain_ctx) ((cipher_plain_ctx)->data)

/// @brief Get the delta array where i'th entry stores `floor(q / t) % q_i`, where `t` is the plaintext
/// modulus. Also called `delta` in the literature. Each element has `CCPOLYZP_PO2CYC_NUNITS_PER_COEFF` units.
/// @param cipher_plain_ctx The cipher-plain context to get the delta array from
#define CCHE_CIPHER_PLAIN_CTX_DELTA_CONST(cipher_plain_ctx) ((const cc_unit *)((cipher_plain_ctx)->data))

/// @brief Get the plain increment array
/// @param cipher_plain_ctx The cipher-plain context to get the plain increment array from
/// @details Plain increment array stores `q_i - t`.
#define CCHE_CIPHER_PLAIN_CTX_PLAIN_INCREMENT(cipher_plain_ctx) \
    ((cipher_plain_ctx)->data + (cipher_plain_ctx)->cipher_ctx->dims.nmoduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF)

/// @brief Get the plain increment array
/// @param cipher_plain_ctx The cipher-plain context to get the plain increment array from
/// @details Plain increment array stores `q_i - t`.
#define CCHE_CIPHER_PLAIN_CTX_PLAIN_INCREMENT_CONST(cipher_plain_ctx) \
    ((cipher_plain_ctx)->data + (cipher_plain_ctx)->cipher_ctx->dims.nmoduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF)

/// @brief Initialize the cipher-plain context
/// @param ws Workspace
/// @param cipher_plain_ctx The cipher-plain context to initialize
/// @param param_ctx The parameter context that holds the plaintext context
/// @param cipher_ctx The ciphertext context
/// @return CCERR_OK if successful
CC_WARN_RESULT CC_NONNULL_ALL int cche_cipher_plain_ctx_init_ws(cc_ws_t ws,
                                                                cche_cipher_plain_ctx_t cipher_plain_ctx,
                                                                cche_param_ctx_const_t param_ctx,
                                                                ccpolyzp_po2cyc_ctx_const_t cipher_ctx);

#endif /* _CORECRYPTO_CCHE_CIPHER_PLAIN_CTX_H */
