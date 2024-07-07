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

#ifndef _CORECRYPTO_CCHE_UTIL_H_
#define _CORECRYPTO_CCHE_UTIL_H_

#include "cche_internal.h"

/// @brief Initialize a ciphertext in coefficient format with a given context
/// @param ctext The ciphertext to initialize
/// @param param_ctx The parameter context
/// @param npolys The number of polynomials in the ciphertext
/// @param cipher_ctx The polynomial context to use for the ciphertext polynomials
/// @details This makes sure that the ciphertext and the polynomial contexts are initialized, it does not however
/// initialize the actual polynomial coefficients.
CC_INLINE CC_NONNULL_ALL void cche_ciphertext_coeff_init(cche_ciphertext_coeff_t ctext,
                                                         cche_param_ctx_const_t param_ctx,
                                                         uint32_t npolys,
                                                         ccpolyzp_po2cyc_ctx_const_t cipher_ctx)
{
    cche_ciphertext_coeff_t ctext_coeff = (cche_ciphertext_coeff_t)ctext;
    ctext_coeff->param_ctx = param_ctx;
    ctext_coeff->npolys = npolys;
    ctext_coeff->correction_factor = CCHE_CIPHERTEXT_FRESH_CORRECTION_FACTOR;

    // note we cannot use `cche_ciphertext_coeff_polynomial(ctext, 0)` here, because the context is not initialized yet
    ccpolyzp_po2cyc_t c0 = (ccpolyzp_po2cyc_t)ctext_coeff->data;
    ((ccpolyzp_po2cyc_coeff_t)c0)->context = cipher_ctx;
    for (uint32_t poly_idx = 1; poly_idx < npolys; ++poly_idx) {
        ccpolyzp_po2cyc_coeff_t poly = cche_ciphertext_coeff_polynomial(ctext_coeff, poly_idx);
        poly->context = cipher_ctx;
    }
}

/// @brief Initialize a ciphertext in evaluation format with a given context
/// @param ctext The ciphertext to initialize
/// @param param_ctx The parameter context
/// @param npolys The number of polynomials in the ciphertext
/// @param cipher_ctx The polynomial context to use for the ciphertext polynomials
/// @details This makes sure that the ciphertext and the polynomial contexts are initialized, it does not however
/// initialize the actual polynomial coefficients.
CC_INLINE CC_NONNULL_ALL void cche_ciphertext_eval_init(cche_ciphertext_eval_t ctext,
                                                        cche_param_ctx_const_t param_ctx,
                                                        uint32_t npolys,
                                                        ccpolyzp_po2cyc_ctx_const_t cipher_ctx)
{
    cche_ciphertext_coeff_init((cche_ciphertext_coeff_t)ctext, param_ctx, npolys, cipher_ctx);
}

/// @brief Initializes the plaintext with the given parameter context
/// @param ptext The plaintext; should be allocated via CCHE_PLAINTEXT_ALLOC_WS
/// @param param_ctx The parameter context with which to initialize the plaintext
CC_INLINE CC_NONNULL_ALL void cche_plaintext_init(cche_plaintext_t ptext, cche_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = cche_param_ctx_plaintext_context(param_ctx);
    ccpolyzp_po2cyc_coeff_t poly = cche_plaintext_polynomial(ptext);
    poly->context = plain_ctx;
}

/// @brief Multiply a polynomial with the secret key
/// @param r The polynomial where to store the result
/// @param x The polynomial to multiply
/// @param sk The secret key to multiply
/// @details This is different from `ccpolyzp_po2cyc_eval_mul_ws` because we allow the secret key context to be larger. This is
/// contant time in the coefficients of `x` and the value in `sk`. Polynomials must have the same context and not overlap, unless
/// r == x. Secret key context must be a "parent" context to the polynomial context.
CC_NONNULL_ALL void cche_mul_poly_sk(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, cche_secret_key_const_t sk);

#endif /* _CORECRYPTO_CCHE_UTIL_H_ */
