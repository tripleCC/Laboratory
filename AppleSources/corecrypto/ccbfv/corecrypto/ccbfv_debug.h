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

#ifndef _CORECRYPTO_CCBFV_DEBUG_H_
#define _CORECRYPTO_CCBFV_DEBUG_H_

#include <corecrypto/cc_config.h>
#include "ccbfv_internal.h"
#include "ccbfv_galois_key.h"
#include "ccbfv_relin_key.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Prints a human-readable representation of a plaintext
/// @param ptext The plaintext to print
/// @param label The label to associate with the plaintext
CC_NONNULL((1))
void ccbfv_plaintext_lprint(ccbfv_plaintext_const_t ptext, const char *cc_cstring label);

/// @brief Prints a human-readable representation of a ciphertext in coefficient format
/// @param ctext The ciphertext to print
/// @param label The label to associate with the ciphertext
/// @details The printed value does not reveal the underlying plaintext
CC_NONNULL((1))
void ccbfv_ciphertext_coeff_lprint(ccbfv_ciphertext_coeff_const_t ctext, const char *cc_cstring label);

/// @brief Prints a human-readable representation of a ciphertext in evaluation format
/// @param ctext The ciphertext to print
/// @param label The label to associate with the ciphertext
/// @details The printed value does not reveal the underlying plaintext
CC_NONNULL((1))
void ccbfv_ciphertext_eval_lprint(ccbfv_ciphertext_eval_const_t ctext, const char *cc_cstring label);

/// @brief Prints a human-readable representation of a Galois key
/// @param galois_key The Galois key to print
/// @param label The label to associate with the Galois key
CC_NONNULL((1))
void ccbfv_galois_key_lprint(ccbfv_galois_key_const_t galois_key, const char *cc_cstring label);

/// @brief Prints a human-readable representation of a relinearization key
/// @param relin_key The relinearization key to print
/// @param label The label to associate with the relinearization key
CC_NONNULL((1))
void ccbfv_relin_key_lprint(ccbfv_relin_key_const_t relin_key, const char *cc_cstring label);

/// @brief Compares two plaintexts
/// @param x A plaintext to compare
/// @param y A plaintext to compare
/// @return True if x and y are equal, false else
/// @details Not constant-time
CC_INLINE CC_NONNULL_ALL bool ccbfv_plaintext_eq(ccbfv_plaintext_const_t x, ccbfv_plaintext_const_t y)
{
    return x->param_ctx == y->param_ctx &&
           ccpolyzp_po2cyc_coeff_eq(ccbfv_plaintext_polynomial_const(x), ccbfv_plaintext_polynomial_const(y));
}

/// @brief Returns whether or not two ciphertexts in coefficient format are equal (and have the same parameter context pointer)
/// @param x Ciphertext to compare
/// @param y Ciphertext to compare
CC_INLINE CC_NONNULL_ALL bool ccbfv_ciphertext_coeff_eq(ccbfv_ciphertext_coeff_const_t x, ccbfv_ciphertext_coeff_const_t y)
{
    if (x->npolys != y->npolys) {
        return false;
    }
    if (x->param_ctx != y->param_ctx) {
        return false;
    }
    for (uint32_t poly_idx = 0; poly_idx < x->npolys; ++poly_idx) {
        ccpolyzp_po2cyc_coeff_const_t x_poly = ccbfv_ciphertext_coeff_polynomial_const(x, poly_idx);
        ccpolyzp_po2cyc_coeff_const_t y_poly = ccbfv_ciphertext_coeff_polynomial_const(y, poly_idx);
        if (!ccpolyzp_po2cyc_coeff_eq(x_poly, y_poly)) {
            return false;
        }
    }
    return true;
}

/// @brief Returns whether or not two ciphertexts in evaluation format are equal (and have the same parameter context pointer)
/// @param x Ciphertext to compare
/// @param y Ciphertext to compare
CC_INLINE CC_NONNULL_ALL bool ccbfv_ciphertext_eval_eq(ccbfv_ciphertext_eval_const_t x, ccbfv_ciphertext_eval_const_t y)
{
    return ccbfv_ciphertext_coeff_eq((ccbfv_ciphertext_coeff_const_t)x, (ccbfv_ciphertext_coeff_const_t)y);
}

#endif /* _CORECRYPTO_CCBFV_DEBUG_H_ */