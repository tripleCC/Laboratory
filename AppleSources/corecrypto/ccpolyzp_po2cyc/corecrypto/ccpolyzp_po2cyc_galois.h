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

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_GALOIS_H
#define _CORECRYPTO_CCPOLYZP_PO2CYC_GALOIS_H

#include "ccpolyzp_po2cyc_internal.h"

/// @brief Returns whether or not the Galois element is valid for the polynomial degree
/// @param galois_elt Galois element
/// @param degree Polynomial degree
/// @details Leaks galois_elt and degree through timing
CC_INLINE CC_WARN_RESULT bool is_valid_galois_element_and_degree(uint32_t galois_elt, uint32_t degree)
{
    bool is_valid_degree = ccpolyzp_po2cyc_ctx_is_valid_degree(degree);
    return is_valid_degree && ((galois_elt & 1) == 1) && (galois_elt > 1) && (galois_elt < 2 * degree);
}

/// @brief Applies the transformation f(x) -> f(x^{galois_elt}) for polynomials in coefficient format
/// @param r The output polynomial
/// @param x The input polynomial; r != x, and r must not overlap with x
/// @param galois_elt The Galois element; must be odd in [3, 2 * N - 1]
/// @return CCERR_OK if successful
/// @details Constant-time in the coefficients, but not the context, of x. Leaks galois_elt through error and timing.
CC_NONNULL_ALL CC_WARN_RESULT int
ccpolyzp_po2cyc_coeff_apply_galois(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x, uint32_t galois_elt);

/// @brief Applies the transformation f(x) -> f(x^{galois_elt}) for polynomials in evaluation format
/// @param r The output polynomial
/// @param x The input polynomial; r != x, and r must not overlap with x
/// @param galois_elt The Galois element; must be odd in [3, 2 * N - 1]
/// @return CCERR_OK if successful
/// @details Constant-time in the coefficients, but not the context, of x. Leaks galois_elt through error and timing.
CC_NONNULL_ALL CC_WARN_RESULT int
ccpolyzp_po2cyc_eval_apply_galois(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, uint32_t galois_elt);

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_GALOIS_H */
