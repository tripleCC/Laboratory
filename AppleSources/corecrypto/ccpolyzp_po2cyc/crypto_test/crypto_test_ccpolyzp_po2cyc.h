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

#ifndef _CORECRYPTO_CRYPTO_TEST_CCPOLYZP_PO2CYC_H
#define _CORECRYPTO_CRYPTO_TEST_CCPOLYZP_PO2CYC_H

#include "ccpolyzp_po2cyc_internal.h"

/// Returns a uniform random number in [0, max - 1].
ccrns_int rns_int_uniform(ccrns_int max);

/// @brief Initializes a context
/// @param ws Workspace to allocate memory from
/// @param dims Dimensions of the context to initialize
/// @param moduli The moduli in the context to initialize
/// @return The initialized contexts
CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_t ccpolyzp_po2cyc_ctx_init_helper(cc_ws_t ws,
                                                                     ccpolyzp_po2cyc_dims_const_t dims,
                                                                     const ccrns_int *moduli);

/// @brief Initializes a polynomial in coefficient format
/// @param ws The workspace to allocate memory from
/// @param dims The dimensions for the polynomial context
/// @param moduli The moduli for the polynomial context
/// @param coeffs The polynomial coefficients
/// @return The initialized polynomial
ccpolyzp_po2cyc_coeff_t ccpolyzp_po2cyc_coeff_init_helper(cc_ws_t ws,
                                                          ccpolyzp_po2cyc_dims_const_t dims,
                                                          const ccrns_int *moduli,
                                                          const ccrns_int *coeffs);

/// @brief Initializes a zero polynomial in coefficient format
/// @param ws The workspace to allocate memory from
/// @param dims The dimensions for the polynomial context
/// @param moduli The moduli for the polynomial context
/// @return The initialized polynomial
ccpolyzp_po2cyc_coeff_t ccpolyzp_po2cyc_coeff_init_zero_helper(cc_ws_t ws,
                                                               ccpolyzp_po2cyc_dims_const_t dims,
                                                               const ccrns_int *cc_counted_by(dims->nmoduli) moduli);

/// @brief Initializes a polynomial in evaluation format
/// @param ws The workspace to allocate memory from
/// @param dims The dimensions for the polynomial context
/// @param moduli The polynomial context's moduli
/// @param coeffs The polynomial coefficients
/// @return The initialized polynomial
ccpolyzp_po2cyc_eval_t ccpolyzp_po2cyc_eval_init_helper(cc_ws_t ws,
                                                        ccpolyzp_po2cyc_dims_const_t dims,
                                                        const ccrns_int *cc_counted_by(dims->nmoduli) moduli,
                                                        const ccrns_int *cc_counted_by(dims->nmoduli * dims->degree) coeffs);

/// @brief Initializes a zero polynomial in evaluation format
/// @param ws The workspace to allocate memory from
/// @param dims The dimensions for the polynomial context
/// @param moduli The moduli for the polynomial context
/// @return The initialized polynomial
ccpolyzp_po2cyc_eval_t ccpolyzp_po2cyc_eval_init_zero_helper(cc_ws_t ws,
                                                             ccpolyzp_po2cyc_dims_const_t dims,
                                                             const ccrns_int *cc_counted_by(dims->nmoduli) moduli);

/// @brief Returns whether or not all of a polynomial's RNS coefficients are in list of values
/// @param poly Polynomial
/// @param values List of checked RNS values
/// @param nvalues Number of values in `values`
/// @details Not constant-time. For each coefficient `x mod q`, checks `x mod q_i == values[j]` for some `0 <= j < nvalues`.
/// Note, this does *not* ensure `x mod q == values[j]` for some `0 <= j < nvalues`.
CC_NONNULL_ALL bool ccpolyzp_po2cyc_coeff_rns_in(ccpolyzp_po2cyc_coeff_const_t poly, ccrns_int *values, uint32_t nvalues);

/// @brief Returns whether or not a polynomial has all coefficients with value 0
/// @param poly Polynomial
CC_INLINE CC_NONNULL_ALL bool ccpolyzp_po2cyc_all_zero(ccpolyzp_po2cyc_const_t poly)
{
    ccrns_int values[] = { 0 };
    return ccpolyzp_po2cyc_coeff_rns_in((ccpolyzp_po2cyc_coeff_const_t)poly, values, 1);
}

/// @brief Returns whether or not a polynomial has all coefficients with value 1
/// @param poly Polynomial
CC_INLINE CC_NONNULL_ALL bool ccpolyzp_po2cyc_coeff_all_one(ccpolyzp_po2cyc_coeff_const_t poly)
{
    ccrns_int values[] = { 1 };
    return ccpolyzp_po2cyc_coeff_rns_in((ccpolyzp_po2cyc_coeff_const_t)poly, values, 1);
}

/// @brief Returns whether or not a polynomial has any zero RNS components
/// @param poly Polynomial
/// @details Note, a zero RNS component does *not* guarantee a zero polynomial coefficient, but rather that the coefficient `x`
/// satisfies `x % q_i = 0` for some `q_i`.
bool ccpolyzp_po2cyc_has_zero_rns(ccpolyzp_po2cyc_const_t poly);

/// @brief Returns the computed variance from a polynomial, as a float
/// @param poly Polynomial
float ccpolyzp_po2cyc_compute_variance(ccpolyzp_po2cyc_const_t poly);

void test_ccpolyzp_po2cyc_base_convert(void);
void test_ccpolyzp_po2cyc_galois(void);
void test_ccpolyzp_po2cyc_random(void);
void test_ccpolyzp_po2cyc_serialization(void);
void test_ccpolyzp_po2cyc_scalar(void);

#endif /* _CORECRYPTO_CRYPTO_TEST_CCPOLYZP_PO2CYC_H */
