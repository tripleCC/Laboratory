/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_DEBUG_H_
#define _CORECRYPTO_CCPOLYZP_PO2CYC_DEBUG_H_

#include <corecrypto/cc_config.h>
#include "ccpolyzp_po2cyc_internal.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Prints a human-readable representation of a context
/// @param context The context to print
/// @param label Optionally, the label to associate with the context
CC_NONNULL((1))
void ccpolyzp_po2cyc_ctx_lprint(ccpolyzp_po2cyc_ctx_const_t context, const char *cc_cstring label);

/// @brief Prints a human-readable representation of a polynomial in coefficient format
/// @param x The polynomial to print
/// @param label Optionally, the label to associate with the polynomial
CC_NONNULL((1))
void ccpolyzp_po2cyc_coeff_lprint(ccpolyzp_po2cyc_coeff_const_t x, const char *cc_cstring label);

/// @brief Prints a human-readable representation of a polynomial in evaluation format
/// @param x The polynomial to print
/// @param label Optionally, the label to associate with the polynomial
CC_NONNULL((1))
void ccpolyzp_po2cyc_eval_lprint(ccpolyzp_po2cyc_eval_const_t x, const char *cc_cstring label);

/// @brief Returns whether or not a polynomial in coefficient format has all coefficients in [0, q - 1]
/// @param x Polynomial
/// @details Not constant-time
CC_NONNULL_ALL bool ccpolyzp_po2cyc_coeff_has_valid_data(ccpolyzp_po2cyc_coeff_const_t x);

/// @brief Returns whether or not a polynomial in evaluation format has all coefficients in [0, q - 1]
/// @param x Polynomial
/// @details Not constant-time
CC_NONNULL_ALL CC_INLINE bool ccpolyzp_po2cyc_eval_has_valid_data(ccpolyzp_po2cyc_eval_const_t x)
{
    return ccpolyzp_po2cyc_coeff_has_valid_data((ccpolyzp_po2cyc_coeff_const_t)x);
}

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_DEBUG_H_ */
