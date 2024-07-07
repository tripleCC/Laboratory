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

#include "ccpolyzp_po2cyc_scalar.h"

/// @brief Computes the Barrett factor floor(2^(n * CCRNS_INT_NBITS) * x / p)
/// @param ws Workspace
/// @param r Stores the Barrett factor
/// @param n Number of ccrns_int-sized words to compute the factor for. Must be 1 or 2.
/// @param x The multiplicand. Must be in [0, p - 1]
/// @param p The modulus. Must be in [2, CCPOLYZP_PO2CYC_MAX_MODULUS - 1]
/// @return CCERR_OK if successful
/// @details Leaks `n` through timing
static int ccrns_modulus_compute_mod_factor_ws(cc_ws_t ws, uint32_t n, ccrns_int *cc_counted_by(n) r, ccrns_int x, ccrns_int p)
{
    cc_require_or_return(n > 0 && n <= 2, CCERR_PARAMETER);
    cc_require_or_return(p > 1 && p < CCPOLYZP_PO2CYC_MAX_MODULUS, CCERR_PARAMETER);

    cc_unit p_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(p_units, p);

    cc_unit x_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(x_units, x);

    // 2^(n * CCRNS_INT_NBITS)
    cc_unit mod_factor_numerator_shift[3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] = { 1 };
    ccn_shift_left_multi(
        3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, mod_factor_numerator_shift, mod_factor_numerator_shift, n * CCRNS_INT_NBITS);

    // 2^(n * CCRNS_INT_NBITS) * x
    cc_unit mod_factor_numerator[4 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_muln(3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
             mod_factor_numerator,
             mod_factor_numerator_shift,
             CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
             x_units);

    // floor(2^(n * CCRNS_INT_NBITS) * x / p)
    cc_unit mod_factor[4 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_divmod_ws(ws,
                  4 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                  mod_factor_numerator,
                  3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                  mod_factor,
                  CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                  NULL,
                  p_units);

    for (uint32_t i = 0; i < n; ++i) {
        r[i] = ccpolyzp_po2cyc_units_to_rns_int(&mod_factor[i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
    }

    return CCERR_OK;
}

/// @brief Computes the Barrett factor floor(2^(n * CCRNS_INT_NBITS) * x / p)
/// @param ws Workspace
/// @param r Stores the Barrett factor
/// @param n Number of ccrns_int-sized words to compute the factor for. Must be 1 or 2.
/// @param x The multiplicand. Must be in [0, p - 1]
/// @param p The modulus. Must be in [2, CCPOLYZP_PO2CYC_MAX_MODULUS - 1]
/// @return CCERR_OK if successful
/// @details Leaks `x, n, p` through timing. For an alternative which does not leak `x`, use `ccrns_modulus_compute_mod_factor_ws`
static int
ccrns_modulus_compute_mod_factor_var_time_ws(cc_ws_t ws, uint32_t n, ccrns_int *cc_counted_by(n) r, ccrns_int x, ccrns_int p)
{
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    if (n == 1) {
        cc_dunit numerator = ((cc_dunit)x) << CCRNS_INT_NBITS;
        cc_dunit quotient = numerator / (cc_dunit)p;
        r[0] = (ccrns_int)quotient;
        return CCERR_OK;
    }
#endif
    return ccrns_modulus_compute_mod_factor_ws(ws, n, r, x, p);
}

/// @brief Implementation runtime
typedef enum {
    /// Operation runtime is independent of inputs
    CONSTANT_TIME = 0,
    /// Operation runtime may vary on inputs
    /// @warning Should only be used on public data
    VARIABLE_TIME = 1
} ccpolyzp_po2cyc_runtime_t;

static int ccrns_modulus_init_helper_ws(cc_ws_t ws, ccrns_modulus_t p, ccrns_int value, ccpolyzp_po2cyc_runtime_t runtime)
{
    int rv = CCERR_OK;
    cc_require_or_return(value > 1 && value < CCPOLYZP_PO2CYC_MAX_MODULUS, CCERR_PARAMETER);
    p->value = value;

    cc_unit p_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(p_units, value);

    // compute mod1 factor: floor(2^CCRNS_INT_NBITS / p)
    // compute mod2 factor: floor(2^(2 * CCRNS_INT_NBITS) / p)
    ccrns_int multiplicand = 1;
    switch (runtime) {
    case CONSTANT_TIME:
        cc_require_or_return((rv = ccrns_modulus_compute_mod_factor_ws(ws, 1, &p->mod1_factor, multiplicand, value)) == CCERR_OK,
                             rv);
        cc_require_or_return((rv = ccrns_modulus_compute_mod_factor_ws(ws, 2, p->mod2_factor, multiplicand, value)) == CCERR_OK,
                             rv);
        break;
    case VARIABLE_TIME:
        cc_require_or_return(
            (rv = ccrns_modulus_compute_mod_factor_var_time_ws(ws, 1, &p->mod1_factor, multiplicand, value)) == CCERR_OK, rv);
        cc_require_or_return(
            (rv = ccrns_modulus_compute_mod_factor_var_time_ws(ws, 2, p->mod2_factor, multiplicand, value)) == CCERR_OK, rv);
        break;
    }

    // Compute Barrett factor for division
    // ceil(2^k / p) = floor(2^k / p) + (2^k % p != 0)
    size_t ceil_log2_p = (size_t)ccpolyzp_po2cyc_ceil_log2_uint64(p->value);
    size_t k = 2 * CCRNS_INT_NBITS + ceil_log2_p;
    const cc_size u192_nunits = 3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    cc_unit two_pow_k[3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] = { 1 };
    ccn_shift_left_multi(u192_nunits, two_pow_k, two_pow_k, k);

    // div_a = ceil(2^k / p)
    cc_unit div_a[3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit remainder[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_divmod_ws(ws, u192_nunits, two_pow_k, u192_nunits, div_a, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, remainder, p_units);
    cc_unit has_remainder;
    CC_HEAVISIDE_STEP(has_remainder, (uint64_t)ccpolyzp_po2cyc_units_to_rns_int(remainder));
    cc_unit carry = ccn_add1_ws(ws, u192_nunits, div_a, div_a, has_remainder);
    cc_require_or_return(carry == 0, CCERR_INTERNAL);

    // div_a = ceil(2^k / p) - 2^128
    cc_unit two_pow_128[3 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] = { 1 };
    ccn_shift_left_multi(u192_nunits, two_pow_128, two_pow_128, 2 * CCRNS_INT_NBITS);
    carry = ccn_sub_ws(ws, u192_nunits, div_a, div_a, two_pow_128);
    cc_require_or_return(carry == 0, CCERR_INTERNAL);
    ccn_set(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, p->div_a, div_a);

    return CCERR_OK;
}

int ccrns_modulus_init_ws(cc_ws_t ws, ccrns_modulus_t p, ccrns_int value)
{
    return ccrns_modulus_init_helper_ws(ws, p, value, CONSTANT_TIME);
}

int ccrns_modulus_init_var_time_ws(cc_ws_t ws, ccrns_modulus_t p, ccrns_int value)
{
    return ccrns_modulus_init_helper_ws(ws, p, value, VARIABLE_TIME);
}

int ccrns_mul_modulus_init_ws(cc_ws_t ws, ccrns_mul_modulus_t p, ccrns_int value, ccrns_int multiplicand)
{
    cc_require_or_return(value > 1 && value < CCPOLYZP_PO2CYC_MAX_MODULUS, CCERR_PARAMETER);
    cc_require_or_return(multiplicand < value, CCERR_PARAMETER);
    p->multiplicand = multiplicand;
    p->modulus = value;

    // compute floor(2^CCRNS_INT_NBITS * multiplicand / p)
    ccrns_modulus_compute_mod_factor_ws(ws, 1, &p->mod_factor, multiplicand, value);
    return CCERR_OK;
}

int ccrns_mul_modulus_init_var_time_ws(cc_ws_t ws, ccrns_mul_modulus_t p, ccrns_int value, ccrns_int multiplicand)
{
    cc_require_or_return(value > 1 && value < CCPOLYZP_PO2CYC_MAX_MODULUS, CCERR_PARAMETER);
    cc_require_or_return(multiplicand < value, CCERR_PARAMETER);
    p->multiplicand = multiplicand;
    p->modulus = value;

    // compute floor(2^CCRNS_INT_NBITS * multiplicand / p)
    ccrns_modulus_compute_mod_factor_var_time_ws(ws, 1, &p->mod_factor, multiplicand, value);
    return CCERR_OK;
}

void ccpolyzp_po2cyc_scalar_divmod_ws(cc_ws_t ws, cc_unit *r, const cc_unit *x, ccrns_modulus_const_t p)
{
    // We have pre-computed `p->div_a = ceil(2^k / p) - 2^128`, for `k = 128 + ceil(log2(p))`
    // Now, we compute `floor(x / p) = (((x - b) >> 1) + b) >> (ceil(log2(p)) - 1)`
    // where `b = (x * p->div_a) >> 128`

    // b = (x * p_div_a) >> 128
    cc_unit r_256[4 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_mul_ws(ws, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, r_256, x, p->div_a);
    cc_unit *b = &r_256[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];

    // floor((x - b) >> 1) + b
    cc_unit numerator[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_sub_ws(ws, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, numerator, x, b);
    ccn_shift_right(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, numerator, numerator, 1);
    ccn_add_ws(ws, 2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, numerator, numerator, b);

    size_t right_shift = (size_t)ccpolyzp_po2cyc_ceil_log2_uint64(p->value) - 1;
    ccn_shift_right_multi(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, numerator, numerator, right_shift);
    ccn_set(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, r, numerator);
}

int64_t ccpolyzp_po2cyc_rem_to_centered(ccrns_int x, ccrns_int p)
{
    cc_assert(x < p && p < (UINT64_C(1) << 63));

    // (x > (p - 1) / 2) ? (x - p): x
    ccrns_int p_div_2 = (p - 1) >> 1;
    ccrns_int x_gt_p_div_2 = ((x - (p_div_2 + 1)) >> CCRNS_INT_NBITS_MINUS_1) ^ 1;

    ccrns_int result;
    CC_MUXU(result, x_gt_p_div_2, x - p, x);
    return (int64_t)result;
}

ccrns_int ccpolyzp_po2cyc_centered_to_rem(int64_t x, ccrns_int p)
{
    cc_assert(x >= -(int64_t)p / 2 && x <= ((int64_t)p - 1) / 2 && p < (UINT64_C(1) << 63));

    ccrns_int x_rns = (ccrns_int)x;
    // will be 1 if x < 0
    ccrns_int x_lt_0 = (x_rns >> CCRNS_INT_NBITS_MINUS_1) & 1;

    ccrns_int result;
    CC_MUXU(result, x_lt_0, x_rns + p, x_rns);
    return result;
}
