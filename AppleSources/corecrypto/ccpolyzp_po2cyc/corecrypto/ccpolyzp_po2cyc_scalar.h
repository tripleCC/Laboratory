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

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_SCALAR_H
#define _CORECRYPTO_CCPOLYZP_PO2CYC_SCALAR_H

#include <corecrypto/cc_config.h>
#include "cc.h"
#include "cc_memory.h"

/// Coefficients and moduli are 64-bits stored in cc_units
typedef uint64_t ccrns_int;
#define CCRNS_INT_MAX UINT64_MAX
// Must be compile-time constant to suport #if CCPOLYZP_PO2CYC_NUNITS_PER_COEFF == N
#define CCRNS_INT_NBYTES 8
// Must be a power of two to support masking
#define CCRNS_INT_NBITS 64
#define CCRNS_INT_MASK ((ccrns_int)~0)
#define CCRNS_INT_NBITS_MINUS_1 (CCRNS_INT_NBITS - 1)
#define CCPOLYZP_PO2CYC_NUNITS_PER_COEFF (CCRNS_INT_NBYTES / CCN_UNIT_SIZE)
// Defines an exclusive upper bound on each RNS modulus, i.e. q_i < CCPOLYZP_PO2CYC_MAX_MODULUS
#define CCPOLYZP_PO2CYC_MAX_MODULUS (UINT64_C(1) << 63)

/// @brief Converts a ccrns_int to cc_units compatible with cczp operations
/// @param units The units to populate
/// @param rns_int The integer to convert
CC_NONNULL_ALL CC_INLINE void ccpolyzp_po2cyc_rns_int_to_units(cc_unit *units, ccrns_int rns_int)
{
#if CCPOLYZP_PO2CYC_NUNITS_PER_COEFF == 1
    *units = rns_int;
#elif CCPOLYZP_PO2CYC_NUNITS_PER_COEFF == 2
    // Store coefficients with low order bits in units[0], stored in host-endianness
    cc_store64_le(rns_int, (uint8_t *)units);
    units[0] = CC_H2LE32(units[0]);
    units[1] = CC_H2LE32(units[1]);
#else
#error "Unsupported CCPOLYZP_PO2CYC_NUNITS_PER_COEFF"
#endif
}

/// @brief Converts cc_units to a ccrns_int
/// @param units The units to convert
CC_NONNULL_ALL CC_INLINE ccrns_int ccpolyzp_po2cyc_units_to_rns_int(const cc_unit *units)
{
#if CCPOLYZP_PO2CYC_NUNITS_PER_COEFF == 1
    return (ccrns_int)(*units);
#elif CCPOLYZP_PO2CYC_NUNITS_PER_COEFF == 2
    cc_unit coeff_le[2];
    coeff_le[0] = CC_H2LE32(units[0]);
    coeff_le[1] = CC_H2LE32(units[1]);
    return cc_load64_le((const uint8_t *)&coeff_le);
#else
#error "Unsupported CCPOLYZP_PO2CYC_NUNITS_PER_COEFF"
#endif
}

/// @brief Stores pre-computed factors for efficient modular operations for a ccrns_int modulus
/// @details The modulus value must be in [2, CCPOLYZP_PO2CYC_MAX_MODULUS - 1]. This ensures the pre-computed values fit in one
/// ccrns_int (mod1_factor) or two ccrns_int's (mod2_factor)
struct ccrns_modulus {
    /// @brief The modulus
    ccrns_int value;
    /// @brief floor(2^CCRNS_INT_NBITS / value)
    ccrns_int mod1_factor;
    /// @brief floor(2^(2 * CCRNS_INT_NBITS) / value)
    ccrns_int mod2_factor[2];
    /// @brief low 2 * CCRNS_INT_NBITS bits of ceil(2^k / value) - 2^(2 * CCRNS_INT_NBITS),
    /// where `k = 2 * CCRNS_INT_NBITS + ceil(log2(value))`
    cc_unit div_a[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
};
typedef struct ccrns_modulus *ccrns_modulus_t;
typedef const struct ccrns_modulus *ccrns_modulus_const_t;

/// @brief Initializes a modulus for efficient modular operations
/// @param ws Workspace
/// @param p Modulus to initialize
/// @param value Value of the modulus. Must be in [2, 2^63 - 1]
/// @return CCERR_OK if modulus initialized successfully
CC_NONNULL_ALL CC_WARN_RESULT int ccrns_modulus_init_ws(cc_ws_t ws, ccrns_modulus_t p, ccrns_int value);

/// @brief Initializes a modulus for efficient modular operations
/// @param ws Workspace
/// @param p Modulus to initialize
/// @param value Value of the modulus. Must be in [2, 2^63 - 1]
/// @return CCERR_OK if modulus initialized successfully
/// @details Leaks `value` through timing. For a constant-time alternative, use `ccrns_modulus_init_ws`
CC_NONNULL_ALL CC_WARN_RESULT int ccrns_modulus_init_var_time_ws(cc_ws_t ws, ccrns_modulus_t p, ccrns_int value);

/// @brief Stores pre-computed factors for efficient modular multiplication with a known multiplicand and a ccrns_int modulus
struct ccrns_mul_modulus {
    /// @brief The modulus
    ccrns_int modulus;
    /// @brief Must be in [0, modulus - 1]
    ccrns_int multiplicand;
    /// @brief floor(2^CCRNS_INT_NBITS * multiplicand / modulus)
    ccrns_int mod_factor;
};
typedef struct ccrns_mul_modulus *ccrns_mul_modulus_t;
typedef const struct ccrns_mul_modulus *ccrns_mul_modulus_const_t;

/// @brief Returns the number of cc_units required to store ccrns_mul_modulus
CC_INLINE CC_WARN_RESULT cc_size ccrns_mul_modulus_nof_n(void)
{
    return ccn_nof_size(sizeof_struct_ccrns_mul_modulus());
}

/// @brief Initializes a modulus for efficient modular multiplication by a known multiplicand
/// @param p Modulus to initialize
/// @param value Value of the modulus. Must be in [2, 2^63 - 1]
/// @param multiplicand Multiplicand. Must be in [0, value - 1]
/// @return CCERR_OK if modulus initialized successfully
CC_NONNULL_ALL CC_WARN_RESULT int
ccrns_mul_modulus_init_ws(cc_ws_t ws, ccrns_mul_modulus_t p, ccrns_int value, ccrns_int multiplicand);

/// @brief Initializes a modulus for efficient modular multiplication by a known multiplicand
/// @param p Modulus to initialize
/// @param value Value of the modulus. Must be in [2, 2^63 - 1]
/// @param multiplicand Multiplicand. Must be in [0, value - 1]
/// @return CCERR_OK if modulus initialized successfully
/// @details Leaks `value, multiplicand` through timing. For a constant-time alternative, use `ccrns_mul_modulus_init_ws`.
CC_NONNULL_ALL CC_WARN_RESULT int
ccrns_mul_modulus_init_var_time_ws(cc_ws_t ws, ccrns_mul_modulus_t p, ccrns_int value, ccrns_int multiplicand);

/// @brief Given x in [0, 2p - 1], returns x % p
/// @param x Must be in [0, 2p - 1]
/// @param p Modulus. Must be < 2^63
/// @details Constant-time
CC_INLINE CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_cond_sub(ccrns_int x, ccrns_int p)
{
    cc_assert(x < 2 * p && p < (UINT64_C(1) << 63));
    ccrns_int x_minus_p = x - p; // May underflow
    ccrns_int x_gt_p = (x_minus_p >> CCRNS_INT_NBITS_MINUS_1) ^ 1;
    ccrns_int result;
    CC_MUXU(result, x_gt_p, x_minus_p, x);
    return result;
}

/// @brief Returns (x + y) % p
/// @param x Summand. Must be in [0, p-1]
/// @param y Summand. Must be in [0, p-1]
/// @param p Modulus. Must be < 2^63
/// @details Constant-time
CC_INLINE CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_add_mod(ccrns_int x, ccrns_int y, ccrns_int p)
{
    cc_assert(x < p && y < p && p < (UINT64_C(1) << 63));
    ccrns_int sum = x + y;
    return ccpolyzp_po2cyc_scalar_cond_sub(sum, p);
}

/// @brief Returns (x - y) % p
/// @param x x Minuend. Must be in [0, p-1]
/// @param y Subtrahend. Must be in [0, p-1]
/// @param p Modulus. Must be < 2^63
/// @details Constant-time
CC_INLINE CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_sub_mod(ccrns_int x, ccrns_int y, ccrns_int p)
{
    cc_assert(x < p && y < p && p < (UINT64_C(1) << 63));
    ccrns_int diff = (x + p) - y;
    return ccpolyzp_po2cyc_scalar_cond_sub(diff, p);
}

/// @brief Returns -x % p
/// @param x Value to negate; must be in [0, p - 1]
/// @param p Modulus
/// @details Constant-time
CC_INLINE CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_negate_mod(ccrns_int x, ccrns_int p)
{
    cc_assert(x < p);
    ccrns_int p_minus_x = p - x;
    ccrns_int x_gt_0;
    CC_HEAVISIDE_STEP(x_gt_0, x);
    ccrns_int result;
    CC_MUXU(result, x_gt_0, p_minus_x, 0);
    return result;
}

/// @brief Returns the high CCRNS_INT_NBITS bits of x * y
/// @param x Multiplicand
/// @param y Multiplicand
CC_INLINE CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_mul_hi(ccrns_int x, ccrns_int y)
{
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    return ((cc_dunit)x * y) >> CCRNS_INT_NBITS;
#else
    cc_unit x_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(x_units, x);
    cc_unit y_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(y_units, y);

    cc_unit prod[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_mul(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, prod, x_units, y_units);
    return ccpolyzp_po2cyc_units_to_rns_int(&prod[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
#endif
}

/// @brief Computes the product x * y
/// @param r Stores the product as 2 * CCRNS_INT_NBITS, with r[0] storing the low CCRNS_INT_NBITS bits.
/// @param x Multiplicand
/// @param y Multiplicand
CC_INLINE void ccpolyzp_po2cyc_scalar_mul(ccrns_int *r, ccrns_int x, ccrns_int y)
{
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    cc_dunit product = (cc_dunit)x * y;
    r[0] = (ccrns_int)(product & CCRNS_INT_MASK);
    r[1] = (ccrns_int)(product >> CCRNS_INT_NBITS);
#else
    r[0] = x * y;
    r[1] = ccpolyzp_po2cyc_scalar_mul_hi(x, y);
#endif
}

/// @brief Returns x % p
/// @param x Value to reduce
/// @param p Modulus; must be in [2, 2^63 - 1]
/// @details Constant-time
/// Proof of correctness:
///     Let b = floor(2^64 / p)
///     Let q = floor(x * b / 2^64)
///     We want to show 0 <= x - q * p < 2p
///     * First, by definition of b, 0 <= 2^64 / p - b < 1        (1)
///     * Second, by definition of q, 0 <= x * b / 2^64 - q < 1   (2)
///     * Multiplying (1) by x * p / 2^64 yields
///       0 <= x - x * b * p / 2^64 < x * p / 2^64                (3)
///     * Multiplying (2) by p yields
///       0 <= x * p * b / 2^64 - q * p < p                       (4)
///     * Adding (3) and (4) yields 0 <= x - q * p < x * p / 2^64 + p < 2p
/// Thus, we need only a single conditional subtraction
/// Note, the bound on p < 2^63 comes from 2 * p < 2^64, allowing us to compute only the low 64 bits of x - q * p
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_mod1(ccrns_int x, ccrns_modulus_const_t p)
{
    cc_assert(p->value > 1 && p->value < 1ULL << 63);
    ccrns_int q_hat = ccpolyzp_po2cyc_scalar_mul_hi(x, p->mod1_factor);
    ccrns_int z = x - q_hat * p->value;
    return ccpolyzp_po2cyc_scalar_cond_sub(z, p->value);
}

/// @brief Returns r < 2p such that r mod p = x mod p
/// @param x Value to reduce; stored with 2 * CCRNS_INT_NBITS bits
/// @param p Modulus; must be in [2, 2^63 - 1]
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT ccrns_int
ccpolyzp_po2cyc_scalar_mod2_lazy(const cc_unit *cc_counted_by(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) x, ccrns_modulus_const_t p)
{
    cc_assert(p->value > 1 && p->value < 1ULL << 63);

    ccrns_int x_lo = ccpolyzp_po2cyc_units_to_rns_int(x);
    ccrns_int x_hi = ccpolyzp_po2cyc_units_to_rns_int(&x[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);

    // Compute word2 = ((x * p->mod2_factor) >> (2 * CCRNS_INT_NBITS)) % (1 << CCRNS_INT_NBITS)
    // where [b_hi, b_lo] is the Barrett factor p->mod2_factor:
    //               [ x_hi, x_lo ]
    //             x [ b_hi, b_lo ]
    // ---------------------------
    //               [x_lo * b_lo ]
    //         [x_hi * b_lo]
    //         [x_lo * b_hi]
    // + [x_hi * b_hi]
    // ---------------------------
    //   |word3|word2|word1|word0 |
    //            ^- we only need these bits
    ccrns_int x_lo_times_b_lo = ccpolyzp_po2cyc_scalar_mul_hi(x_lo, p->mod2_factor[0]);
    ccrns_int x_hi_times_b_lo[2];
    ccpolyzp_po2cyc_scalar_mul(x_hi_times_b_lo, x_hi, p->mod2_factor[0]);

    ccrns_int word1;
    // Ignore overflow into word3
    ccrns_int word2 = x_hi_times_b_lo[1] + (ccrns_int)cc_add_overflow(x_lo_times_b_lo, x_hi_times_b_lo[0], &word1);

    ccrns_int x_lo_times_b_hi[2];
    ccpolyzp_po2cyc_scalar_mul(x_lo_times_b_hi, x_lo, p->mod2_factor[1]);

    // Ignore overflow into word3
    word2 += x_lo_times_b_hi[1] + (ccrns_int)cc_add_overflow(x_lo_times_b_hi[0], word1, &word1);
    // Ignore overflow into word3
    word2 += x_hi * p->mod2_factor[1];

    // Barrett subtraction; we know the result will be single-word (p < 2^63, so 2p < 2^64),
    // so compute only the low 64 bits.
    return x_lo - word2 * p->value;
}

/// @brief Returns x mod p
/// @param x Value to reduce; stored with 2 * CCRNS_INT_NBITS bits
/// @param p Modulus; must be in [2, 2^63 - 1]
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT ccrns_int
ccpolyzp_po2cyc_scalar_mod2(const cc_unit *cc_counted_by(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) x, ccrns_modulus_const_t p)
{
    ccrns_int z = ccpolyzp_po2cyc_scalar_mod2_lazy(x, p);
    return ccpolyzp_po2cyc_scalar_cond_sub(z, p->value);
}

/// @brief Returns r < 2p with r mod p = x * y mod p
/// @param x Multiplicand; may exceed p
/// @param y Multiplicand; may exceed p
/// @param p Modulus; must be in [2, 2^63 - 1]
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_mul_mod_lazy(ccrns_int x,
                                                                                      ccrns_int y,
                                                                                      ccrns_modulus_const_t p)
{
    cc_assert(p->value > 1 && p->value < 1ULL << 63);
    cc_unit prod[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_scalar_mul((ccrns_int *)prod, x, y);
    return ccpolyzp_po2cyc_scalar_mod2_lazy(prod, p);
}

/// @brief Returns x * y mod p
/// @param x Multiplicand; may exceed p
/// @param y Multiplicand; may exceed p
/// @param p Modulus; must be in [2, 2^63 - 1]
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_mul_mod(ccrns_int x,
                                                                                 ccrns_int y,
                                                                                 ccrns_modulus_const_t p)
{
    cc_assert(p->value > 1 && p->value < 1ULL << 63);
    ccrns_int z = ccpolyzp_po2cyc_scalar_mul_mod_lazy(x, y, p);
    return ccpolyzp_po2cyc_scalar_cond_sub(z, p->value);
}

/// @brief Computes `floor(x / p) % 2^CCRNS_INT_NBITS`
/// @param ws Workspace
/// @param r Stores `floor(x / p) % 2^CCRNS_INT_NBITS`
/// @param x Dividend
/// @param p Divisor
CC_NONNULL_ALL void ccpolyzp_po2cyc_scalar_divmod_ws(cc_ws_t ws,
                                                     cc_unit *cc_counted_by(CPOLYZP_PO2CYC_NUNITS_PER_COEFF) r,
                                                     const cc_unit *cc_counted_by(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF) x,
                                                     ccrns_modulus_const_t p);

/// @brief Returns r < 2p with r mod p = x * y mod p for x, y < p
/// @param x Multiplicand; must be < p
/// @param p Modulus with modulus p in [2, 2^63 - 1] and multiplicand y < p
/// @details Proof of correctness follows `ccpolyzp_po2cyc_scalar_shoup_mul_mod`
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_shoup_mul_mod_lazy(ccrns_int x,
                                                                                            ccrns_mul_modulus_const_t p)
{
    cc_assert(p->modulus > 1 && p->modulus < 1ULL << 63);
    cc_assert(p->multiplicand < p->modulus);
    ccrns_int q = ccpolyzp_po2cyc_scalar_mul_hi(x, p->mod_factor);
    // Barrett subtraction; we know the result will be single-word (p < 2^63, so z < 2p < 2^64),
    // so we compute only the low 64 bits.
    return x * p->multiplicand - q * p->modulus;
}

/// @brief Returns x * y mod p for fixed y and p.
/// @param x Multiplicand; must be < p
/// @param p Modulus with modulus p in [2, 2^63 - 1] and multiplicand y in [0, p - 1]
/// @details Proof of correctness:
///     Let b = floor(2^64 / p)
///     Let q = floor(y * b / 2^64) <-- p->mod_factor
///     We want to show 0 <= x * y - q * p < 2p
///     * First, by definition of b, 0 <= 2^64 / p - b < 1        (1)
///     * Second, by definition of q, 0 <= y * b / 2^64 - q < 1   (2)
///     * Multiplying (1) by y * p / 2^64 yields
///       0 <= y - y * b * p / 2^64 < y * p / 2^64                (3)
///     * Multiplying (2) by p yields
///       0 <= y * p * b / 2^64 - q * p < p                       (4)
///     * Adding (3) and (4) yields 0 <= y - q * p < y * p / 2^64 + p < 2p
/// Thus, we need only a single conditional subtraction
/// Note, the bound on p < 2^63 comes from 2 * p < 2^64, allowing us to compute only the low 64 bits of y - q * p
CC_INLINE CC_NONNULL_ALL CC_WARN_RESULT ccrns_int ccpolyzp_po2cyc_scalar_shoup_mul_mod(ccrns_int x, ccrns_mul_modulus_const_t p)
{
    ccrns_int z = ccpolyzp_po2cyc_scalar_shoup_mul_mod_lazy(x, p);
    return ccpolyzp_po2cyc_scalar_cond_sub(z, p->modulus);
}

/// @brief Reverses the bits in x when representing x with nbits bits
/// @param x The number whose bits to reverse, must be less than 2^{nbits}
/// @param nbits The number of bits in x, must be in [1, 32]
/// @details Constant-time
/// @return The reversed low `nbits` bits of `x`
CC_INLINE CC_WARN_RESULT CC_NONNULL_ALL uint32_t ccpolyzp_po2cyc_reverse_bits(uint32_t x, uint32_t nbits)
{
    cc_assert(nbits >= 1 && nbits <= 32);
    cc_assert((nbits == 32) || x < (1UL << nbits));

    // swap consecutive bits
    x = ((x & 0xAAAAAAAA) >> 1) | ((x & 0x55555555) << 1);
    // swap consecutive 2-bit pairs
    x = ((x & 0xCCCCCCCC) >> 2) | ((x & 0x33333333) << 2);
    // swap consecutive 4-bit pairs
    x = ((x & 0xF0F0F0F0) >> 4) | ((x & 0x0F0F0F0F) << 4);
    // swap consecutive bytes
    x = ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8);
    // swap consecutive 2-byte pairs
    x = (x >> 16) | (x << 16);
    x >>= (32 - nbits);
    return x;
}

/// @brief Returns whether or not a value is a power of two
/// @param x The value
/// @return True if x is a power of two, false otherwise
CC_INLINE bool ccpolyzp_po2cyc_is_power_of_two_uint64(uint64_t x)
{
    return cc_popcount64(x) == 1;
}

/// @brief Returns whether or not a value is a power of two
/// @param x The value
/// @return True if x is a power of two, false otherwise
CC_INLINE bool ccpolyzp_po2cyc_is_power_of_two_uint32(uint32_t x)
{
    return cc_popcount32(x) == 1;
}

/// @brief Returns floor(log2(x)) for an unsigned 32-bit integer
/// @param x Must be non-zero
/// @details Returns the greatest integer less than or equal to log2(x)
CC_INLINE uint32_t ccpolyzp_po2cyc_log2_uint32(uint32_t x)
{
    cc_assert(x != 0);
    return CCN_UNIT_BITS - cc_clz_nonzero((cc_unit)x) - 1;
}

/// @brief Returns floor(log2(x)) for an unsigned 64-bit integer
/// @param x Must be non-zero
/// @details Returns the greatest integer less than or equal to log2(x)
CC_INLINE uint32_t ccpolyzp_po2cyc_log2_uint64(uint64_t x)
{
    cc_assert(x != 0);
    return sizeof(uint64_t) * 8 - cc_clz64(x) - 1;
}

/// @brief Returns ceil(log2(x)) for an unsigned 64-bit integer
/// @param x Must be non-zero
/// @details Returns the greatest integer greater than or equal to log2(x)
CC_INLINE uint32_t ccpolyzp_po2cyc_ceil_log2_uint64(uint64_t x)
{
    cc_assert(x != 0);
    uint32_t is_power_of_two = (uint32_t)ccpolyzp_po2cyc_is_power_of_two_uint64(x);
    return ccpolyzp_po2cyc_log2_uint64(x) + (1 - is_power_of_two);
}

/// @brief Transforms x from remainder representation to centered representation
/// @param x Must be in [0, p - 1]
/// @param p Modulus. Must be < 2^63
/// @return x % p in [-floor(p/2), floor(p-1)/2]
/// @details Constant-time
int64_t ccpolyzp_po2cyc_rem_to_centered(ccrns_int x, ccrns_int p);

/// @brief Transforms x from centered representation to remainder representation
/// @param x Must be in [-floor(p/2), floor(p-1)/2]
/// @param p Modulus. Must < 2^63
/// @return x % p in [0, p - 1]
/// @details Constant-time
ccrns_int ccpolyzp_po2cyc_centered_to_rem(int64_t x, ccrns_int p);

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_SCALAR_H */
