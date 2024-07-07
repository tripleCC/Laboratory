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

#ifndef _CORECRYPTO_CRYPTO_TEST_CCHE_H
#define _CORECRYPTO_CRYPTO_TEST_CCHE_H

#include <corecrypto/cc_config.h>
#include <corecrypto/ccrng.h>
#include "testmore.h"
#include "cche_priv.h"
#include "cche_internal.h"

/// @brief Returns a uniform random signed number in [-max/2, max/2 - 1]
/// @param max Maximum magnitude of generated number
CC_INLINE int64_t uniform_int64(uint64_t max)
{
    uint64_t result;
    ccrng_uniform(global_test_rng, max, &result);
    return (int64_t)result - (int64_t)max / 2;
}

/// @brief Generates an array of uniform values in [0, modulus - 1]
/// @param n Number of entries in the array
/// @param values Array to populate
/// @param modulus Exclusive upper bound on entry values
CC_INLINE void random_int_array(uint32_t n, uint64_t *cc_counted_by(n) values, uint64_t modulus)
{
    for (uint32_t i = 0; i < n; ++i) {
        ccrng_uniform(global_test_rng, modulus, values + i);
    }
}

/// @brief Returns whether or not two unsigned integer arrays are equal
/// @param n Number of elements in each array
/// @param x Array of elements to compare
/// @param y Array of elements to compare
/// @return True if arrays are equal
CC_INLINE CC_NONNULL_ALL bool array_eq_uint64(uint32_t n, const uint64_t *cc_counted_by(n) x, const uint64_t *cc_counted_by(n) y)
{
    for (uint32_t i = 0; i < n; ++i) {
        if (x[i] != y[i]) {
            return false;
        }
    }
    return true;
}

/// @brief Returns whether or not two unsigned integer arrays are equal
/// @param n Number of elements in each array
/// @param x Array of elements to compare
/// @param y Array of elements to compare
/// @return True if arrays are equal
CC_INLINE CC_NONNULL_ALL bool array_eq_uint32(uint32_t n, const uint32_t *cc_counted_by(n) x, const uint32_t *cc_counted_by(n) y)
{
    for (uint32_t i = 0; i < n; ++i) {
        if (x[i] != y[i]) {
            return false;
        }
    }
    return true;
}

/// @brief Returns whether or not two signed integer arrays are equal
/// @param n Number of elements in each array
/// @param x Array of elements to compare
/// @param y Array of elements to compare
/// @return True if arrays are equal
CC_INLINE CC_NONNULL_ALL bool array_eq_int64(uint32_t n, const int64_t *cc_counted_by(n) x, const int64_t *cc_counted_by(n) y)
{
    for (uint32_t i = 0; i < n; ++i) {
        if (x[i] != y[i]) {
            return false;
        }
    }
    return true;
}

/// @brief Returns test encryption parameters
cche_encrypt_params_const_t get_test_encrypt_params(cche_scheme_t he_scheme, uint32_t nmoduli);

void test_cche_compose_decompose(cche_scheme_t he_scheme);
void test_cche_serialization(void);
void test_cche_galois(cche_scheme_t he_scheme);
void test_cche_relin(cche_scheme_t he_scheme);
int ntests_cche_public(void);
void test_cche_public(void);

#endif /* _CORECRYPTO_CRYPTO_TEST_CCHE_H */
