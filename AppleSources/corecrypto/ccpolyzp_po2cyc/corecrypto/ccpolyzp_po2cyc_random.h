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

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_RANDOM_H
#define _CORECRYPTO_CCPOLYZP_PO2CYC_RANDOM_H

#include "ccpolyzp_po2cyc_internal.h"
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccrng.h>

/// The size of the seed for `ccpolyzp_po2cyc_block_rng_init`.
#define CCPOLYZP_PO2CYC_RANDOM_RNG_SEED_SIZE 32

/// Object to store the block rng seed
struct ccpolyzp_po2cyc_block_rng_seed {
    uint8_t data[CCPOLYZP_PO2CYC_RANDOM_RNG_SEED_SIZE];
};

typedef struct ccpolyzp_po2cyc_block_rng_seed *ccpolyzp_po2cyc_block_rng_seed_t;
typedef const struct ccpolyzp_po2cyc_block_rng_seed *ccpolyzp_po2cyc_block_rng_seed_const_t;

cc_static_assert(sizeof(struct ccpolyzp_po2cyc_block_rng_seed) == CCPOLYZP_PO2CYC_RANDOM_RNG_SEED_SIZE,
                 "sizeof(struct ccpolyzp_po2cyc_block_rng_seed) != CCPOLYZP_PO2CYC_RANDOM_RNG_SEED_SIZE");

#define CCPOLYZP_PO2CYC_RANDOM_BUFFER 4096
#define CCPOLYZP_PO2CYC_RANDOM_DRBG_MAX_STATE_SIZE 88

/// NIST SP 800-90 AES-CTR DRBG PRNG using a 4KB buffer
/// Once properly initialized, a pointer to this can be cast to `struct ccrng_state *` and used in various places that require a
/// PRNG.
struct ccpolyzp_po2cyc_block_rng_state {
    CCRNG_STATE_COMMON
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;
    uint8_t drbg_state[CCPOLYZP_PO2CYC_RANDOM_DRBG_MAX_STATE_SIZE];
    cc_size index;
    uint8_t buffer[CCPOLYZP_PO2CYC_RANDOM_BUFFER];
} CC_ALIGNED(CCN_UNIT_SIZE);

typedef struct ccpolyzp_po2cyc_block_rng_state *ccpolyzp_po2cyc_block_rng_state_t;
typedef const struct ccpolyzp_po2cyc_block_rng_state *ccpolyzp_po2cyc_block_rng_state_const_t;

/// @brief Allocate a new block rng
/// @param ws  Workspace
/// @return The allocated memory
#define CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws) \
    (struct ccpolyzp_po2cyc_block_rng_state *)CC_ALLOC_WS(ws, ccn_nof_sizeof(struct ccpolyzp_po2cyc_block_rng_state))

/// @brief Initialize NIST SP 800-90 AES-CTR DRBG PRNG using a 4KB buffer from a seed
/// @param rng The block rng state to initialize
/// @param seed The seed used to initialize the block rng
/// @return CCERR_OK if operation suceeds
CC_NONNULL_ALL
int ccpolyzp_po2cyc_block_rng_init(ccpolyzp_po2cyc_block_rng_state_t rng, ccpolyzp_po2cyc_block_rng_seed_const_t seed);

/// @brief Overwrite the polynomial with each coefficent chosen uniformly from [0, q)
/// @param ws Workspace
/// @param r The polynomial where to store values
/// @param rng The random number generator to use
/// @return CCERR_OK if operation suceeds
CC_NONNULL_ALL
int ccpolyzp_po2cyc_random_uniform_ws(cc_ws_t ws, ccpolyzp_po2cyc_t r, struct ccrng_state *rng);

/// @brief Overwrite the polynomial with each coefficent chosen uniformly from the set {-1, 0, 1} mod q
/// @param ws Workspace
/// @param r The polynomial where to store values
/// @param rng The random number generator to use
/// @return CCERR_OK if operation suceeds
CC_NONNULL_ALL
int ccpolyzp_po2cyc_random_ternary_ws(cc_ws_t ws, ccpolyzp_po2cyc_t r, struct ccrng_state *rng);

typedef enum {
    /// noise level with standard deviation 3.20 (recommended value)
    CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2 = 0,
} ccpolyzp_po2cyc_random_cbd_sigma_t;

/// @brief Overwrite the polynomial with each coefficient chosen from a centered binomial distribution
/// @param ws Workspace
/// @param r The polynomial where to store values
/// @param rng The random number generator to use
/// @param sigma Enum that chooses the standard deviation for the noise distribution
/// @return CCERR_OK if operation suceeds
/// @details coeff = (B(n/2, p) - B(n/2, p)) mod q, where p = 0.5 and n is calculated from the standard deviation:
/// variance = np(1-p)
/// n = sigma^2 / ( p * (1-p)) = sigma^2 * 4
CC_NONNULL_ALL
int ccpolyzp_po2cyc_random_cbd_ws(cc_ws_t ws,
                                  ccpolyzp_po2cyc_t r,
                                  struct ccrng_state *rng,
                                  ccpolyzp_po2cyc_random_cbd_sigma_t sigma);

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_RANDOM_H */
