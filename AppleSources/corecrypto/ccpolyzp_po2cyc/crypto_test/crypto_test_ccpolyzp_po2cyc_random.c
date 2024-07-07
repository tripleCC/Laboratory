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

#include "crypto_test_ccpolyzp_po2cyc.h"
#include "ccpolyzp_po2cyc_random.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include "ccpolyzp_po2cyc_debug.h"

static void test_ccpolyzp_po2cyc_random_rng_workspace(void)
{
    CC_DECL_WORKSPACE_TEST(ws)
    const struct ccpolyzp_po2cyc_block_rng_seed seed = { .data = { 0 } };
    struct ccpolyzp_po2cyc_block_rng_state *rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
    is(ccpolyzp_po2cyc_block_rng_init(rng, &seed), CCERR_OK, "ccpolyzp_po2cyc_block_rng_init != CCERR_OK");
    is(rng->info.size <= CCPOLYZP_PO2CYC_RANDOM_DRBG_MAX_STATE_SIZE,
       true,
       "CCPOLYZP_PO2CYC_RANDOM_DRBG_MAX_STATE_SIZE definition needs to be updated!");
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_random_uniform_kat(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 11, 13 };
    ccpolyzp_po2cyc_coeff_t zero_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);

    struct ccpolyzp_po2cyc_block_rng_state *block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
    struct ccrng_state *rng = (struct ccrng_state *)block_rng;

    // random uniform != zero
    {
        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff, global_test_rng);
        is(ccpolyzp_po2cyc_coeff_eq(poly_coeff, zero_coeff), false, "ccpolyzp_po2cyc_random_uniform random uniform != zero");
    }
    // random uniform with zero seed
    {
        const struct ccpolyzp_po2cyc_block_rng_seed seed = { .data = { 0 } };
        ccrns_int expected0[] = { 4, 0, 2, 8, 10, 9, 3, 2 };
        ccrns_int expected1[] = { 5, 6, 0, 5, 1, 3, 6, 11 };
        ccrns_int expected2[] = { 0, 3, 4, 4, 8, 9, 0, 10 };
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        ccpolyzp_po2cyc_coeff_t poly_expected0 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected0);
        ccpolyzp_po2cyc_coeff_t poly_expected1 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected1);
        ccpolyzp_po2cyc_coeff_t poly_expected2 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected2);

        is(ccpolyzp_po2cyc_block_rng_init(block_rng, &seed), CCERR_OK, "Error initializing block_rng");
        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected0), true, "ccpolyzp_po2cyc_random_uniform zero seed != expected0");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
        }

        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected1), true, "ccpolyzp_po2cyc_random_uniform zero seed != expected1");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
        }

        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected2), true, "ccpolyzp_po2cyc_random_uniform zero seed != expected2");
    }
    // random uniform with nonzero seed
    {
        byteBuffer seed = hexStringToBytes("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        ccrns_int expected0[] = { 9, 6, 9, 0, 10, 8, 7, 3 };
        ccrns_int expected1[] = { 2, 9, 9, 1, 12, 0, 0, 12 };
        ccrns_int expected2[] = { 5, 1, 0, 10, 8, 2, 8, 1 };
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        ccpolyzp_po2cyc_coeff_t poly_expected0 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected0);
        ccpolyzp_po2cyc_coeff_t poly_expected1 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected1);
        ccpolyzp_po2cyc_coeff_t poly_expected2 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected2);

        is(seed->len, 32, "seed length != 32");
        is(ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed->bytes),
           CCERR_OK,
           "Error initializing block_rng");
        free(seed);
        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected0), true, "ccpolyzp_po2cyc_random_uniform nonzero seed != expected0");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
        }

        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected1), true, "ccpolyzp_po2cyc_random_uniform nonzero seed != expected1");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
        }

        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected2), true, "ccpolyzp_po2cyc_random_uniform nonzero seed != expected2");
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_random_uniform_properties(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 8192, .nmoduli = 2 };
    ccrns_int moduli[] = { (1ULL << 55) - 311295, (1ULL << 55) - 1392639 };

    // random uniform != zero
    {
        CC_DECL_BP_WS(ws, bp);

        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        is(ccpolyzp_po2cyc_all_zero((ccpolyzp_po2cyc_t)poly_coeff), true, "ccpolyzp_po2cyc_coeff_init_helper non-zero");
        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff, global_test_rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");

        bool has_zero = ccpolyzp_po2cyc_has_zero_rns((ccpolyzp_po2cyc_const_t)poly_coeff);
        is(has_zero, false, "ccpolyzp_po2cyc_random_uniform has 0 coefficient");

        CC_FREE_BP_WS(ws, bp);
    }
    // random uniform with nonzero seed
    {
        CC_DECL_BP_WS(ws, bp);

        struct ccpolyzp_po2cyc_block_rng_state *block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
        struct ccrng_state *rng = (struct ccrng_state *)block_rng;

        byteBuffer seed = hexStringToBytes("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        is(seed->len, 32, "seed length != 32");
        is(ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed->bytes),
           CCERR_OK,
           "Error initializing block_rng");
        free(seed);

        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        is(ccpolyzp_po2cyc_all_zero((ccpolyzp_po2cyc_t)poly_coeff), true, "ccpolyzp_po2cyc_coeff_init_helper non-zero");
        is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_uniform != CCERR_OK");

        bool has_zero = ccpolyzp_po2cyc_has_zero_rns((ccpolyzp_po2cyc_const_t)poly_coeff);
        is(has_zero, false, "ccpolyzp_po2cyc_random_uniform has 0 coefficient");

        CC_FREE_BP_WS(ws, bp);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_random_ternary_kat(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 11, 13 };
    ccrns_int zero_data[8] = { 0 };
    struct ccpolyzp_po2cyc_block_rng_state *block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
    struct ccrng_state *rng = (struct ccrng_state *)block_rng;
    // random ternary with nonzero seed
    {
        byteBuffer seed = hexStringToBytes("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        ccrns_int expected0[] = { 0, 10, 10, 1, 0, 12, 12, 1 };
        ccrns_int expected1[] = { 1, 10, 1, 0, 1, 12, 1, 0 };
        ccrns_int expected2[] = { 1, 0, 0, 1, 1, 0, 0, 1 };
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, zero_data);
        ccpolyzp_po2cyc_coeff_t poly_expected0 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected0);
        ccpolyzp_po2cyc_coeff_t poly_expected1 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected1);
        ccpolyzp_po2cyc_coeff_t poly_expected2 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected2);

        is(seed->len, 32, "seed length != 32");
        is(ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed->bytes),
           CCERR_OK,
           "Error initializing block_rng");
        free(seed);
        is(ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_ternary != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected0), true, "ccpolyzp_po2cyc_random_ternary nonzero seed != expected0");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
        }

        is(ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_ternary != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected1), true, "ccpolyzp_po2cyc_random_ternary nonzero seed != expected1");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly, rng);
        }

        is(ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_ternary != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected2), true, "ccpolyzp_po2cyc_random_ternary nonzero seed != expected2");
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_random_ternary_properties(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 8192, .nmoduli = 2 };
    ccrns_int moduli[] = { (1ULL << 55) - 311295, (1ULL << 55) - 1392639 };
    ccrns_int valid_rns_coeffs[] = { 0, 1, moduli[0] - 1, moduli[1] - 1 };

    // random ternary has zero coefficient
    {
        CC_DECL_BP_WS(ws, bp);

        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        is(ccpolyzp_po2cyc_all_zero((ccpolyzp_po2cyc_t)poly_coeff), true, "ccpolyzp_po2cyc_coeff_init_helper non-zero");
        is(ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff, global_test_rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_ternary_ws != CCERR_OK");
        bool has_ternary_coeffs = ccpolyzp_po2cyc_coeff_rns_in(poly_coeff, valid_rns_coeffs, CC_ARRAY_LEN(valid_rns_coeffs));
        is(has_ternary_coeffs, true, "ccpolyzp_po2cyc_random_ternary_ws doesn't have ternary coefficients");

        bool has_zero = ccpolyzp_po2cyc_has_zero_rns((ccpolyzp_po2cyc_const_t)poly_coeff);
        is(has_zero, true, "ccpolyzp_po2cyc_random_ternary_ws doesn't have any 0 coefficients");

        CC_FREE_BP_WS(ws, bp);
    }
    // random ternary with nonzero seed
    {
        CC_DECL_BP_WS(ws, bp);

        struct ccpolyzp_po2cyc_block_rng_state *block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
        struct ccrng_state *rng = (struct ccrng_state *)block_rng;

        byteBuffer seed = hexStringToBytes("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        is(seed->len, 32, "seed length != 32");
        is(ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed->bytes),
           CCERR_OK,
           "Error initializing block_rng");
        free(seed);

        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        is(ccpolyzp_po2cyc_all_zero((ccpolyzp_po2cyc_t)poly_coeff), true, "ccpolyzp_po2cyc_coeff_init_helper non-zero");
        is(ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff, rng),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_ternary_ws != CCERR_OK");
        bool has_ternary_coeffs = ccpolyzp_po2cyc_coeff_rns_in(poly_coeff, valid_rns_coeffs, CC_ARRAY_LEN(valid_rns_coeffs));
        is(has_ternary_coeffs, true, "ccpolyzp_po2cyc_random_ternary_ws doesn't have ternary coefficients");

        bool has_zero = ccpolyzp_po2cyc_has_zero_rns((ccpolyzp_po2cyc_const_t)poly_coeff);
        is(has_zero, true, "ccpolyzp_po2cyc_random_ternary_ws doesn't have any 0 coefficients");

        CC_FREE_BP_WS(ws, bp);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_random_cbd_kat(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 2 };
    ccrns_int moduli[] = { 23, 29 };
    ccrns_int zero_data[8] = { 0 };
    struct ccpolyzp_po2cyc_block_rng_state *block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
    struct ccrng_state *rng = (struct ccrng_state *)block_rng;

    // random cbd with nonzero seed
    {
        byteBuffer seed = hexStringToBytes("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        ccrns_int expected0[] = { 1, 20, 18, 2, 1, 26, 24, 2 };
        ccrns_int expected1[] = { 0, 0, 21, 18, 0, 0, 27, 24 };
        ccrns_int expected2[] = { 2, 22, 19, 21, 2, 28, 25, 27 };
        ccpolyzp_po2cyc_coeff_t poly = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, zero_data);
        ccpolyzp_po2cyc_coeff_t poly_expected0 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected0);
        ccpolyzp_po2cyc_coeff_t poly_expected1 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected1);
        ccpolyzp_po2cyc_coeff_t poly_expected2 = ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, expected2);

        is(seed->len, 32, "seed length != 32");
        is(ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed->bytes),
           CCERR_OK,
           "Error initializing block_rng");
        free(seed);
        is(ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly, rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_cbd != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected0), true, "ccpolyzp_po2cyc_random_cbd nonzero seed != expected0");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly, rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2);
        }

        is(ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly, rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_cbd != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected1), true, "ccpolyzp_po2cyc_random_cbd nonzero seed != expected1");

        for (int i = 0; i < 1000; ++i) {
            ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly, rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2);
        }

        is(ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly, rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_cbd != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly, poly_expected2), true, "ccpolyzp_po2cyc_random_cbd nonzero seed != expected2");
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_random_cbd_properties(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccpolyzp_po2cyc_dims dims = { .degree = 8192, .nmoduli = 2 };
    ccrns_int moduli[] = { (1ULL << 55) - 311295, (1ULL << 55) - 1392639 };
    // Samples should fall within 7.8125σ, where σ = 3.2, so samples should be in [-25, 25].
    // Valid coefficients: { 0, 1, -1 % moduli[0], -1 % moduli[1], 2, ... , 25, -25 % moduli[0], -25 % moduli[1] }
    ccrns_int valid_cbd_coeffs[76];
    valid_cbd_coeffs[0] = 0;
    for (ccrns_int i = 1; i <= 25; ++i) {
        valid_cbd_coeffs[i * 3 - 2] = i;
        valid_cbd_coeffs[i * 3 - 1] = ccpolyzp_po2cyc_scalar_negate_mod(i, moduli[0]);
        valid_cbd_coeffs[i * 3] = ccpolyzp_po2cyc_scalar_negate_mod(i, moduli[1]);
    }

    // random cbd has valid cbd coefficients, has at least one zero coefficient, has correct variance.
    {
        CC_DECL_BP_WS(ws, bp);

        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        is(ccpolyzp_po2cyc_all_zero((ccpolyzp_po2cyc_t)poly_coeff), true, "ccpolyzp_po2cyc_coeff_init_helper non-zero");
        is(ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff, global_test_rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_cbd_ws != CCERR_OK");
        bool has_cbd_coeffs = ccpolyzp_po2cyc_coeff_rns_in(poly_coeff, valid_cbd_coeffs, CC_ARRAY_LEN(valid_cbd_coeffs));
        is(has_cbd_coeffs, true, "ccpolyzp_po2cyc_random_cbd_ws doesn't have valid cbd coefficients");

        bool has_zero = ccpolyzp_po2cyc_has_zero_rns((ccpolyzp_po2cyc_const_t)poly_coeff);
        is(has_zero, true, "ccpolyzp_po2cyc_random_cbd_ws doesn't have any 0 coefficients");

        float variance = ccpolyzp_po2cyc_compute_variance((ccpolyzp_po2cyc_const_t)poly_coeff);
        // σ = 3.2, variance = σ^2 = 10.24. Make sure actual variance of samples is within expected bounds.
        ok(variance < 15, "variance is higher than expected, should be close to 10.24");
        ok(variance > 5, "variance is lower than expected, should be close to 10.24");

        CC_FREE_BP_WS(ws, bp);
    }
    // random cbd with nonzero seed has valid cbd coefficients, has at least one zero coefficient, has correct variance.
    {
        CC_DECL_BP_WS(ws, bp);

        struct ccpolyzp_po2cyc_block_rng_state *block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
        struct ccrng_state *rng = (struct ccrng_state *)block_rng;

        byteBuffer seed = hexStringToBytes("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        is(seed->len, 32, "seed length != 32");
        is(ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed->bytes),
           CCERR_OK,
           "Error initializing block_rng");
        free(seed);

        ccpolyzp_po2cyc_coeff_t poly_coeff = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
        is(ccpolyzp_po2cyc_all_zero((ccpolyzp_po2cyc_t)poly_coeff), true, "ccpolyzp_po2cyc_coeff_init_helper non-zero");
        is(ccpolyzp_po2cyc_random_cbd_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff, rng, CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2),
           CCERR_OK,
           "ccpolyzp_po2cyc_random_cbd_ws != CCERR_OK");
        bool has_cbd_coeffs = ccpolyzp_po2cyc_coeff_rns_in(poly_coeff, valid_cbd_coeffs, CC_ARRAY_LEN(valid_cbd_coeffs));
        is(has_cbd_coeffs, true, "ccpolyzp_po2cyc_random_cbd_ws doesn't have valid cbd coefficients");

        bool has_zero = ccpolyzp_po2cyc_has_zero_rns((ccpolyzp_po2cyc_const_t)poly_coeff);
        is(has_zero, true, "ccpolyzp_po2cyc_random_cbd_ws doesn't have any 0 coefficients");

        float variance = ccpolyzp_po2cyc_compute_variance((ccpolyzp_po2cyc_const_t)poly_coeff);
        // σ = 3.2, variance = σ^2 = 10.24. Make sure actual variance of samples is within expected bounds.
        ok(variance < 10.3, "variance is higher than expected");
        ok(variance > 10.2, "variance is lower than expected");

        CC_FREE_BP_WS(ws, bp);
    }
    CC_FREE_WORKSPACE(ws);
}

void test_ccpolyzp_po2cyc_random(void)
{
    test_ccpolyzp_po2cyc_random_rng_workspace();
    test_ccpolyzp_po2cyc_random_uniform_kat();
    test_ccpolyzp_po2cyc_random_uniform_properties();
    test_ccpolyzp_po2cyc_random_ternary_kat();
    test_ccpolyzp_po2cyc_random_ternary_properties();
    test_ccpolyzp_po2cyc_random_cbd_kat();
    test_ccpolyzp_po2cyc_random_cbd_properties();
}
