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
#include "ccpolyzp_po2cyc_scalar.h"
#include <corecrypto/ccrng.h>
#include "testmore.h"
#include "testccnBuffer.h"

static void test_ccpolyzp_po2cyc_ccrns_int(void)
{
    cc_static_assert(sizeof(ccrns_int) == CCRNS_INT_NBYTES, "sizeof(ccrns_int) != CCRNS_INT_NBYTES");
    cc_static_assert(CCRNS_INT_NBITS == 8 * CCRNS_INT_NBYTES, "CCRNS_INT_NBITS != 8 * CCRNS_INT_NBYTES");
    cc_static_assert(CCPOLYZP_PO2CYC_MAX_MODULUS < CCRNS_INT_MAX, "CCPOLYZP_PO2CYC_MAX_MODULUS >= CCRNS_INT_MAX");
}

static void test_ccpolyzp_po2cyc_scalar_cond_sub(void)
{
    is(ccpolyzp_po2cyc_scalar_cond_sub(0, 2), 0, "ccpolyzp_po2cyc_scalar_cond_sub(0, 2) != 0");
    is(ccpolyzp_po2cyc_scalar_cond_sub(1, 2), 1, "ccpolyzp_po2cyc_scalar_cond_sub(1, 2) != 1");
    is(ccpolyzp_po2cyc_scalar_cond_sub(2, 2), 0, "ccpolyzp_po2cyc_scalar_cond_sub(2, 2) != 0");

    is(ccpolyzp_po2cyc_scalar_cond_sub(5, 7), 5, "ccpolyzp_po2cyc_scalar_cond_sub(5, 7) != 5");
    is(ccpolyzp_po2cyc_scalar_cond_sub(13, 7), 6, "ccpolyzp_po2cyc_scalar_cond_sub(13, 7) != 6");

    is(ccpolyzp_po2cyc_scalar_cond_sub(UINT64_C(1) << 62, (UINT64_C(1) << 62) + 1),
       UINT64_C(1) << 62,
       "ccpolyzp_po2cyc_scalar_cond_sub(2^62, 2^62 + 1) != 2^62");
    is(ccpolyzp_po2cyc_scalar_cond_sub(UINT64_C(1) << 63, (UINT64_C(1) << 62) + 1),
       (UINT64_C(1) << 62) - 1,
       "ccpolyzp_po2cyc_scalar_cond_sub(2^63, 2^62 + 1) != 2^62 - 1");
}

static void test_ccpolyzp_po2cyc_scalar_add_mod(void)
{
    is(ccpolyzp_po2cyc_scalar_add_mod(1, 0, 2), 1, "ccpolyzp_po2cyc_scalar_add_mod(1, 0, 2) != 1");
    is(ccpolyzp_po2cyc_scalar_add_mod(0, 1, 2), 1, "ccpolyzp_po2cyc_scalar_add_mod(0, 1, 2) != 1");
    is(ccpolyzp_po2cyc_scalar_add_mod(1, 1, 2), 0, "ccpolyzp_po2cyc_scalar_add_mod(1, 1, 2) != 0");
    is(ccpolyzp_po2cyc_scalar_add_mod(5, 6, 7), 4, "ccpolyzp_po2cyc_scalar_add_mod(5, 6, 7) != 4");

    is(ccpolyzp_po2cyc_scalar_add_mod(UINT64_C(1) << 62, (UINT64_C(1) << 62) + 3, (UINT64_C(1) << 62) + 4),
       (UINT64_C(1) << 62) - 1,
       "ccpolyzp_po2cyc_scalar_add_mod(2^62, 2^62 + 3, 2^62 + 4) != 2^62 - 1");
    is(ccpolyzp_po2cyc_scalar_add_mod((UINT64_C(1) << 62) + 1, 2, (UINT64_C(1) << 62) + 4),
       (UINT64_C(1) << 62) + 3,
       "ccpolyzp_po2cyc_scalar_add_mod(2^62 + 1, 2, 2^62 + 4) != 2^62 + 3");
}

static void test_ccpolyzp_po2cyc_scalar_sub_mod(void)
{
    is(ccpolyzp_po2cyc_scalar_sub_mod(1, 0, 2), 1, "ccpolyzp_po2cyc_scalar_sub_mod(1, 0, 2) != 1");
    is(ccpolyzp_po2cyc_scalar_sub_mod(0, 1, 2), 1, "ccpolyzp_po2cyc_scalar_sub_mod(0, 1, 2) != 1");
    is(ccpolyzp_po2cyc_scalar_sub_mod(1, 1, 2), 0, "ccpolyzp_po2cyc_scalar_sub_mod(1, 1, 2) != 0");
    is(ccpolyzp_po2cyc_scalar_sub_mod(5, 6, 7), 6, "ccpolyzp_po2cyc_scalar_sub_mod(5, 6, 7) != 6");
    is(ccpolyzp_po2cyc_scalar_sub_mod(6, 5, 7), 1, "ccpolyzp_po2cyc_scalar_sub_mod(6, 5, 7) != 1");

    is(ccpolyzp_po2cyc_scalar_sub_mod(UINT64_C(1) << 62, (UINT64_C(1) << 62) + 3, (UINT64_C(1) << 62) + 4),
       (UINT64_C(1) << 62) + 1,
       "ccpolyzp_po2cyc_scalar_sub_mod(2^62, 2^62 + 3, 2^62 + 4) != 2^62 + 1");
    is(ccpolyzp_po2cyc_scalar_sub_mod((UINT64_C(1) << 62) + 1, 2, (UINT64_C(1) << 62) + 4),
       (UINT64_C(1) << 62) - 1,
       "ccpolyzp_po2cyc_scalar_sub_mod(2^62 + 1, 2, 2^62 + 4) != 2^62 - 1");
}

static void test_ccpolyzp_po2cyc_scalar_negate_mod(void)
{
    is(ccpolyzp_po2cyc_scalar_negate_mod(0, 1), 0, "ccpolyzp_po2cyc_scalar_negate_mod(0, 1) != 0");
    is(ccpolyzp_po2cyc_scalar_negate_mod(0, 2), 0, "ccpolyzp_po2cyc_scalar_negate_mod(0, 2) != 0");
    is(ccpolyzp_po2cyc_scalar_negate_mod(1, 2), 1, "ccpolyzp_po2cyc_scalar_negate_mod(1, 2) != 1");

    is(ccpolyzp_po2cyc_scalar_negate_mod(0, (UINT64_C(1) << 63) + 1), 0, "ccpolyzp_po2cyc_scalar_negate_mod(0, 2^63 + 1) != 0");
    is(ccpolyzp_po2cyc_scalar_negate_mod(1, (UINT64_C(1) << 63) + 1),
       UINT64_C(1) << 63,
       "ccpolyzp_po2cyc_scalar_negate_mod(1, (2^63) + 1) != 2^63");
    is(ccpolyzp_po2cyc_scalar_negate_mod(2, (UINT64_C(1) << 63) + 1),
       (UINT64_C(1) << 63) - 1,
       "ccpolyzp_po2cyc_scalar_negate_mod(2, 2^63 + 1) != 2^63 - 1");
    is(ccpolyzp_po2cyc_scalar_negate_mod((UINT64_C(1) << 63) - 2, (UINT64_C(1) << 63) + 1),
       3,
       "ccpolyzp_po2cyc_scalar_negate_mod(2^63, 2^63 + 1) != 3");
    is(ccpolyzp_po2cyc_scalar_negate_mod((UINT64_C(1) << 63) - 1, (UINT64_C(1) << 63) + 1),
       2,
       "ccpolyzp_po2cyc_scalar_negate_mod(2^63, 2^63 + 1) != 2");
    is(ccpolyzp_po2cyc_scalar_negate_mod(UINT64_C(1) << 63, (UINT64_C(1) << 63) + 1),
       1,
       "ccpolyzp_po2cyc_scalar_negate_mod(2^63 - 1, 2^63 + 1) != 2");
}

static void test_ccrns_modulus_init_ws(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    struct ccrns_modulus_init_kat_vector {
        /// modulus
        ccrns_int p;
        /// mod1_factor
        ccrns_int mod1_factor;
        /// mod2_factor
        ccrns_int mod2_factor[2];
        /// hex string for div_a
        const char *div_a;
    };
    const struct ccrns_modulus_init_kat_vector kat_vectors[] = {
        { .p = 2,
          .mod1_factor = UINT64_C(9223372036854775808),
          .mod2_factor = { 0, UINT64_C(9223372036854775808) },
          .div_a = "0" },
        { .p = (UINT64_C(1) << 32) + 1,
          .mod1_factor = UINT64_C(4294967295),
          .mod2_factor = { UINT64_C(4294967295), UINT64_C(4294967295) },
          .div_a = "fffffffe00000001fffffffe00000002" },
        { .p = (UINT64_C(1) << 63) - 1,
          .mod1_factor = UINT64_C(2),
          .mod2_factor = { UINT64_C(4), UINT64_C(2) },
          .div_a = "20000000000000005" },
    };

    for (uint32_t i = 0; i < CC_ARRAY_LEN(kat_vectors); ++i) {
        struct ccrns_modulus_init_kat_vector kat = kat_vectors[i];

        struct ccrns_modulus modulus;
        is(ccrns_modulus_init_ws(ws, &modulus, kat.p), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
        is(modulus.value, kat.p, "test_ccrns_modulus_init_ws wrong value");
        is(modulus.mod1_factor, kat.mod1_factor, "test_ccrns_modulus_init_ws wrong mod1_factor");
        is(modulus.mod2_factor[0], kat.mod2_factor[0], "test_ccrns_modulus_init_ws wrong mod2_factor low");
        is(modulus.mod2_factor[1], kat.mod2_factor[1], "test_ccrns_modulus_init_ws wrong mod2_factor hi");

        ccnBuffer div_a_buffer = hexStringToCcn(kat.div_a);
        cc_unit div_a_expected[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccn_setn(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, div_a_expected, div_a_buffer->len, div_a_buffer->units);
        ok_ccn_cmp(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                   modulus.div_a,
                   div_a_expected,
                   "test_ccrns_modulus_init_ws wrong div_a factor for p=%" PRIu64,
                   (uint64_t)kat.p);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_scalar_mod1(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    {
        struct ccrns_modulus p;
        is(ccrns_modulus_init_ws(ws, &p, 2), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
        is(ccpolyzp_po2cyc_scalar_mod1(0, &p), 0, "ccpolyzp_po2cyc_scalar_mod1(0, 2) != 0");
        is(ccpolyzp_po2cyc_scalar_mod1(1, &p), 1, "ccpolyzp_po2cyc_scalar_mod1(1, 2) != 1");
    }
    {
        struct ccrns_modulus p;
        is(ccrns_modulus_init_ws(ws, &p, (1ULL << 32) + 1), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
        is(ccpolyzp_po2cyc_scalar_mod1((1ULL << 33) + 1, &p),
           ((1ULL << 33) + 1) % p.value,
           "ccpolyzp_po2cyc_scalar_mod1(2^33 + 1, 2^32 + 1) != 2^32");
        is(ccpolyzp_po2cyc_scalar_mod1(1ULL << 60, &p),
           (1ULL << 60) % p.value,
           "ccpolyzp_po2cyc_scalar_mod1(2^33 + 1, 2^32 + 1) != 4026531841");
    }

    for (int i = 0; i < 100; ++i) {
        struct ccrns_modulus p;
        is(ccrns_modulus_init_ws(ws, &p, rns_int_uniform(1ULL << 63)), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
        ccrns_int x = rns_int_uniform(p.value);
        is(ccpolyzp_po2cyc_scalar_mod1(x, &p),
           x % p.value,
           "ccpolyzp_po2cyc_scalar_mod1(%" PRIu64 ", %" PRIu64 ") != %" PRIu64,
           x,
           p.value,
           (x % p.value));
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_scalar_mod2(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    // even moduli
    {
        /// KAT for scalar 128-bit modular reduction
        struct ccpolyzp_po2cyc_scalar_mod2_vector {
            /// 128-bit hex string
            const char *x;
            /// modulus
            ccrns_int p;
            /// expected x % p
            ccrns_int x_mod_p;
        };

        const struct ccpolyzp_po2cyc_scalar_mod2_vector mod2_test_vectors[] = {
            { .x = "82147ae6c1c269a71c694549c4408ab5", .p = (1ULL << 62), .x_mod_p = 2047243688744094389ULL },
            { .x = "9fac3762a6252e908ac36460e19af306", .p = (1ULL << 62), .x_mod_p = 775573928102523654ULL },
            { .x = "0deb202c0c26faed49be73296d0e875a", .p = (1ULL << 62), .x_mod_p = 702125213676898138ULL },
            { .x = "10000000000000000", .p = (1ULL << 62), .x_mod_p = 0 },
            { .x = "10000000000000001", .p = (1ULL << 62), .x_mod_p = 1 },
            { .x = "82147ae6c1c269a71c694549c4408ab5", .p = (1 << 30) + (1 << 16) + 72, .x_mod_p = 439962925 },
            { .x = "9fac3762a6252e908ac36460e19af306", .p = (1 << 30) + (1 << 16) + 72, .x_mod_p = 479571822 },
            { .x = "0deb202c0c26faed49be73296d0e875a", .p = (1 << 30) + (1 << 16) + 72, .x_mod_p = 668444858 },
        };
        for (uint32_t i = 0; i < CC_ARRAY_LEN(mod2_test_vectors); ++i) {
            struct ccpolyzp_po2cyc_scalar_mod2_vector kat = mod2_test_vectors[i];
            struct ccrns_modulus p;
            is(ccrns_modulus_init_ws(ws, &p, kat.p), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
            ccnBuffer x_hex = hexStringToCcn(kat.x);
            {
                ccrns_int x_mod_p = ccpolyzp_po2cyc_scalar_mod2(x_hex->units, &p);
                is(x_mod_p, kat.x_mod_p, "0x%s mod %" PRIu64 " != %" PRIu64, kat.x, kat.p, kat.x_mod_p);
            }
            {
                ccrns_int x_mod_p = ccpolyzp_po2cyc_scalar_mod2_lazy(x_hex->units, &p);
                is(x_mod_p < 2 * kat.p && x_mod_p % kat.p == kat.x_mod_p,
                   true,
                   "0x%s mod %" PRIu64 " != %" PRIu64,
                   kat.x,
                   kat.p,
                   kat.x_mod_p);
            }
        }
    }
    // odd moduli - compare against cczp
    {
        for (int i = 0; i < 100; ++i) {
            ccrns_int modulus = rns_int_uniform(1ULL << 63);
            // cczp supports only odd moduli
            if (modulus % 2 == 0) {
                modulus++;
            }
            cc_unit x[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            is(ccrng_generate(global_test_rng, sizeof(x), x), CCERR_OK, "ccrng_generate != CCERR_OK");

            struct ccrns_modulus ccrns_p;
            is(ccrns_modulus_init_ws(ws, &ccrns_p, modulus), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
            cczp_t cczp_p = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF));
            is(ccpolyzp_po2cyc_modulus_to_cczp_ws(ws, cczp_p, ccrns_p.value),
               CCERR_OK,
               "ccpolyzp_po2cyc_modulus_to_cczp_ws != CCERR_OK");
            cc_unit x_mod_cczp[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            cczp_mod_ws(ws, cczp_p, x_mod_cczp, x);
            ccrns_int x_mod_p_exp = ccpolyzp_po2cyc_units_to_rns_int(x_mod_cczp);
            {
                ccrns_int x_mod_p = ccpolyzp_po2cyc_scalar_mod2(x, &ccrns_p);
                is(x_mod_p,
                   x_mod_p_exp,
                   "test_ccpolyzp_po2cyc_scalar_mod2 mod %" PRIu64 " != %" PRIu64,
                   (uint64_t)x_mod_p,
                   (uint64_t)x_mod_p_exp);
            }
            {
                ccrns_int x_mod_p = ccpolyzp_po2cyc_scalar_mod2_lazy(x, &ccrns_p);
                is(x_mod_p < 2 * modulus && x_mod_p % modulus == x_mod_p_exp,
                   true,
                   "ccpolyzp_po2cyc_scalar_mod2_lazy mod %" PRIu64 " != %" PRIu64,
                   (uint64_t)x_mod_p,
                   (uint64_t)x_mod_p_exp);
            }
        }
    }
    CC_FREE_WORKSPACE(ws);
}

/// @brief Computes (x * y) % p using cczp_mul_ws
/// @param ws Workspace
/// @param x Multiplicand
/// @param y Multiplicand
/// @param p Modulus
/// @return (x * y) % p
static ccrns_int cczp_mul_mod(cc_ws_t ws, ccrns_int x, ccrns_int y, ccrns_int p)
{
    cczp_t cczp_p = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF));
    is(ccpolyzp_po2cyc_modulus_to_cczp_ws(ws, cczp_p, p), CCERR_OK, "ccpolyzp_po2cyc_modulus_to_cczp_ws != CCERR_OK");
    cc_unit x_y_mod_cczp_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit x_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit y_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(x_units, x);
    ccpolyzp_po2cyc_rns_int_to_units(y_units, y);
    cczp_mul_ws(ws, cczp_p, x_y_mod_cczp_units, x_units, y_units);
    return ccpolyzp_po2cyc_units_to_rns_int(x_y_mod_cczp_units);
}

// KAT for scalar modular multiplication
struct ccpolyzp_po2cyc_scalar_mul_mod_vector {
    ccrns_int x;
    ccrns_int y;
    ccrns_int p;
    ccrns_int x_y_mod_p;
};
const struct ccpolyzp_po2cyc_scalar_mul_mod_vector mul_mod_test_vectors[] = {
    { .x = 0, .y = 789101112, .p = 1ULL << 62, .x_y_mod_p = 0 },
    { .x = 1, .y = 789101112, .p = 1ULL << 62, .x_y_mod_p = 789101112 },
    { .x = 123456, .y = 789101112, .p = 1ULL << 62, .x_y_mod_p = 97419266883072ULL },
    { .x = (1ULL << 62) - 1, .y = (1ULL << 62) - 1, .p = 1ULL << 62, .x_y_mod_p = 1 },
    { .x = 0, .y = 789101112, .p = (1 << 30) + (1 << 16) + 72, .x_y_mod_p = 0 },
    { .x = (1 << 30) + (1 << 16) + 71, .y = (1 << 30) + (1 << 16) + 71, .p = (1 << 30) + (1 << 16) + 72, .x_y_mod_p = 1 },
};

static void test_ccpolyzp_po2cyc_scalar_mul_mod(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    for (uint32_t i = 0; i < CC_ARRAY_LEN(mul_mod_test_vectors); ++i) {
        struct ccpolyzp_po2cyc_scalar_mul_mod_vector kat = mul_mod_test_vectors[i];
        struct ccrns_modulus p;
        is(ccrns_modulus_init_ws(ws, &p, kat.p), CCERR_OK, "ccrns_modulus_init != CCERR_OK");

        {
            ccrns_int x_y_mod_p = ccpolyzp_po2cyc_scalar_mul_mod(kat.x, kat.y, &p);
            is(x_y_mod_p,
               kat.x_y_mod_p,
               "%" PRIu64 " * %" PRIu64 " mod %" PRIu64 " != %" PRIu64,
               (uint64_t)kat.x,
               (uint64_t)kat.y,
               (uint64_t)(p.value),
               (uint64_t)kat.x_y_mod_p);
        }
        {
            ccrns_int x_y_mod_p_lazy = ccpolyzp_po2cyc_scalar_mul_mod_lazy(kat.x, kat.y, &p);
            is((x_y_mod_p_lazy < 2 * p.value) && (x_y_mod_p_lazy % p.value == kat.x_y_mod_p),
               true,
               "%" PRIu64 " * %" PRIu64 " mod %" PRIu64 " != %" PRIu64,
               (uint64_t)kat.x,
               (uint64_t)kat.y,
               (uint64_t)(p.value),
               (uint64_t)kat.x_y_mod_p);
        }
    }
    // odd moduli - compare against cczp
    {
        for (int i = 0; i < 100; ++i) {
            ccrns_int modulus = 2 + rns_int_uniform(1ULL << CC_MIN_EVAL(i, 63));
            // cczp supports only odd moduli
            if (modulus % 2 == 0) {
                modulus++;
            }
            ccrns_int x = rns_int_uniform(modulus);
            ccrns_int y = rns_int_uniform(modulus);

            struct ccrns_modulus ccrns_p;
            is(ccrns_modulus_init_ws(ws, &ccrns_p, modulus), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
            ccrns_int x_y_mod_cczp = cczp_mul_mod(ws, x, y, modulus);

            {
                ccrns_int x_y_mod_p = ccpolyzp_po2cyc_scalar_mul_mod(x, y, &ccrns_p);
                is(x_y_mod_p,
                   x_y_mod_cczp,
                   "test_ccpolyzp_po2cyc_scalar_mul_mod(%" PRIu64 ", %" PRIu64 " mod %" PRIu64 " != %" PRIu64,
                   (uint64_t)x,
                   (uint64_t)y,
                   (uint64_t)modulus,
                   (uint64_t)x_y_mod_cczp);
            }
            {
                ccrns_int x_y_mod_p_lazy = ccpolyzp_po2cyc_scalar_mul_mod_lazy(x, y, &ccrns_p);
                is((x_y_mod_p_lazy < 2 * modulus) && (x_y_mod_p_lazy % modulus == x_y_mod_cczp),
                   true,
                   "test_ccpolyzp_po2cyc_scalar_mul_mod(%" PRIu64 ", %" PRIu64 " mod %" PRIu64 " != %" PRIu64,
                   (uint64_t)x,
                   (uint64_t)y,
                   (uint64_t)modulus,
                   (uint64_t)x_y_mod_cczp);
            }
        }
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_scalar_shoup_mul_mod(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    for (uint32_t i = 0; i < CC_ARRAY_LEN(mul_mod_test_vectors); ++i) {
        struct ccpolyzp_po2cyc_scalar_mul_mod_vector kat = mul_mod_test_vectors[i];
        struct ccrns_mul_modulus p;
        is(ccrns_mul_modulus_init_ws(ws, &p, kat.p, kat.y), CCERR_OK, "ccrns_mul_modulus_init != CCERR_OK");

        {
            ccrns_int x_y_mod_p = ccpolyzp_po2cyc_scalar_shoup_mul_mod(kat.x, &p);
            is(x_y_mod_p,
               kat.x_y_mod_p,
               "test_ccpolyzp_po2cyc_scalar_shoup_mul_mod(%" PRIu64 ", %" PRIu64 ") mod %" PRIu64 " != %" PRIu64,
               (uint64_t)kat.x,
               (uint64_t)kat.y,
               (uint64_t)(p.modulus),
               (uint64_t)kat.x_y_mod_p);
        }
        {
            ccrns_int x_y_mod_p = ccpolyzp_po2cyc_scalar_shoup_mul_mod_lazy(kat.x, &p);
            is((x_y_mod_p < 2 * kat.p) && (x_y_mod_p % kat.p == kat.x_y_mod_p),
               true,
               "test_ccpolyzp_po2cyc_scalar_shoup_mul_mod_lazy(%" PRIu64 ", %" PRIu64 ") mod %" PRIu64 " != %" PRIu64,
               (uint64_t)kat.x,
               (uint64_t)kat.y,
               (uint64_t)(p.modulus),
               (uint64_t)kat.x_y_mod_p);
        }
    }
    // odd moduli - compare against cczp
    {
        for (int i = 0; i < 100; ++i) {
            ccrns_int modulus = 2 + rns_int_uniform(1ULL << (i % 63));
            // cczp supports only odd moduli
            if (modulus % 2 == 0) {
                modulus++;
            }
            ccrns_int x = rns_int_uniform(modulus);
            ccrns_int y = rns_int_uniform(modulus);

            struct ccrns_mul_modulus ccrns_p;
            is(ccrns_mul_modulus_init_ws(ws, &ccrns_p, modulus, y), CCERR_OK, "ccrns_modulus_init != CCERR_OK");
            ccrns_int x_y_mod_p = ccpolyzp_po2cyc_scalar_shoup_mul_mod(x, &ccrns_p);
            ccrns_int x_y_mod_cczp = cczp_mul_mod(ws, x, y, modulus);
            is(x_y_mod_p,
               x_y_mod_cczp,
               "test_ccpolyzp_po2cyc_scalar_shoup_mul_mod(%" PRIu64 ", %" PRIu64 ") mod %" PRIu64 " != %" PRIu64,
               (uint64_t)x,
               (uint64_t)y,
               (uint64_t)modulus,
               (uint64_t)x_y_mod_cczp);
        }
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_scalar_divmod_ws(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // KAT - arbitrary values
    {
        struct ccpolyzp_po2cyc_scalar_divmod_kat {
            /// hex string for 128-bit divisor
            const char *x;
            /// modulus
            ccrns_int p;
            /// expected hex string of floor(x / p)
            const char *floor_x_div_p;
        };
        const struct ccpolyzp_po2cyc_scalar_divmod_kat scalar_div_mod_vectors[] = {
            { .x = "fffffffe00000001fffffffe00000002",
              .p = (UINT64_C(1) << 32) + 1,
              .floor_x_div_p = "fffffffd00000004fffffff9" },
            { .x = "908692722e5567a7183588c79de540b8", .p = UINT64_C(30212015965), .floor_x_div_p = "148bc00d0501cc527799d772" }
        };

        for (uint32_t i = 0; i < CC_ARRAY_LEN(scalar_div_mod_vectors); ++i) {
            struct ccpolyzp_po2cyc_scalar_divmod_kat kat = scalar_div_mod_vectors[i];
            struct ccrns_modulus p;
            is(ccrns_modulus_init_ws(ws, &p, kat.p), CCERR_OK, "ccrns_modulus_init != CCERR_OK");

            ccnBuffer x_buffer = hexStringToCcn(kat.x);
            ccnBuffer expected_buffer = hexStringToCcn(kat.floor_x_div_p);

            cc_unit r[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            ccpolyzp_po2cyc_scalar_divmod_ws(ws, r, x_buffer->units, &p);

            cc_unit expected_units[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            ccn_setn(2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, expected_units, expected_buffer->len, expected_buffer->units);
            ok_ccn_cmp(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                       r,
                       expected_units,
                       "ccpolyzp_po2cyc_scalar_divmod_ws(0x%s), %" PRIu64 ") incorrect",
                       kat.x,
                       (uint64_t)kat.p);
        }
    }

    // Random values - compare against ccn_divmod_ws
    for (int i = 0; i < 100; ++i) {
        ccrns_int modulus = 2 + rns_int_uniform(1ULL << CC_MIN_EVAL(i, 63));
        struct ccrns_modulus ccrns_p;
        is(ccrns_modulus_init_ws(ws, &ccrns_p, modulus), CCERR_OK, "ccrns_modulus_init != CCERR_OK");

        cc_unit x[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        is(ccrng_generate(global_test_rng, sizeof(x), x), CCERR_OK, "ccrng_generate != CCERR_OK");

        cc_unit modulus_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccpolyzp_po2cyc_rns_int_to_units(modulus_units, modulus);

        cc_unit expected_units[2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccn_divmod_ws(ws,
                      2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                      x,
                      2 * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                      expected_units,
                      CCPOLYZP_PO2CYC_NUNITS_PER_COEFF,
                      NULL,
                      modulus_units);

        cc_unit r[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccpolyzp_po2cyc_scalar_divmod_ws(ws, r, x, &ccrns_p);

        ccrns_int x_lo = ccpolyzp_po2cyc_units_to_rns_int(x);
        ccrns_int x_hi = ccpolyzp_po2cyc_units_to_rns_int(&x[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
        is(ccn_cmp(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, expected_units, r),
           0,
           "ccpolyzp_po2cyc_scalar_divmod_ws(%" PRIu64 ", %" PRIu64 "), %" PRIu64 " incorrect",
           (uint64_t)x_lo,
           (uint64_t)x_hi,
           (uint64_t)modulus);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_log2(void)
{
    // ccpolyzp_po2cyc_log2_uint32
    {
        is(ccpolyzp_po2cyc_log2_uint32(1), 0, "ccpolyzp_po2cyc_log2_uint32(1) != 0");
        is(ccpolyzp_po2cyc_log2_uint32(2), 1, "ccpolyzp_po2cyc_log2_uint32(2) != 1");
        is(ccpolyzp_po2cyc_log2_uint32(3), 1, "ccpolyzp_po2cyc_log2_uint32(3) != 1");
        is(ccpolyzp_po2cyc_log2_uint32(4), 2, "ccpolyzp_po2cyc_log2_uint32(4) != 2");

        for (uint32_t i = 0; i < 32; ++i) {
            is(ccpolyzp_po2cyc_log2_uint32(UINT32_C(1) << i),
               i,
               "ccpolyzp_po2cyc_log2_uint32(%" PRIu32 ") != %" PRIu32,
               UINT32_C(1) << i,
               i);
            if (i > 0) {
                is(ccpolyzp_po2cyc_log2_uint32((UINT32_C(1) << i) - 1),
                   i - 1,
                   "ccpolyzp_po2cyc_log2_uint32(%" PRIu32 ") != %" PRIu32,
                   (UINT32_C(1) << i) - 1,
                   i - 1);
                is(ccpolyzp_po2cyc_log2_uint32((UINT32_C(1) << i) + 1),
                   i,
                   "ccpolyzp_po2cyc_log2_uint32(%" PRIu32 ") != %" PRIu32,
                   (UINT32_C(1) << i) + 1,
                   i);
            }
        }
    }
    // ccpolyzp_po2cyc_log2_uint64
    {
        is(ccpolyzp_po2cyc_log2_uint64(1), 0, "ccpolyzp_po2cyc_log2_uint64(1) != 0");
        is(ccpolyzp_po2cyc_log2_uint64(2), 1, "ccpolyzp_po2cyc_log2_uint64(2) != 1");
        is(ccpolyzp_po2cyc_log2_uint64(3), 1, "ccpolyzp_po2cyc_log2_uint64(3) != 1");
        is(ccpolyzp_po2cyc_log2_uint64(4), 2, "ccpolyzp_po2cyc_log2_uint64(4) != 2");

        for (uint32_t i = 0; i < 64; ++i) {
            is(ccpolyzp_po2cyc_log2_uint64(UINT64_C(1) << i),
               i,
               "ccpolyzp_po2cyc_log2_uint64(%" PRIu64 ") != %" PRIu32,
               UINT64_C(1) << i,
               i);
            if (i > 0) {
                is(ccpolyzp_po2cyc_log2_uint64((UINT64_C(1) << i) - 1),
                   i - 1,
                   "ccpolyzp_po2cyc_log2_uint64(%" PRIu64 ") != %" PRIu32,
                   (UINT64_C(1) << i) - 1,
                   i - 1);
                is(ccpolyzp_po2cyc_log2_uint64((UINT64_C(1) << i) + 1),
                   i,
                   "ccpolyzp_po2cyc_log2_uint64(%" PRIu64 ") != %" PRIu32,
                   (UINT64_C(1) << i) + 1,
                   i);
            }
        }
    }
    // ccpolyzp_po2cyc_ceil_log2_uint64
    {
        is(ccpolyzp_po2cyc_ceil_log2_uint64(1), 0, "ccpolyzp_po2cyc_ceil_log2_uint64(1) != 0");
        is(ccpolyzp_po2cyc_ceil_log2_uint64(2), 1, "ccpolyzp_po2cyc_ceil_log2_uint64(2) != 1");
        is(ccpolyzp_po2cyc_ceil_log2_uint64(3), 2, "ccpolyzp_po2cyc_ceil_log2_uint64(3) != 1");
        is(ccpolyzp_po2cyc_ceil_log2_uint64(4), 2, "ccpolyzp_po2cyc_ceil_log2_uint64(4) != 2");

        for (uint32_t i = 0; i < 64; ++i) {
            is(ccpolyzp_po2cyc_ceil_log2_uint64(UINT64_C(1) << i),
               i,
               "ccpolyzp_po2cyc_ceil_log2_uint64(%" PRIu64 ") != %" PRIu32,
               UINT64_C(1) << i,
               i);
            if (i > 1) {
                is(ccpolyzp_po2cyc_ceil_log2_uint64((UINT64_C(1) << i) - 1),
                   i,
                   "ccpolyzp_po2cyc_ceil_log2_uint64(%" PRIu64 ") != %" PRIu32,
                   (UINT64_C(1) << i) - 1,
                   i);
                is(ccpolyzp_po2cyc_ceil_log2_uint64((UINT64_C(1) << i) + 1),
                   i + 1,
                   "ccpolyzp_po2cyc_ceil_log2_uint64(%" PRIu64 ") != %" PRIu32,
                   (UINT64_C(1) << i) + 1,
                   i + 1);
            }
        }
    }
}

static void test_ccpolyzp_po2cyc_is_power_of_two(void)
{
    // ccpolyzp_po2cyc_is_power_of_two_uint32
    {
        is(ccpolyzp_po2cyc_is_power_of_two_uint32(0), false, "ccpolyzp_po2cyc_is_power_of_two_uint32(0) != false");
        is(ccpolyzp_po2cyc_is_power_of_two_uint32(1), true, "ccpolyzp_po2cyc_is_power_of_two_uint32(1) != true");
        is(ccpolyzp_po2cyc_is_power_of_two_uint32(2), true, "ccpolyzp_po2cyc_is_power_of_two_uint32(2) != true");
        is(ccpolyzp_po2cyc_is_power_of_two_uint32(4), true, "ccpolyzp_po2cyc_is_power_of_two_uint32(4) != true");
        for (uint32_t i = 0; i < 32; ++i) {
            is(ccpolyzp_po2cyc_is_power_of_two_uint32(UINT32_C(1) << i),
               true,
               "ccpolyzp_po2cyc_is_power_of_two_uint32(%" PRIu32 ") != true",
               UINT32_C(1) << i);
            if (i > 1) {
                is(ccpolyzp_po2cyc_is_power_of_two_uint32((UINT32_C(1) << i) - 1),
                   false,
                   "ccpolyzp_po2cyc_is_power_of_two_uint32(%" PRIu32 ") != false",
                   (UINT32_C(1) << i) - 1);
                is(ccpolyzp_po2cyc_is_power_of_two_uint32((UINT32_C(1) << i) + 1),
                   false,
                   "ccpolyzp_po2cyc_is_power_of_two_uint32(%" PRIu32 ") != false",
                   (UINT32_C(1) << i) + 1);
            }
        }
    }
    // ccpolyzp_po2cyc_is_power_of_two_uint64
    {
        is(ccpolyzp_po2cyc_is_power_of_two_uint64(0), false, "ccpolyzp_po2cyc_is_power_of_two_uint64(0) != false");
        is(ccpolyzp_po2cyc_is_power_of_two_uint64(1), true, "ccpolyzp_po2cyc_is_power_of_two_uint64(1) != true");
        is(ccpolyzp_po2cyc_is_power_of_two_uint64(2), true, "ccpolyzp_po2cyc_is_power_of_two_uint64(2) != true");
        is(ccpolyzp_po2cyc_is_power_of_two_uint64(4), true, "ccpolyzp_po2cyc_is_power_of_two_uint64(4) != true");
        for (uint32_t i = 0; i < 64; ++i) {
            is(ccpolyzp_po2cyc_is_power_of_two_uint64(UINT64_C(1) << i),
               true,
               "ccpolyzp_po2cyc_is_power_of_two_uint64(%" PRIu64 ") != true",
               UINT64_C(1) << i);
            if (i > 1) {
                is(ccpolyzp_po2cyc_is_power_of_two_uint64((UINT64_C(1) << i) - 1),
                   false,
                   "ccpolyzp_po2cyc_is_power_of_two_uint64(%" PRIu64 ") != false",
                   (UINT64_C(1) << i) - 1);
                is(ccpolyzp_po2cyc_is_power_of_two_uint64((UINT64_C(1) << i) + 1),
                   false,
                   "ccpolyzp_po2cyc_is_power_of_two_uint64(%" PRIu64 ") != false",
                   (UINT64_C(1) << i) + 1);
            }
        }
    }
}

static void test_ccpolyzp_po2cyc_reverse_bits(void)
{
    {
        is(ccpolyzp_po2cyc_reverse_bits(0, 1), 0, "ccpolyzp_po2cyc_reverse_bits(0, 1) != 0");
    }
    {
        is(ccpolyzp_po2cyc_reverse_bits(0, 32), 0, "ccpolyzp_po2cyc_reverse_bits(0, 32) != 32");
    }
    {
        is(ccpolyzp_po2cyc_reverse_bits(0x80000000, 32), 1, "ccpolyzp_po2cyc_reverse_bits(0x80000000, 32) != 1");
    }
    {
        is(ccpolyzp_po2cyc_reverse_bits(0xFF00F00F, 32),
           0xF00F00FF,
           "ccpolyzp_po2cyc_reverse_bits(0xFF00F00F, 32) != 0xF00F00FF");
    }
    {
        is(ccpolyzp_po2cyc_reverse_bits(0xFF00, 16), 0x00FF, "ccpolyzp_po2cyc_reverse_bits(0xFF00, 16) != 0x00FF");
    }
    {
        is(ccpolyzp_po2cyc_reverse_bits(0b011011010, 9),
           0b010110110,
           "ccpolyzp_po2cyc_reverse_bits(0b011011010, 16) != 0b010110110");
    }
}

static void test_ccpolyzp_po2cyc_rem_to_from_centered(void)
{
    // odd modulus
    {
        is(ccpolyzp_po2cyc_rem_to_centered(0, 7), 0, "rem_to_centered(0, 7) != 0");
        is(ccpolyzp_po2cyc_rem_to_centered(1, 7), 1, "rem_to_centered(1, 7) != 1");
        is(ccpolyzp_po2cyc_rem_to_centered(2, 7), 2, "rem_to_centered(2, 7) != 2");
        is(ccpolyzp_po2cyc_rem_to_centered(3, 7), 3, "rem_to_centered(3, 7) != -4");
        is(ccpolyzp_po2cyc_rem_to_centered(4, 7), -3, "rem_to_centered(4, 7) != -3");
        is(ccpolyzp_po2cyc_rem_to_centered(5, 7), -2, "rem_to_centered(5, 7) != -2");
        is(ccpolyzp_po2cyc_rem_to_centered(6, 7), -1, "rem_to_centered(6, 7) != -1");

        is(ccpolyzp_po2cyc_centered_to_rem(0, 7), 0, "centered_to_rem(0, 7) != 0");
        is(ccpolyzp_po2cyc_centered_to_rem(1, 7), 1, "centered_to_rem(1, 7) != 1");
        is(ccpolyzp_po2cyc_centered_to_rem(2, 7), 2, "centered_to_rem(2, 7) != 2");
        is(ccpolyzp_po2cyc_centered_to_rem(3, 7), 3, "centered_to_rem(3, 7) != 3");
        is(ccpolyzp_po2cyc_centered_to_rem(-3, 7), 4, "centered_to_rem(4, 7) != 4");
        is(ccpolyzp_po2cyc_centered_to_rem(-2, 7), 5, "centered_to_rem(5, 7) != 5");
        is(ccpolyzp_po2cyc_centered_to_rem(-1, 7), 6, "centered_to_rem(6, 7) != 6");
    }
    // even modulus
    {
        is(ccpolyzp_po2cyc_rem_to_centered(0, 8), 0, "rem_to_centered(0, 8) != 0");
        is(ccpolyzp_po2cyc_rem_to_centered(1, 8), 1, "rem_to_centered(1, 8) != 1");
        is(ccpolyzp_po2cyc_rem_to_centered(2, 8), 2, "rem_to_centered(2, 8) != 2");
        is(ccpolyzp_po2cyc_rem_to_centered(3, 8), 3, "rem_to_centered(3, 8) != 3");
        is(ccpolyzp_po2cyc_rem_to_centered(4, 8), -4, "rem_to_centered(4, 8) != -4");
        is(ccpolyzp_po2cyc_rem_to_centered(5, 8), -3, "rem_to_centered(5, 8) != -3");
        is(ccpolyzp_po2cyc_rem_to_centered(6, 8), -2, "rem_to_centered(6, 8) != -2");
        is(ccpolyzp_po2cyc_rem_to_centered(7, 8), -1, "rem_to_centered(7, 8) != -1");

        is(ccpolyzp_po2cyc_centered_to_rem(0, 8), 0, "centered_to_rem(0, 8) != 0");
        is(ccpolyzp_po2cyc_centered_to_rem(1, 8), 1, "centered_to_rem(1, 8) != 1");
        is(ccpolyzp_po2cyc_centered_to_rem(2, 8), 2, "centered_to_rem(2, 8) != 2");
        is(ccpolyzp_po2cyc_centered_to_rem(3, 8), 3, "centered_to_rem(3, 8) != 3");
        is(ccpolyzp_po2cyc_centered_to_rem(-4, 8), 4, "centered_to_rem(-4, 8) != 4");
        is(ccpolyzp_po2cyc_centered_to_rem(-3, 8), 5, "centered_to_rem(-3, 8) != 5");
        is(ccpolyzp_po2cyc_centered_to_rem(-2, 8), 6, "centered_to_rem(-2, 8) != 6");
        is(ccpolyzp_po2cyc_centered_to_rem(-1, 8), 7, "centered_to_rem(-1, 8) != 7");
    }
}

void test_ccpolyzp_po2cyc_scalar(void)
{
    test_ccrns_modulus_init_ws();

    // ccrns_int
    test_ccpolyzp_po2cyc_ccrns_int();
    test_ccpolyzp_po2cyc_scalar_cond_sub();
    test_ccpolyzp_po2cyc_scalar_add_mod();
    test_ccpolyzp_po2cyc_scalar_sub_mod();
    test_ccpolyzp_po2cyc_scalar_negate_mod();
    test_ccpolyzp_po2cyc_scalar_mod1();
    test_ccpolyzp_po2cyc_scalar_mod2();
    test_ccpolyzp_po2cyc_scalar_mul_mod();
    test_ccpolyzp_po2cyc_scalar_shoup_mul_mod();

    test_ccpolyzp_po2cyc_log2();
    test_ccpolyzp_po2cyc_is_power_of_two();
    test_ccpolyzp_po2cyc_reverse_bits();
    test_ccpolyzp_po2cyc_rem_to_from_centered();
    test_ccpolyzp_po2cyc_scalar_divmod_ws();
}
