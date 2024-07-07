/* Copyright (c) (2016-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng_sequence.h>
#include <limits.h>
#include "testmore.h"
#include "cczp_internal.h"
#include "cc_debug.h"
#include "ccn_internal.h"
#include "cc_workspaces.h"

static void test_cczp_init(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cczp_decl_n(1, zp);
    CCZP_N(zp) = 1;

    ccn_seti(1, CCZP_PRIME(zp), 0);
    is(cczp_init_ws(ws, zp), CCERR_PARAMETER, "cczp_init() should fail");

    ccn_seti(1, CCZP_PRIME(zp), 1);
    is(cczp_init_ws(ws, zp), CCERR_PARAMETER, "cczp_init() should fail");

    ccn_seti(1, CCZP_PRIME(zp), 2);
    is(cczp_init_ws(ws, zp), CCERR_PARAMETER, "cczp_init() should fail");

    ccn_seti(1, CCZP_PRIME(zp), 3);
    is(cczp_init_ws(ws, zp), CCERR_OK, "cczp_init() failed");

    ccn_seti(1, CCZP_PRIME(zp), 4);
    is(cczp_init_ws(ws, zp), CCERR_PARAMETER, "cczp_init() should fail");

    ccn_seti(1, CCZP_PRIME(zp), 32);
    is(cczp_init_ws(ws, zp), CCERR_PARAMETER, "cczp_init() should fail");

    CC_FREE_WORKSPACE(ws);
}

static const cc_unit p[] = {
    ccn256_32(0xe5a022bd, 0x33109be3, 0x536f9eda, 0x564edabe, 0x9b4ddf1c, 0x157c483c, 0x4caa41fc, 0xccbee49b)
};
static size_t n = ccn_nof(256);

/* negative tests for cczp_power* edge cases */
/* common cases are well covered by higher-level tests (e.g. ccdh, ccrsa, etc.) */
static void test_cczp_power_fns(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cc_unit r[n];
    cc_unit s[n];
    cc_unit t[n];
    cc_unit e[n];
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init_ws(ws, zp), CCERR_OK, "cczp_init() failed");

    ccn_seti(n, s, 2);

    ccn_seti(n, e, 0);
    cczp_power_ws(ws, zp, r, s, 0, e);
    ok(ccn_is_one(n, r), "cczp_power when e = 0");
    cczp_mm_power_ws(ws, zp, r, s, 0, e);
    ok(ccn_is_one(n, r), "cczp_mm_power when e = 0");
    cczp_power_fast_ws(ws, zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_power_fast when e = 0");
    cczp_mm_power_fast_ws(ws, zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_mm_power_fast when e = 0");
    (void)cczp_power_blinded_ws(ws, zp, r, s, 0, e, global_test_rng);
    ok(ccn_is_one(n, r), "cczp_power_blinded_ws when e = 0");

    ccn_seti(n, e, 1);
    cczp_power_ws(ws, zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, s, "cczp_power when e = 1");
    cczp_mm_power_ws(ws, zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, s, "cczp_mm_power when e = 1");
    cczp_power_fast_ws(ws, zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_power_fast when e = 1");
    cczp_mm_power_fast_ws(ws, zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_mm_power_fast when e = 1");
    (void)cczp_power_blinded_ws(ws, zp, r, s, ccn_bitlen(n, e), e, global_test_rng);
    ok_ccn_cmp(n, r, s, "cczp_power_blinded_ws when e = 1");

    ccn_seti(n, e, 2);
    ccn_seti(n, t, 4);
    cczp_power_ws(ws, zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, t, "cczp_power when e = 2");
    cczp_mm_power_ws(ws, zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power when e = 2");
    cczp_power_fast_ws(ws, zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power_fast when e = 2");
    cczp_mm_power_fast_ws(ws, zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power_fast when e = 2");
    (void)cczp_power_blinded_ws(ws, zp, r, s, ccn_bitlen(n, e), e, global_test_rng);
    ok_ccn_cmp(n, r, t, "cczp_power_blinded_ws when e = 2");

    ccn_seti(n, e, 4);
    ccn_seti(n, t, 16);
    cczp_power_ws(ws, zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, t, "cczp_power when e = 4");
    cczp_mm_power_ws(ws, zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power when e = 4");
    cczp_power_fast_ws(ws, zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power_fast when e = 4");
    cczp_mm_power_fast_ws(ws, zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power_fast when e = 4");
    (void)cczp_power_blinded_ws(ws, zp, r, s, ccn_bitlen(n, e), e, global_test_rng);
    ok_ccn_cmp(n, r, t, "cczp_power_blinded_ws when e = 4");

    cczp_power_ws(ws, zp, r, s, ccn_bitlen(n, p), e);
    ok_ccn_cmp(n, r, t, "cczp_power when e = 4 with bit length |p|");
    cczp_mm_power_ws(ws, zp, r, s, ccn_bitlen(n, p), e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power when e = 4 with bit length |p|");
    (void)cczp_power_blinded_ws(ws, zp, r, s, ccn_bitlen(n, p), e, global_test_rng);
    ok_ccn_cmp(n, r, t, "cczp_power_blinded_ws when e = 4 with bit length |p|");

    ccn_add_ws(ws, n, t, s, p);
    isnt(cczp_power_ws(ws, zp, r, t, ccn_bitlen(n, e), e), 0, "cczp_power when base > p");
    isnt(cczp_mm_power_ws(ws, zp, r, t, ccn_bitlen(n, e), e), 0, "cczp_mm_power when base > p");
    isnt(cczp_power_blinded_ws(ws, zp, r, t, ccn_bitlen(n, e), e, global_test_rng), 0, "cczp_power_blinded_ws when base > p");

    CC_FREE_WORKSPACE(ws);
}

#define NUM_RANDOM_POWER_TESTS 1000

static void test_cczp_power_fns_randomized(cczp_const_t zp)
{
    struct ccrng_state *rng = global_test_rng;

    cc_size n = cczp_n(zp);
    cc_unit r0[n], r1[n], r2[n], r3[n], r4[n];
    cc_unit b[n], e[n];

    for (int i = 0; i < NUM_RANDOM_POWER_TESTS; i++) {
        CC_DECL_WORKSPACE_TEST(ws);

        is(cczp_generate_non_zero_element_ws(ws, zp, rng, e), CCERR_OK, "RNG failed");
        is(cczp_generate_non_zero_element_ws(ws, zp, rng, b), CCERR_OK, "RNG failed");

        is(cczp_power_ws(ws, zp, r0, b, ccn_bitlen(n, e), e), 0, "cczp_power randomized");
        is(cczp_mm_power_ws(ws, zp, r1, b, ccn_bitlen(n, e), e), 0, "cczp_mm_power randomized");
        is(cczp_power_fast_ws(ws, zp, r2, b, e), 0, "cczp_power_fast randomized");
        is(cczp_mm_power_fast_ws(ws, zp, r3, b, e), 0, "cczp_mm_power_fast randomized");
        is(cczp_power_blinded_ws(ws, zp, r4, b, ccn_bitlen(n, e), e, global_test_rng), 0, "cczp_power_blinded_ws randomized");

        ok_ccn_cmp(n, r0, r1, "cczp_power != cczp_mm_power");
        ok_ccn_cmp(n, r0, r2, "cczp_power != cczp_power_fast");
        ok_ccn_cmp(n, r0, r3, "cczp_power != cczp_mm_power_fast");
        ok_ccn_cmp(n, r0, r4, "cczp_power != cczp_power_blinded_ws");

        CC_FREE_WORKSPACE(ws);
    }
}

static int test_cczp_sqrt_single(cc_unit *r, cc_unit q, size_t p_len, const uint8_t *p)
{
    cc_size n = ccn_nof_size(p_len);

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_read_uint(n, CCZP_PRIME(zp), p_len, p);
    is(cczp_init(zp), CCERR_OK, "cczp_init() failed");

    cc_unit x[n];
    ccn_seti(n, x, q);

    return cczp_sqrt(zp, r, x);
}

#define NUM_RANDOM_SQRT_TESTS 1000

static void test_cczp_sqrt_randomized(cczp_const_t zq, cc_size n)
{
    cc_unit x[n];
    cc_unit r1[n];

    for (int i = 0; i < NUM_RANDOM_SQRT_TESTS; i++) {
        is(cczp_generate_non_zero_element(zq, global_test_rng, x), CCERR_OK, "RNG Failure");
        is(cczp_sqr(zq, x, x), CCERR_OK, "cczp_sqr() failed");

        is(cczp_sqrt(zq, r1, x), CCERR_OK, "sqrt() failed");
        is(cczp_sqr(zq, r1, r1), CCERR_OK, "cczp_sqr() failed");

        is(ccn_cmp(n, r1, x), 0, "SQRT FAILURE");
    }
}

static void test_cczp_sqrt_3mod4(void)
{
    // 597035519 = 3 mod 4
    const uint8_t prime1[] = { 0x23, 0x96, 0x09, 0xff };
    cc_unit r1[ccn_nof_sizeof(prime1)];
    is(test_cczp_sqrt_single(r1, 2, sizeof(prime1), prime1), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r1, 0, sizeof(prime1), prime1), 0, "cczp_sqrt failed");

    // 597035539 = 3 mod 4
    const uint8_t prime2[] = { 0x23, 0x96, 0x0a, 0x13 };
    cc_unit r2[ccn_nof_sizeof(prime2)];

    // x^2 = 2 mod 597035539 has no solution as 2 is not a quadratic residue.
    is(test_cczp_sqrt_single(r2, 2, sizeof(prime2), prime2), CCERR_PARAMETER, "cczp_sqrt should fail");
}

CC_UNUSED
static void test_cczp_sqrt_1mod4(void)
{
    // 40961 = 1 mod 4
    const uint8_t prime3[] = { 0xa0, 0x01 };
    cc_unit r3[ccn_nof_sizeof(prime3)];
    is(test_cczp_sqrt_single(r3, 5, sizeof(prime3), prime3), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r3, 0, sizeof(prime3), prime3), 0, "cczp_sqrt failed");

    // 360027784083079948259017962255826129 = 1 mod 4
    const uint8_t prime4[] = { 0x45, 0x56, 0xbd, 0x7f, 0x9d, 0xf3, 0x85, 0xb1, 0xcb, 0xb2, 0x24, 0xe3, 0x64, 0x3c, 0xd1 };
    cc_unit r4[ccn_nof_sizeof(prime4)];
    is(test_cczp_sqrt_single(r4, 2, sizeof(prime4), prime4), 0, "cczp_sqrt failed");

    // x^2 = 23 mod 360027784083079948259017962255826129 has no solution.
    is(test_cczp_sqrt_single(r4, 23, sizeof(prime4), prime4), CCERR_PARAMETER, "cczp_sqrt should fail");

    // 2^224 - 4733179336708116180759420887881155 = 1 mod 4
    ccec_const_cp_t p224 = ccec_cp_224();
    cczp_const_t zq224 = ccec_cp_zq(p224);
    cc_size n224 = ccec_cp_n(p224);

    cc_unit r5[n224], x5[n224];
    ccn_seti(n224, x5, 3);
    is(cczp_sqrt(zq224, r5, x5), 0, "cczp_sqrt failed");
}

static void test_cczp_sqr_vs_mul(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init(zp), CCERR_OK, "cczp_init() failed");

    cc_unit r_sqr[n];
    cc_unit r_mul[n];
    cc_unit x[n];

    for (int i = 0; i < NUM_RANDOM_SQRT_TESTS; i++) {
        is(cczp_generate_non_zero_element(zp, global_test_rng, x), CCERR_OK, "Gen Element Failure");
        is(cczp_sqr(zp, r_sqr, x), CCERR_OK, "cczp_sqr() failed");
        is(cczp_mul(zp, r_mul, x, x), CCERR_OK, "cczp_mul() failed");
        ok_ccn_cmp(n, r_sqr, r_mul, "SQR != MUL");
    }
}

static void test_cczp_add_sub(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init(zp), CCERR_OK, "cczp_init() failed");

    cc_unit x[n];
    cc_unit r[n];
    cc_unit one[n];

    ccn_seti(n, one, 1);
    ccn_set(n, x, p);
    x[0] -= 1; // x = p - 1

    is(cczp_add(zp, r, x, one), CCERR_OK, "cczp_add() failed"); // r = p - 1 + 1 == 0
    is(ccn_is_zero(n, r), 1, "p - 1 + 1 is not zero!");

    is(cczp_sub(zp, r, r, one), CCERR_OK, "cczp_sub() failed"); // r = p - 1
    is(ccn_cmp(n, r, x), 0, "0 - 1 is not p - 1!");
}

static void test_cczp_negate(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init(zp), CCERR_OK, "cczp_init() failed");

    cc_unit x[n];
    cc_unit y[n];
    cc_unit r[n];

    ccn_seti(n, y, 1);
    ccn_set(n, x, p);
    x[0] -= 1; // x = p - 1

    cczp_negate(zp, r, y);
    ok_ccn_cmp(n, r, x, "r = p-1");

    ccn_clear(n, y);
    cczp_negate(zp, r, y);
    ok(ccn_is_zero(n, r), "r = 0");
}

static void test_cczp_div2(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init_ws(ws, zp), CCERR_OK, "cczp_init() failed");

    cc_unit x[n];
    cc_unit r[n];
    cc_unit two[n];
    ccn_seti(n, two, 2);

    ccn_seti(n, x, 0);
    cczp_div2_ws(ws, zp, r, x); // 0 / 2
    is(ccn_is_zero(n, r), 1, "div2 failure");

    ccn_seti(n, x, 1);
    cczp_div2_ws(ws, zp, r, x); // 1 / 2
    cczp_mul_ws(ws, zp, r, r, two);
    is(ccn_is_one(n, r), 1, "div2 failure");

    ccn_seti(n, x, 2);
    cczp_div2_ws(ws, zp, r, x); // 2 / 2
    is(ccn_is_one(n, r), 1, "div2 failure");

    ccn_sub1(n, x, cczp_prime(zp), 1);
    cczp_div2_ws(ws, zp, r, x);
    cczp_mul_ws(ws, zp, r, r, two); // (p - 1) / 2
    ok_ccn_cmp(n, r, x, "div2 failure");

    CC_FREE_WORKSPACE(ws);
}

static void test_cczp_modn(size_t cn)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init(zp), CCERR_OK, "cczp_init() failed");

    cc_unit x[cn * n];
    cc_unit r[n];
    ccn_clear(cn * n, x);

    ccn_set(n, x + (cn - 1) * n, p);
    cczp_modn(zp, r, cn * n, x); // r = p << (cn - 1) * 256 mod p
    is(ccn_is_zero(n, r), 1, "modn failure");

    ccn_add1(cn * n, x, x, 1);
    cczp_modn(zp, r, cn * n, x); // r = (p + 1) mod p
    is(ccn_is_one(n, r), 1, "modn failure");

    ccn_sub1(cn * n, x, x, 2);
    cczp_modn(zp, r, cn * n, x); // p = (p - 1) mod p
    ccn_add1(n, r, r, 1);
    ok_ccn_cmp(n, r, p, "modn failure");
}

static void test_cczp_mod(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init_ws(ws, zp), CCERR_OK, "cczp_init() failed");

    cc_unit x[2 * n];
    cc_unit r[n];
    ccn_clear(2 * n, x);
    ccn_set(n, x + n, p);

    cczp_mod_ws(ws, zp, r, x); // 0 mod p
    is(ccn_is_zero(n, r), 1, "mod failure");

    ccn_add1_ws(ws, 2 * n, x, x, 1);
    cczp_mod_ws(ws, zp, r, x); // 1 mod p
    is(ccn_is_one(n, r), 1, "mod failure");

    ccn_sub1(2 * n, x, x, 2);
    cczp_mod_ws(ws, zp, r, x); // p - 1 mod p
    ccn_add1_ws(ws, n, r, r, 1);
    ok_ccn_cmp(n, r, p, "mod failure");

    CC_FREE_WORKSPACE(ws);
}

static void test_cczp_inv(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init(zp), CCERR_OK, "cczp_init() failed");

    int res;
    cc_unit x[n];
    cc_unit r[n];

    ccn_seti(n, x, 1);
    res = cczp_inv(zp, r, x); // 1 / 1
    is(res, 0, "cczp_inv failure");
    is(ccn_is_one(n, r), 1, "cczp_inv failure");

    ccn_seti(n, x, 2);
    res = cczp_inv(zp, r, x); // 1 / 2
    is(cczp_mul(zp, r, r, x), CCERR_OK, "cczp_mul() failed");
    is(res, 0, "cczp_inv failure");
    is(ccn_is_one(n, r), 1, "cczp_inv failure");

    ccn_sub1(n, x, p, 1);
    res = cczp_inv(zp, r, x); // 1 / (p - 1)
    is(cczp_mul(zp, r, r, x), CCERR_OK, "cczp_mul() failed");
    is(res, 0, "cczp_inv failure");
    is(ccn_is_one(n, r), 1, "cczp_inv failure");

    res = cczp_inv(zp, r, p); // 1 / p
    isnt(res, 0, "cczp_inv should have failed");

    ccn_clear(n, x);
    res = cczp_inv(zp, r, x); // 1 / 0
    isnt(res, 0, "cczp_inv should have failed");
}

static void test_cczp_quadratic_residue(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    is(cczp_init_ws(ws, zp), CCERR_OK, "cczp_init() failed");

    int res;
    cc_unit x[n];

    ccn_seti(n, x, 23); // 23 is a quadratic residue
    res = cczp_is_quadratic_residue_ws(ws, zp, x);
    is(res, 1, "QR test failure: x = 23 is a QR");

    ccn_seti(n, x, 235); // 235 is not a quadratic residue
    res = cczp_is_quadratic_residue_ws(ws, zp, x);
    isnt(res, 1, "QR test failure: x = 235 is not a QR");

    ccn_set(n, x, p);
    res = cczp_is_quadratic_residue_ws(ws, zp, x);
    isnt(res, 1, "QR test failure: x = p is not a QR");

    CC_FREE_WORKSPACE(ws);
}

int cczp_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int num_tests = 0;
    num_tests += 6;                               // test_cczp_init
    num_tests += 27;                              // test_cczp_power_fns
    num_tests += 2 * 11 * NUM_RANDOM_POWER_TESTS; // test_cczp_power_fns_randomized
    num_tests += 6;                               // test_cczp_sqrt_3mod4
    num_tests += 5 * NUM_RANDOM_SQRT_TESTS;       // test_cczp_sqrt_randomized
#if CCZP_SUPPORT_SQRT_1MOD4
    num_tests += 9;                               // test_cczp_sqrt_1mod4
    num_tests += 5 * NUM_RANDOM_SQRT_TESTS;       // test_cczp_sqrt_randomized
#endif
    num_tests += 1 + 4 * NUM_RANDOM_SQRT_TESTS;   // test_cczp_sqr_vs_mul
    num_tests += 5;                               // test_cczp_add_sub
    num_tests += 3;                               // test_cczp_negate
    num_tests += 5;                               // test_cczp_div2
    num_tests += 3 * 4;                           // test_cczp_modn
    num_tests += 4;                               // test_cczp_mod
    num_tests += 11;                              // test_cczp_inv
    num_tests += 4;                               // test_cczp_quadratic_residue

    plan_tests(num_tests);

    test_cczp_init();

    test_cczp_power_fns();
    test_cczp_power_fns_randomized(ccec_cp_zq(ccec_cp_256()));
    test_cczp_power_fns_randomized(ccec_cp_zq(ccec_cp_384()));

    test_cczp_sqrt_3mod4();
    ccec_const_cp_t p384 = ccec_cp_384(); // q == 3 mod 4
    test_cczp_sqrt_randomized(ccec_cp_zq(p384), ccec_cp_n(p384));

#if CCZP_SUPPORT_SQRT_1MOD4
    test_cczp_sqrt_1mod4();
    ccec_const_cp_t p224 = ccec_cp_224(); // q == 1 mod 4
    test_cczp_sqrt_randomized(ccec_cp_zq(p224), ccec_cp_n(p224));
#endif

    test_cczp_sqr_vs_mul();
    test_cczp_add_sub();
    test_cczp_negate();
    test_cczp_div2();

    test_cczp_modn(1);
    test_cczp_modn(2);
    test_cczp_modn(4);
    test_cczp_mod();

    test_cczp_inv();
    test_cczp_quadratic_residue();

    return 0;
}
