/* Copyright (c) (2011,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccperf.h"
#include <corecrypto/ccn.h>
#include "ccn_internal.h"

#define CCN_PERF_FUNCTION_N_R_N_X_N_Y_WS(func)         \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit y[n];                                  \
        cc_unit r[2 * n];                              \
        double perf_res;                               \
        ccn_random(n, x, rng);                         \
        ccn_random(n, y, rng);                         \
        CC_DECL_WORKSPACE_TEST(ws);                    \
        perf_start();                                  \
        do                                             \
            (void)func(ws, n, r, n, x, n, y);          \
        while (--loops != 0);                          \
        perf_res = perf_seconds();                     \
        CC_FREE_WORKSPACE(ws);                         \
        return perf_res;                               \
    }

#define CCN_PERF_FUNCTION_N_R_X_N_Y_WS(func)         \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit y[n];                                  \
        cc_unit r[2 * n];                              \
        double perf_res;                               \
        ccn_random(n, x, rng);                         \
        ccn_random(n, y, rng);                         \
        CC_DECL_WORKSPACE_TEST(ws);                    \
        perf_start();                                  \
        do                                             \
            (void)func(ws, n, r, x, n, y);          \
        while (--loops != 0);                          \
        perf_res = perf_seconds();                     \
        CC_FREE_WORKSPACE(ws);                         \
        return perf_res;                               \
    }

#define CCN_PERF_FUNCTION_N_R_N_X_Y_WS(func)           \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit y[n];                                  \
        cc_unit r[n];                                  \
        double perf_res;                               \
        ccn_random(n, x, rng);                         \
        ccn_random(n, y, rng);                         \
        y[0] |= 1;                                     \
        CC_DECL_WORKSPACE_TEST(ws);                    \
        perf_start();                                  \
        do                                             \
            (void)func(ws, n, r, n, x, y);             \
        while (--loops != 0);                          \
        perf_res = perf_seconds();                     \
        CC_FREE_WORKSPACE(ws);                         \
        return perf_res;                               \
    }

#define CCN_PERF_FUNCTION_N_R_X_Y_WS(func)             \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit y[n];                                  \
        cc_unit r[2 * n];                              \
        double perf_res;                               \
        ccn_random(n, x, rng);                         \
        ccn_random(n, y, rng);                         \
        CC_DECL_WORKSPACE_TEST(ws);                    \
        perf_start();                                  \
        do                                             \
            func(ws, n, r, x, y);                      \
        while (--loops != 0);                          \
        perf_res = perf_seconds();                     \
        CC_FREE_WORKSPACE(ws);                         \
        return perf_res;                               \
    }

#define CCN_PERF_FUNCTION_N_R_X_Y(func)                \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit y[n];                                  \
        cc_unit r[2 * n];                              \
        ccn_random(n, x, rng);                         \
        ccn_random(n, y, rng);                         \
        perf_start();                                  \
        do                                             \
            func(n, r, x, y);                          \
        while (--loops != 0);                          \
        return perf_seconds();                         \
    }

#define CCN_PERF_FUNCTION_N_R_X_N_Y(func)              \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit y[n];                                  \
        cc_unit r[2 * n];                              \
        ccn_random(n, x, rng);                         \
        ccn_random(n, y, rng);                         \
        perf_start();                                  \
        do                                             \
            func(n, r, x, n, y);                       \
        while (--loops != 0);                          \
        return perf_seconds();                         \
    }

#define CCN_PERF_FUNCTION_N_R_X(func)                  \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit r[2 * n];                              \
        ccn_random(n, x, rng);                         \
        perf_start();                                  \
        do                                             \
            func(n, r, x);                             \
        while (--loops != 0);                          \
        return perf_seconds();                         \
    }

#define CCN_PERF_FUNCTION_N_R_X_WS(func)               \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        cc_unit r[2 * n];                              \
        ccn_random(n, x, rng);                         \
        CC_DECL_WORKSPACE_TEST(ws);                    \
        perf_start();                                  \
        do                                             \
            func(ws, n, r, x);                         \
        while (--loops != 0);                          \
        CC_FREE_WORKSPACE(ws);                         \
        return perf_seconds();                         \
    }

#define CCN_PERF_FUNCTION_N_X(func)                    \
    static double perf_##func(size_t loops, cc_size n) \
    {                                                  \
        cc_unit x[n];                                  \
        ccn_random(n, x, rng);                         \
        perf_start();                                  \
        do                                             \
            (void)func(n, x);                          \
        while (--loops != 0);                          \
        return perf_seconds();                         \
    }

#define CCN_PERF_FUNCTION_N_R_X_t(func, _type)                                     \
    static double perf_##func(size_t loops, cc_size n)                             \
    {                                                                              \
        cc_unit x[n];                                                              \
        cc_unit r[n];                                                              \
        _type b;                                                                   \
        ccn_random(n, x, rng);                                                     \
        ccn_random(n, r, rng);                                                     \
        ccrng_generate(rng, sizeof(b), &b);                                        \
        /* typecast: Number of bits in a cc_unit will always fit into a cc_unit */ \
        b &= (_type)(CCN_UNIT_BITS - 1);                                           \
        if (b == 0)                                                                \
            b = 1;                                                                 \
        perf_start();                                                              \
        do                                                                         \
            (void)func(n, r, x, b);                                                \
        while (--loops != 0);                                                      \
        return perf_seconds();                                                     \
    }

#define CCN_PERF_FUNCTION_N_R_X_B(func) CCN_PERF_FUNCTION_N_R_X_t(func, cc_unit)
#define CCN_PERF_FUNCTION_N_R_X_S(func) CCN_PERF_FUNCTION_N_R_X_t(func, size_t)

CCN_PERF_FUNCTION_N_R_X_WS(ccn_sqr_ws)
CCN_PERF_FUNCTION_N_R_X_Y_WS(ccn_mul_ws)
CCN_PERF_FUNCTION_N_R_X_Y(ccn_add)
CCN_PERF_FUNCTION_N_R_X_Y(ccn_sub)
CCN_PERF_FUNCTION_N_R_X_Y(ccn_mul)
CCN_PERF_FUNCTION_N_R_X_N_Y(ccn_muln)
CCN_PERF_FUNCTION_N_R_N_X_N_Y_WS(ccn_gcd_ws)
CCN_PERF_FUNCTION_N_R_X_Y_WS(ccn_lcm_ws)
CCN_PERF_FUNCTION_N_R_N_X_Y_WS(ccn_invmod_ws)

CCN_PERF_FUNCTION_N_R_X(ccn_set)
CCN_PERF_FUNCTION_N_X(ccn_bitlen)

CCN_PERF_FUNCTION_N_R_X_B(ccn_add1)
CCN_PERF_FUNCTION_N_R_X_B(ccn_mul1)
CCN_PERF_FUNCTION_N_R_X_B(ccn_addmul1)
CCN_PERF_FUNCTION_N_R_X_S(ccn_shift_left)
CCN_PERF_FUNCTION_N_R_X_S(ccn_shift_right)
CCN_PERF_FUNCTION_N_R_X_S(ccn_shift_left_multi)
CCN_PERF_FUNCTION_N_R_X_S(ccn_shift_right_multi)

/* this test the comparaison of identicals (worst case) */
/* putting this as a global so that compiler dont optimize away the actual calls we are trying to measure */
static int r_for_cmp;
static double perf_ccn_cmp(size_t loops, cc_size n)
{
    cc_unit s[n];
    cc_unit t[n];
    ccn_random(n, s, rng);
    ccn_set(n, t, s);
    perf_start();
    do {
        r_for_cmp = ccn_cmp(n, s, t);
    } while (--loops != 0);
    return perf_seconds();
}

// PERF_FUNCTION_N_R_D_L(ccn_read_uint)
// PERF_FUNCTION_N_R_D_L(ccn_write_uint)

#define CCN_TEST(_op)                                      \
    {                                                      \
        .name = "ccn_" #_op, .di = &_di, .keylen = _keylen \
    }

#define _TEST(_x)                      \
    {                                  \
        .name = #_x, .func = perf_##_x \
    }
static struct ccn_perf_test {
    const char *name;
    double (*func)(size_t loops, cc_size n);
} ccn_perf_tests[] = {
    _TEST(ccn_gcd_ws),
    _TEST(ccn_invmod_ws),

    _TEST(ccn_mul),
    _TEST(ccn_muln),
    _TEST(ccn_mul_ws),
    _TEST(ccn_sqr_ws),
    _TEST(ccn_add),
    _TEST(ccn_sub),

    _TEST(ccn_shift_left),
    _TEST(ccn_shift_right),
    _TEST(ccn_shift_left_multi),
    _TEST(ccn_shift_right_multi),

    _TEST(ccn_add1),
    _TEST(ccn_set),
    _TEST(ccn_cmp),
    _TEST(ccn_bitlen),
    _TEST(ccn_lcm_ws),

    _TEST(ccn_mul1),
    _TEST(ccn_addmul1),
};

static double perf_ccn(size_t loops, size_t *psize, const void *arg)
{
    const struct ccn_perf_test *test = arg;
    cc_size n = ccn_nof(*psize);
    return test->func(loops, n);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccn(int argc, char *argv[])
{
    F_GET_ALL(family, ccn);
    family.loops = 100;
    const size_t number_nbits[] = { 256, 512, 1024, 1280, 2048, 4096 };
    F_SIZES_FROM_ARRAY(family, number_nbits);
    family.size_kind = ccperf_size_bits;
    return &family;
}
