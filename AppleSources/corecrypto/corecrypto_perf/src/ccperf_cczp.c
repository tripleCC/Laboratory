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
#include <corecrypto/cczp.h>
#include "cczp_internal.h"

// p = 77521964218494527399110796663698708768157059199486457132572782396833494502331 = 3 mod 4
const uint8_t prime_256_3mod4[32] = {0xab, 0x63, 0xe0, 0x78, 0xed, 0x14, 0xf4, 0xa7, 0xc7, 0x39, 0xe1, 0xc8, 0x1a, 0x9e, 0x82, 0x03, 0xb3, 0xa1, 0xed, 0xc2, 0x15, 0xb2, 0x01, 0xaa, 0x21, 0x03, 0x86, 0x41, 0xbc, 0xc4, 0x8b, 0xbb};
// p = 77521964218494527399110796663698708768157059199486457132572782396833494502661 = 1 mod 4
const uint8_t prime_256_1mod4[32] = {0xab, 0x63, 0xe0, 0x78, 0xed, 0x14, 0xf4, 0xa7, 0xc7, 0x39, 0xe1, 0xc8, 0x1a, 0x9e, 0x82, 0x03, 0xb3, 0xa1, 0xed, 0xc2, 0x15, 0xb2, 0x01, 0xaa, 0x21, 0x03, 0x86, 0x41, 0xbc, 0xc4, 0x8d, 0x05};
// p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433636664850207 = 3 mod 4
const uint8_t prime_512_3mod4[64] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd, 0x20, 0x67, 0xb7, 0x1f};
// p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433636664850437 = 1 mod 4
const uint8_t prime_512_1mod4[64] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd, 0x20, 0x67, 0xb8, 0x05};

static double perf_cczp_sqrt_common(size_t loops, cc_size nbits, int is_3mod4)
{
    cczp_decl_n(ccn_nof(nbits), zp);
    const uint8_t *primep;
    switch(nbits) {
        case 256:
            if (is_3mod4) {
                primep = &prime_256_3mod4[0];
            } else {
                primep = &prime_256_1mod4[0];
            }
            break;
        case 512:
            if (is_3mod4) {
                primep = &prime_512_3mod4[0];
            } else {
                primep = &prime_512_1mod4[0];
            }
            break;
        default:
            return 0;
    }
    ccn_read_uint(ccn_nof(nbits), CCZP_PRIME(zp), nbits / 8, primep);
    CCZP_N(zp) = ccn_nof(nbits);
    (void)cczp_init(zp);

    cc_unit r[ccn_nof(nbits)], s[ccn_nof(nbits)];
    ccn_random_bits(nbits, s, rng);
    cczp_modn(zp, s, cczp_n(zp), s);
    if (cczp_sqr(zp, s, s)) {
        abort();
    }

    perf_start();
    do {
        cczp_sqrt(zp, r, s);
    } while (--loops != 0);
    return perf_seconds();
}

#define CCZP_SQRT_TEST(_name_, _is_3mod4_)                               \
    static double perf_cczp_sqrt_##_name_(size_t loops, cc_size nbits) { \
        return perf_cczp_sqrt_common(loops, nbits, _is_3mod4_);          \
    }

CCZP_SQRT_TEST(3mod4, true)
CCZP_SQRT_TEST(1mod4, false)

static double perf_cczp_init(size_t loops, cc_size nbits)
{
    cc_size n = ccn_nof(nbits);
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;

    int rv;
    CC_DECL_WORKSPACE_RV(ws, CCZP_INIT_WORKSPACE_N(n), rv);
    if (rv) abort();

    ccn_random_bits(nbits, CCZP_PRIME(zp), rng);
    ccn_set_bit(CCZP_PRIME(zp), 0, 1); // make it odd

    perf_start();
    do {
        (void)cczp_init_ws(ws, zp);
    } while (--loops != 0);

    CC_FREE_WORKSPACE(ws);
    return perf_seconds();
}

static double perf_cczp_add(size_t loops, cc_size nbits)
{
    cczp_decl_n(ccn_nof(nbits), zp);
    cc_unit r[ccn_nof(nbits)], s[ccn_nof(nbits)];
    CCZP_N(zp) = ccn_nof(nbits);

    ccn_random_bits(nbits, s, rng);
    ccn_random_bits(nbits, CCZP_PRIME(zp), rng);
    ccn_set_bit(CCZP_PRIME(zp), 0, 1); // make it odd
    (void)cczp_init(zp);
    cczp_modn(zp,s,cczp_n(zp),s);
    perf_start();
    do {
        if (cczp_add(zp, r, s, s)) {
            abort();
        }
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cczp_sub(size_t loops, cc_size nbits)
{
    cczp_decl_n(ccn_nof(nbits), zp);
    cc_unit r[ccn_nof(nbits)], s[ccn_nof(nbits)], t[ccn_nof(nbits)];
    CCZP_N(zp) = ccn_nof(nbits);

    ccn_random_bits(nbits, s, rng);
    ccn_random_bits(nbits, t, rng);
    ccn_random_bits(nbits, CCZP_PRIME(zp), rng);
    ccn_set_bit(CCZP_PRIME(zp), 0, 1); // make it odd
    (void)cczp_init(zp);
    cczp_modn(zp,s,cczp_n(zp),s);
    cczp_modn(zp,t,cczp_n(zp),t);
    perf_start();
    do {
        if (cczp_sub(zp, r, s, t)) {
            abort();
        }
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cczp_mul(size_t loops, cc_size nbits)
{
    cczp_decl_n(ccn_nof(nbits), zp);
    cc_unit r[ccn_nof(nbits)], s[ccn_nof(nbits)];
    CCZP_N(zp) = ccn_nof(nbits);

    ccn_random_bits(nbits, s, rng);
    ccn_random_bits(nbits, CCZP_PRIME(zp), rng);
    ccn_set_bit(CCZP_PRIME(zp), 0, 1); // make it odd
    (void)cczp_init(zp);
    cczp_modn(zp,s,cczp_n(zp),s);
    perf_start();
    do {
        if (cczp_mul(zp, r, s, s)) {
            abort();
        }
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cczp_sqr(size_t loops, cc_size nbits)
{
    cczp_decl_n(ccn_nof(nbits), zp);
    cc_unit r[ccn_nof(nbits)], s[ccn_nof(nbits)];
    CCZP_N(zp) = ccn_nof(nbits);

    ccn_random_bits(nbits, s, rng);
    ccn_random_bits(nbits, CCZP_PRIME(zp), rng);
    ccn_set_bit(CCZP_PRIME(zp), 0, 1); // make it odd
    (void)cczp_init(zp);
    cczp_modn(zp,s,cczp_n(zp),s);
    perf_start();
    do {
        cczp_sqr(zp, r, s);
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cczp_power_fast(size_t loops, cc_size nbits, cc_unit *exponent)
{
    cczp_decl_n(ccn_nof(nbits), zp);
    cc_unit r[ccn_nof(nbits)], msg[ccn_nof(nbits)];
    CCZP_N(zp) = ccn_nof(nbits);

    ccn_random_bits(nbits, msg, rng);
    ccn_random_bits(nbits, CCZP_PRIME(zp), rng);
    ccn_set_bit(CCZP_PRIME(zp), 0, 1); // make it odd
    (void)cczp_init(zp);
    cczp_modn(zp,msg,cczp_n(zp),msg);
    perf_start();
    do {
        cczp_power_fast(zp, r, msg, exponent);
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cczp_power(size_t loops, cc_size nbits, cc_unit *exponent)
{
    cczp_decl_n(ccn_nof(nbits), zp);
    cc_unit r[ccn_nof(nbits)], msg[ccn_nof(nbits)];
    CCZP_N(zp) = ccn_nof(nbits);

    ccn_random_bits(nbits, msg, rng);
    ccn_random_bits(nbits, CCZP_PRIME(zp), rng);
    ccn_set_bit(CCZP_PRIME(zp), 0, 1); // make it odd
    (void)cczp_init(zp);
    cczp_modn(zp,msg,cczp_n(zp),msg);

    CC_DECL_WORKSPACE_TEST(ws);
    perf_start();
    do {
        (void)cczp_power_ws(ws, zp, r, msg, nbits, exponent);
    } while (--loops != 0);

    CC_FREE_WORKSPACE(ws);
    return perf_seconds();
}

static double perf_cczp_power_rnd(size_t loops, cc_size nbits)
{
    cc_unit exponent[ccn_nof(nbits)];
    ccn_random_bits(nbits, exponent, rng);
    return perf_cczp_power(loops, nbits, exponent);
}

static double perf_cczp_power_fast_3(size_t loops, cc_size nbits)
{
    cc_unit exponent[ccn_nof(nbits)];
    ccn_seti(ccn_nof(nbits), exponent, 3);
    return perf_cczp_power_fast(loops, nbits, exponent);
}

static double perf_cczp_power_fast_65537(size_t loops, cc_size nbits)
{
    cc_unit exponent[ccn_nof(nbits)];
    ccn_seti(ccn_nof(nbits), exponent, 65537);
    return perf_cczp_power_fast(loops, nbits, exponent);
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct cczp_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size n);
} cczp_perf_tests[] = {
    _TEST(cczp_init),
    _TEST(cczp_add),
    _TEST(cczp_sub),
    _TEST(cczp_sqr),
    _TEST(cczp_mul),
    _TEST(cczp_power_rnd),
    _TEST(cczp_power_fast_3),
    _TEST(cczp_power_fast_65537),
    _TEST(cczp_sqrt_3mod4),
    _TEST(cczp_sqrt_1mod4),
};

static double perf_cczp(size_t loops, size_t *psize, const void *arg)
{
    const struct cczp_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cczp(int argc, char *argv[])
{
    F_GET_ALL(family, cczp);
    static const size_t group_nbits[]={256,512,1024,2048,4096};
    F_SIZES_FROM_ARRAY(family, group_nbits);
    family.size_kind=ccperf_size_bits;
    return &family;
}
