/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"

typedef int (*cczp_cczp_inv_t)(cczp_const_t zp, cc_unit *r, const cc_unit *x);

static double perf_cczp_inv_ws(size_t loops, cc_size nbits)
{
    int st;
    cc_size n = ccn_nof(nbits);
    cc_unit a[n], ai[n];

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;

    st=ccn_random(n, a, rng); if(st!=0) abort();
    st=ccn_random(n, CCZP_PRIME(zp), rng); if(st!=0) abort();
    CCZP_PRIME(zp)[0] |= 1; // ensure p is odd
    (void)cczp_init(zp);
    cczp_modn(zp, a, n, a);

    perf_start();
    do {
        (void)cczp_inv(zp, ai, a);
    } while (--loops != 0);

    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct cczp_inv_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbits);
} cczp_inv_perf_tests[] = {
    _TEST(cczp_inv_ws),
};

static double perf_cczp_inv(size_t loops CC_UNUSED, size_t *psize, const void *arg)
{
    const struct cczp_inv_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cczp_inv(int argc, char *argv[])
{
    F_GET_ALL(family, cczp_inv);

    const size_t sizes[] = { 256, 512, 1024,2048, 4096 };
    F_SIZES_FROM_ARRAY(family, sizes);

    family.size_kind=ccperf_size_bits;
    return &family;
}
