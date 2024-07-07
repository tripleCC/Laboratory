/* Copyright (c) (2014-2020) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng.h>
#include "ccrng_internal.h"
#include <corecrypto/ccrng_system.h>
#include <corecrypto/ccaes.h>

static struct ccrng_system_state system_ctx;
static struct ccrng_state *default_rng;

static double perf_f_ccrng(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;
    perf_start();
    do {
        status = ccrng_generate(default_rng, nbytes, results);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    return time;
}

static double perf_f_ccrng_system_generate(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;
    perf_start();
    do {
        status = ccrng_generate((struct ccrng_state *)&system_ctx, nbytes, results);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    return time;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static double perf_f_ccrng_system_oneshot(size_t loops, size_t nbytes)
{
    struct ccrng_system_state local_system_ctx;
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;
    perf_start();
    do {
        status = ccrng_system_init(&local_system_ctx);
        cc_assert(status==0);
        status = ccrng_generate((struct ccrng_state *)&local_system_ctx, nbytes, results);
        cc_assert(status==0);
        ccrng_system_done(&local_system_ctx);
    } while (--loops != 0);
    time=perf_seconds();
    return time;
}
#pragma clang diagnostic pop

static double perf_f_cc_get_entropy(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;
    perf_start();
    do {
        status = cc_get_entropy(nbytes, results);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    return time;
}


#define _TEST(_x) { .name = #_x, .func = perf_f_ ## _x}
static struct ccrng_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbytes);
} ccrng_perf_tests[] = {
    _TEST(ccrng),
    _TEST(cc_get_entropy),
    _TEST(ccrng_system_generate),
    _TEST(ccrng_system_oneshot),
};

static double perf_ccrng(size_t loops, size_t *psize, const void *arg)
{
    const struct ccrng_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;


struct ccperf_family *ccperf_family_ccrng(int argc, char *argv[])
{
    CC_UNUSED int status;

    default_rng = ccrng(&status);
    cc_assert(status==0);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = ccrng_system_init(&system_ctx);
#pragma clang diagnostic pop
    cc_assert(status==0);

    F_GET_ALL(family, ccrng);
    static const size_t sizes[]={4,16,32,256,1024,32*1024};
    F_SIZES_FROM_ARRAY(family,sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}
