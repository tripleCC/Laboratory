/* Copyright (c) (2011,2012,2014-2016,2018,2019,2021-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>
#include "ccsha3_internal.h"

#define CCDIGEST_TEST(_di) { .name=#_di, .di=&_di }

static struct ccdigest_info ccsha1_di_default;
static struct ccdigest_info ccsha224_di_default;
static struct ccdigest_info ccsha256_di_default;
static struct ccdigest_info ccsha384_di_default;
static struct ccdigest_info ccsha512_di_default;
static struct ccdigest_info ccsha512_256_di_default;
static struct ccdigest_info ccsha3_224_di_default;
static struct ccdigest_info ccsha3_256_di_default;
static struct ccdigest_info ccsha3_384_di_default;
static struct ccdigest_info ccsha3_512_di_default;

static struct ccdigest_perf_test {
    const char *name;
    const struct ccdigest_info *di;
} ccdigest_perf_tests[] = {
    CCDIGEST_TEST(ccmd2_ltc_di),
    CCDIGEST_TEST(ccmd4_ltc_di),
    CCDIGEST_TEST(ccmd5_ltc_di),
    CCDIGEST_TEST(ccsha1_eay_di),
    CCDIGEST_TEST(ccsha1_ltc_di),
    CCDIGEST_TEST(ccsha1_di_default),
    CCDIGEST_TEST(ccsha224_ltc_di),
    CCDIGEST_TEST(ccsha224_di_default),
    CCDIGEST_TEST(ccsha256_ltc_di),
    CCDIGEST_TEST(ccsha256_di_default),
    CCDIGEST_TEST(ccsha384_ltc_di),
    CCDIGEST_TEST(ccsha384_di_default),
    CCDIGEST_TEST(ccsha512_ltc_di),
    CCDIGEST_TEST(ccsha512_di_default),
    CCDIGEST_TEST(ccsha512_256_ltc_di),
    CCDIGEST_TEST(ccsha512_256_di_default),
    CCDIGEST_TEST(ccsha3_224_c_di),
    CCDIGEST_TEST(ccsha3_256_c_di),
    CCDIGEST_TEST(ccsha3_384_c_di),
    CCDIGEST_TEST(ccsha3_512_c_di),
    CCDIGEST_TEST(ccsha3_224_di_default),
    CCDIGEST_TEST(ccsha3_256_di_default),
    CCDIGEST_TEST(ccsha3_384_di_default),
    CCDIGEST_TEST(ccsha3_512_di_default),
};

static double perf_ccdigest(size_t loops, size_t *psize, const void *arg)
{
    const struct ccdigest_perf_test *test=arg;
    unsigned char h[test->di->output_size];
    unsigned char *data = malloc(*psize);
    ccrng_generate(rng, *psize, data);

    perf_start();
    do {
        ccdigest(test->di, *psize, data, h);
    } while (--loops != 0);

    double seconds = perf_seconds();
    free(data);
    return seconds;
}

static struct ccperf_family family;

static const size_t sizes[]={16,256,32*1024};

struct ccperf_family *ccperf_family_ccdigest(int argc, char *argv[])
{
    memcpy(&ccsha1_di_default,ccsha1_di(),sizeof(ccsha1_di_default));
    memcpy(&ccsha224_di_default,ccsha224_di(),sizeof(ccsha224_di_default));
    memcpy(&ccsha256_di_default,ccsha256_di(),sizeof(ccsha256_di_default));
    memcpy(&ccsha384_di_default,ccsha384_di(),sizeof(ccsha384_di_default));
    memcpy(&ccsha512_di_default,ccsha512_di(),sizeof(ccsha512_di_default));
    memcpy(&ccsha512_256_di_default,ccsha512_256_di(),sizeof(ccsha512_256_di_default));
    memcpy(&ccsha3_224_di_default,ccsha3_224_di(),sizeof(ccsha3_224_di_default));
    memcpy(&ccsha3_256_di_default,ccsha3_256_di(),sizeof(ccsha3_256_di_default));
    memcpy(&ccsha3_384_di_default,ccsha3_384_di(),sizeof(ccsha3_384_di_default));
    memcpy(&ccsha3_512_di_default,ccsha3_512_di(),sizeof(ccsha3_512_di_default));
    F_GET_ALL(family, ccdigest);
    F_SIZES_FROM_ARRAY(family, sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}
