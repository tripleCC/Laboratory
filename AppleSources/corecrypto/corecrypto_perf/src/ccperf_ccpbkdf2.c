/* Copyright (c) (2011,2012,2014-2019,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>

#define CCPBKDF2_TEST(_di) { .name="ccpbkdf2_"#_di, .di=&_di }

static struct ccdigest_info ccsha1_di_default;
static struct ccdigest_info ccsha224_di_default;
static struct ccdigest_info ccsha256_di_default;
static struct ccdigest_info ccsha384_di_default;
static struct ccdigest_info ccsha512_di_default;

static struct ccpbkdf2_perf_test {
    const char *name;
    const struct ccdigest_info *di;
} ccpbkdf2_perf_tests[] = {
    CCPBKDF2_TEST(ccsha1_eay_di),
    CCPBKDF2_TEST(ccsha1_ltc_di),
    CCPBKDF2_TEST(ccsha1_di_default),

    CCPBKDF2_TEST(ccsha256_ltc_di),
    CCPBKDF2_TEST(ccsha256_di_default),

    CCPBKDF2_TEST(ccsha512_ltc_di),
    CCPBKDF2_TEST(ccsha512_di_default),

    CCPBKDF2_TEST(ccmd4_ltc_di),
    CCPBKDF2_TEST(ccmd5_ltc_di),
};

static double perf_ccpbkdf2(size_t loops, size_t *psize, const void *arg)
{
    const struct ccpbkdf2_perf_test *test=arg;
    size_t pwdLen=16;
    unsigned char pwd[pwdLen];
    size_t saltLen=16;
    unsigned char salt[saltLen];
    size_t dkLen=16;
    unsigned char dk[dkLen];
    size_t iterations=*psize;

    ccrng_generate(rng, pwdLen, pwd);
    ccrng_generate(rng, saltLen, salt);

    perf_start();
    do {
        if (ccpbkdf2_hmac(test->di, pwdLen, pwd, saltLen, salt, iterations, dkLen, dk)) {
            abort();
        }
    } while (--loops != 0);
    return perf_seconds();
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccpbkdf2(int argc, char *argv[])
{
    memcpy(&ccsha1_di_default,ccsha1_di(),sizeof(ccsha1_di_default));
    memcpy(&ccsha224_di_default,ccsha224_di(),sizeof(ccsha224_di_default));
    memcpy(&ccsha256_di_default,ccsha256_di(),sizeof(ccsha256_di_default));
    memcpy(&ccsha384_di_default,ccsha384_di(),sizeof(ccsha384_di_default));
    memcpy(&ccsha512_di_default,ccsha512_di(),sizeof(ccsha512_di_default));

    F_GET_ALL(family, ccpbkdf2);
    static const size_t iteration_numbers[]={1,100,10000};
    F_SIZES_FROM_ARRAY(family,iteration_numbers);
    family.size_kind=ccperf_size_iterations;
    return &family;
}
