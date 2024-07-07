/* Copyright (c) (2014-2020,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccansikdf.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

static struct ccdigest_info ccsha1_di_default;
static struct ccdigest_info ccsha224_di_default;
static struct ccdigest_info ccsha256_di_default;
static struct ccdigest_info ccsha384_di_default;
static struct ccdigest_info ccsha512_di_default;

#define CCANSIKDF_TEST(_di,_Zlen) { .name="kdf_x963_"#_di"_Zlen"#_Zlen, .di=&_di, .Zlen=_Zlen }

static struct ccansikdf_perf_test {
    const char *name;
    const struct ccdigest_info *di;
    const size_t Zlen;
} ccansikdf_perf_tests[] = {
// SHA1
    // Zlen = 16
    CCANSIKDF_TEST(ccsha1_eay_di,16),
    CCANSIKDF_TEST(ccsha1_ltc_di,16),
    CCANSIKDF_TEST(ccsha1_di_default,16),

// SHA1
    // Zlen = 256
    CCANSIKDF_TEST(ccsha1_eay_di,256),
    CCANSIKDF_TEST(ccsha1_ltc_di,256),
    CCANSIKDF_TEST(ccsha1_di_default,256),

// SHA256
    // Zlen = 16
    CCANSIKDF_TEST(ccsha256_ltc_di,16),
    CCANSIKDF_TEST(ccsha256_di_default,16),

// SHA256
    // Zlen = 256
    CCANSIKDF_TEST(ccsha256_ltc_di,256),
    CCANSIKDF_TEST(ccsha256_di_default,256),

// SHA512
    // Zlen = 16
    CCANSIKDF_TEST(ccsha512_ltc_di,16),
    CCANSIKDF_TEST(ccsha512_di_default,256),

    // Zlen = 256
    CCANSIKDF_TEST(ccsha512_ltc_di,16),
    CCANSIKDF_TEST(ccsha512_di_default,256),

};

static double perf_ccansikdf(size_t loops, size_t *psize, const void *arg)
{
    const struct ccansikdf_perf_test *test=arg;
    size_t Zlen=test->Zlen;
    unsigned char Z[Zlen];
    size_t sharedInfoLen=0;
    unsigned char *sharedInfo=NULL;
    size_t outputLen=*psize;
    unsigned char *output = malloc(outputLen);

    ccrng_generate(rng, Zlen, Z);

    perf_start();
    do {
        if (ccansikdf_x963(test->di, Zlen, Z, sharedInfoLen, sharedInfo, outputLen, output)) {
            abort();
        }
    } while (--loops != 0);

    double seconds = perf_seconds();
    free(output);
    return seconds;
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccansikdf(int argc, char *argv[])
{
    memcpy(&ccsha1_di_default,ccsha1_di(),sizeof(ccsha1_di_default));
    memcpy(&ccsha224_di_default,ccsha224_di(),sizeof(ccsha224_di_default));
    memcpy(&ccsha256_di_default,ccsha256_di(),sizeof(ccsha256_di_default));
    memcpy(&ccsha384_di_default,ccsha384_di(),sizeof(ccsha384_di_default));
    memcpy(&ccsha512_di_default,ccsha512_di(),sizeof(ccsha512_di_default));


    F_GET_ALL(family, ccansikdf);
    static const size_t sizes[]={16,32,256};
    F_SIZES_FROM_ARRAY(family,sizes);
    family.size_kind=ccperf_size_iterations;
    return &family;
}

