/* Copyright (c) (2011,2012,2014-2019,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>

#define CCHMAC_TEST(_di, _keylen) { .name="cchmac_"#_keylen"_"#_di, .di=&_di, .keylen=_keylen }

static struct ccdigest_info ccsha1_di_default;
static struct ccdigest_info ccsha224_di_default;
static struct ccdigest_info ccsha256_di_default;
static struct ccdigest_info ccsha384_di_default;
static struct ccdigest_info ccsha512_di_default;

static struct cchmac_perf_test {
    const char *name;
    const struct ccdigest_info *di;
    size_t keylen;
} cchmac_perf_tests[] = {
    CCHMAC_TEST(ccsha1_eay_di, 16),
    CCHMAC_TEST(ccsha1_ltc_di, 16),
    CCHMAC_TEST(ccsha1_di_default, 16),

    CCHMAC_TEST(ccsha256_ltc_di, 16),
    CCHMAC_TEST(ccsha256_di_default, 16),

    CCHMAC_TEST(ccsha512_ltc_di, 16),
    CCHMAC_TEST(ccsha512_di_default,16),

    CCHMAC_TEST(ccmd4_ltc_di, 16),
    CCHMAC_TEST(ccmd5_ltc_di, 16),
};

static double perf_cchmac(size_t loops, size_t *psize, const void *arg)
{
    const struct cchmac_perf_test *test=arg;
    unsigned char mac[test->di->output_size];
    unsigned char key[test->keylen];
    unsigned char *data = malloc(*psize);

    cc_clear(test->keylen,key);

    perf_start();
    do {
        cchmac(test->di, test->keylen, key,
               *psize, data, mac);
    } while (--loops != 0);

    double seconds = perf_seconds();
    free(data);
    return seconds;
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cchmac(int argc, char *argv[])
{
    memcpy(&ccsha1_di_default,ccsha1_di(),sizeof(ccsha1_di_default));
    memcpy(&ccsha224_di_default,ccsha224_di(),sizeof(ccsha224_di_default));
    memcpy(&ccsha256_di_default,ccsha256_di(),sizeof(ccsha256_di_default));
    memcpy(&ccsha384_di_default,ccsha384_di(),sizeof(ccsha384_di_default));
    memcpy(&ccsha512_di_default,ccsha512_di(),sizeof(ccsha512_di_default));

    F_GET_ALL(family, cchmac);
    const size_t sizes[]={32,256,4096,4*4096};
    F_SIZES_FROM_ARRAY(family, sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}
