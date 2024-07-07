/* Copyright (c) (2021,2023) Apple Inc. All rights reserved.
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
#include "cch2c_internal.h"

#define CCH2C_TEST(_di)            \
    {                              \
        .name = #_di, .info = &_di \
    }
static struct cch2c_perf_test {
    const char *name;
    const struct cch2c_info *info;
} cch2c_perf_tests[] = {
    CCH2C_TEST(cch2c_p256_sha256_sswu_ro_info),
    CCH2C_TEST(cch2c_p384_sha512_sswu_ro_info),
    CCH2C_TEST(cch2c_p521_sha512_sswu_ro_info),
    CCH2C_TEST(cch2c_p256_sha256_sae_compat_info),
};

static double perf_cch2c(size_t loops, size_t *psize, const void *arg)
{
    const struct cch2c_perf_test *test = arg;
    unsigned char *data = malloc(*psize);
    uint8_t dst[24];

    ccec_const_cp_t cp = test->info->curve_params();
    ccec_pub_ctx_decl_cp(cp, R);

    perf_start();
    do {
        int status = cch2c(test->info, sizeof(dst), dst, sizeof(data), data, R);
        if (status) {
            abort();
        }
    } while (--loops != 0);

    double seconds = perf_seconds();
    free(data);
    return seconds;
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cch2c(int argc, char *argv[])
{
    F_GET_ALL(family, cch2c);
    F_SIZE(family, CCH2C_MAX_DATA_NBYTES);
    family.size_kind = ccperf_size_bytes;
    return &family;
}
