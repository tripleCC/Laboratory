/* Copyright (c) (2018-2020,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccscrypt.h>

static double perf_ccscrypt_test(size_t loops, cc_size nbits)
{
    double t;

    const uint64_t N = nbits;
    const uint32_t r = 8;
    const uint32_t p = 1;

    uint8_t pwd[] = "pleaseletmein";

    uint8_t salt[16];
    ccrng_generate(rng, sizeof(salt), salt);

    int64_t storage_size = ccscrypt_storage_size(N, r, p);
    if (storage_size <= 0) {
        abort();
    }

    uint32_t buffer_size = (uint32_t)storage_size;
    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if (!buffer) {
        abort();
    }

    memset(buffer, 0, buffer_size);
    uint8_t out[64];

    perf_start();
    do {
        if (ccscrypt(sizeof(pwd), pwd, sizeof(salt), salt, buffer, N, r, p, sizeof(out), out)) {
            abort();
        }
    } while (--loops != 0);

    t = perf_seconds();
    free(buffer);
    return t;
}

#define _TEST(_x)                      \
    {                                  \
        .name = #_x, .func = perf_##_x \
    }
static struct ccscrypt_perf_test {
    const char *name;
    double (*func)(size_t loops, cc_size nbits);
} ccscrypt_perf_tests[] = {
    _TEST(ccscrypt_test),
};

static double perf_ccscrypt(size_t loops, size_t *psize, const void *arg)
{
    const struct ccscrypt_perf_test *test = arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccscrypt(int argc, char *argv[])
{
    F_GET_ALL(family, ccscrypt);
    static const size_t group_nbits[] = {
        1 << 13,
        1 << 14,
        1 << 15,
#if !(TARGET_OS_WATCH || CC_BRIDGE)
        1 << 16,
        1 << 17,
        1 << 18,
#endif
    };
    F_SIZES_FROM_ARRAY(family, group_nbits);
    family.size_kind = ccperf_size_bits;
    return &family;
}
