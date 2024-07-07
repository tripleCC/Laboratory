/* Copyright (c) (2016-2020,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

static struct ccpoly_perf_test {
    const char *name;
} ccpoly_perf_tests[] = {
    {"ccpoly1305_info_default"}
};

static double perf_ccpoly_init(size_t loops, size_t *psize CC_UNUSED, const void *test CC_UNUSED)
{
    ccpoly1305_ctx ctx;

    uint8_t key[32];
    cc_clear(32,key);

    perf_start();
    while(loops--)
        ccpoly1305_init(&ctx, key);

    return perf_seconds();
}

static double perf_ccpoly_update(size_t loops, size_t *psize, const void *test CC_UNUSED)
{
    ccpoly1305_ctx ctx;

    uint8_t key[32];
    cc_clear(32,key);

    unsigned char *temp = malloc(*psize);
    memset(temp, 0, *psize);

    ccpoly1305_init(&ctx, key);

    perf_start();
    while(loops--)
        ccpoly1305_update(&ctx, *psize, temp);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_ccpoly_one_shot(size_t loops, size_t *psize, const void *test CC_UNUSED)
{
    uint8_t key[32];
    cc_clear(32,key);

    uint8_t mac[16];
    unsigned char *temp = malloc(*psize);

    perf_start();
    while(loops--)
        ccpoly1305(key, *psize, temp, mac);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static void ccperf_family_ccpoly_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
}

F_DEFINE(ccpoly, init, ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccpoly, update, ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccpoly, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
