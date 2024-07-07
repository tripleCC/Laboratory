/* Copyright (c) (2016-2019,2023) Apple Inc. All rights reserved.
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

static struct ccchacha_perf_test {
    const char *name;
} ccchacha_perf_tests[] = {
    {"ccchacha20_info_default"}
};

static double perf_ccchacha_init(size_t loops, size_t *psize CC_UNUSED, const void *test CC_UNUSED)
{
    ccchacha20_ctx		ctx;

    uint8_t key[32];
    cc_clear(32,key);

    uint8_t nonce[12];
    cc_clear(12,nonce);

    uint32_t counter = 0;

    perf_start();
    while (loops--) {
        ccchacha20_init(&ctx, key);
        ccchacha20_setnonce(&ctx, nonce);
        ccchacha20_setcounter(&ctx, counter);
    }

    return perf_seconds();
}

static double perf_ccchacha_update(size_t loops, size_t *psize, const void *test CC_UNUSED)
{
    ccchacha20_ctx		ctx;

    uint8_t key[32];
    cc_clear(32,key);

    uint8_t nonce[12];
    cc_clear(12,nonce);

    uint32_t counter = 0;

    unsigned char *temp = malloc(*psize);
    
    ccchacha20_init(&ctx, key);
    ccchacha20_setnonce(&ctx, nonce);
    ccchacha20_setcounter(&ctx, counter);

    perf_start();
    while(loops--)
        ccchacha20_update(&ctx, *psize, temp, temp);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_ccchacha_one_shot(size_t loops, size_t *psize, const void *test CC_UNUSED)
{
    uint8_t key[32];
    cc_clear(32,key);

    uint8_t nonce[12];
    cc_clear(12,nonce);

    uint32_t counter = 0;

    unsigned char *temp = malloc(*psize);

    perf_start();
    while(loops--)
        ccchacha20(key, nonce, counter, *psize, temp, temp);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static void ccperf_family_ccchacha_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
}

F_DEFINE(ccchacha, init, ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccchacha, update, ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccchacha, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
