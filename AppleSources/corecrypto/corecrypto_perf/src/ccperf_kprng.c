/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc.h>

#include "cckprng_internal.h"
#include "ccperf.h"

/*
void cckprng_init(struct cckprng_ctx *ctx,
size_t seed_nbytes,
const void *seed,
size_t nonce_nbytes,
const void *nonce,
cckprng_getentropy getentropy,
void *getentropy_arg)
*/

static int32_t perf_getentropy(size_t *entropy_nbytes, void *entropy, void *arg)
{
    (void) arg;
    memset(entropy, 0xaa, *entropy_nbytes);
    return 1024; // Enough samples to initializei
}


static double perf_cckprng_init(size_t loops, size_t *nbytes, CC_UNUSED const void *arg)
{
    uint8_t seed[*nbytes];
    memset(seed, 0x00, *nbytes);
    uint8_t nonce[32] = {0};
    struct cckprng_ctx ctx;

    perf_start();
    
    do {
        cckprng_init(&ctx, *nbytes, seed, sizeof(nonce), nonce, perf_getentropy, NULL);
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cckprng_generate(size_t loops, size_t *nbytes, CC_UNUSED const void *arg)
{
    uint8_t rand[64];
    uint8_t seed[*nbytes];
    memset(seed, 0x00, *nbytes);
    uint8_t nonce[32] = {0};
    struct cckprng_ctx ctx;

    cckprng_init(&ctx, *nbytes, seed, sizeof(nonce), nonce, perf_getentropy, NULL);
    cckprng_refresh(&ctx);

    perf_start();

    do {
        cckprng_generate(&ctx, 0, sizeof(rand), rand);
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cckprng_reseed(size_t loops, size_t *nbytes, CC_UNUSED const void *arg)
{
    uint8_t seed[*nbytes];
    memset(seed, 0x00, *nbytes);
    uint8_t nonce[32] = {0};
    struct cckprng_ctx ctx;
    
    cckprng_init(&ctx, *nbytes, seed, sizeof(nonce), nonce, perf_getentropy, NULL);
    cckprng_refresh(&ctx);

    perf_start();

    do {
        cckprng_reseed(&ctx, sizeof(seed), seed);
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cckprng_refresh(size_t loops, size_t *nbytes, CC_UNUSED const void *arg)
{
    uint8_t seed[*nbytes];
    memset(seed, 0x00, *nbytes);
    uint8_t nonce[32] = {0};
    struct cckprng_ctx ctx;
    
    cckprng_init(&ctx, *nbytes, seed, sizeof(nonce), nonce, perf_getentropy, NULL);
    cckprng_refresh(&ctx);

    perf_start();

    do {
        cckprng_refresh(&ctx);
    } while (--loops != 0);

    return perf_seconds();
}

static struct ccperf_test cckprng_perf_tests[1] = { { .name = "cckprng_default" } };

static const size_t sizes[] = { 16, 32, 64, 128, 256 };

static void ccperf_family_cckprng_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
}

F_DEFINE_SIZE_ARRAY(cckprng, init, ccperf_size_bytes, sizes)
F_DEFINE_SIZE_ARRAY(cckprng, generate, ccperf_size_bytes, sizes)
F_DEFINE_SIZE_ARRAY(cckprng, reseed, ccperf_size_bytes, sizes)
F_DEFINE_SIZE_ARRAY(cckprng, refresh, ccperf_size_bytes, sizes)
