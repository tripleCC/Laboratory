/* Copyright (c) (2020-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "crypto_test_rng.h"
#include "cc_debug.h"
#include "ccrng_crypto.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>
#include "cc_absolute_time.h"
#include "testmore.h"
#include "cc_priv.h"
#include "ccrng_sequence.h"
#include <corecrypto/ccdrbg.h>
#include <limits.h>

static void
crypto_rng_test_config(void)
{
    // Configuring the RNG with an out-of-range seed size is an error
    int err = ccrng_crypto_init(NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                0,
                                CCRNG_CRYPTO_SEED_MAX_NBYTES + 1,
                                0,
                                NULL);
    is(err, CCERR_CRYPTO_CONFIG, "ccrng_crypto_init (seed max nbytes)");
}

static int
generate_out_of_entropy(CC_UNUSED struct ccrng_state *rng,
                        CC_UNUSED size_t nbytes,
                        CC_UNUSED void *out)
{
    return CCERR_OUT_OF_ENTROPY;
}

static void
crypto_rng_test_out_of_entropy(void)
{
    struct ccrng_state rng_out_of_entropy = {
        .generate = generate_out_of_entropy
    };
    ccentropy_rng_ctx_t entropy_ctx;
    ccentropy_rng_init(&entropy_ctx,
                       (struct ccrng_state *)&rng_out_of_entropy);

    ccrng_schedule_constant_ctx_t schedule_try_reseed_ctx;
    ccrng_schedule_constant_ctx_t schedule_must_reseed_ctx;
    ccrng_schedule_constant_ctx_t schedule_invalid_ctx;

    ccrng_schedule_constant_init(&schedule_try_reseed_ctx,
                                 CCRNG_SCHEDULE_TRY_RESEED);
    ccrng_schedule_constant_init(&schedule_must_reseed_ctx,
                                 CCRNG_SCHEDULE_MUST_RESEED);
    ccrng_schedule_constant_init(&schedule_invalid_ctx,
                                 0);

    const struct ccdigest_info *di = ccsha256_di();
    struct ccdrbg_nisthmac_custom drbg_custom;
    drbg_custom.di = di;
    drbg_custom.strictFIPS = 1;
    struct ccdrbg_info drbg_info;
    ccdrbg_factory_nisthmac(&drbg_info, &drbg_custom);

    uint8_t drbg_state[1280];
    struct ccdrbg_state *drbg_ctx = (struct ccdrbg_state *)&drbg_state;

    uint8_t zero[32] = { 0 };

    int err;

    err = ccdrbg_init(&drbg_info,
                      drbg_ctx,
                      sizeof(zero),
                      zero,
                      0,
                      NULL,
                      0,
                      NULL);
    is(err, CCERR_OK, "crypto_rng_test_out_of_entropy ccdrbg_init");

    uint8_t random[32];

    ccrng_crypto_ctx_t rng_ctx;

    // If the entropy source returns "out of entropy" after a "try
    // reseed" recommendation, we continue to generate random
    err = ccrng_crypto_init(&rng_ctx,
                            &entropy_ctx.entropy_ctx,
                            &schedule_try_reseed_ctx.schedule_ctx,
                            NULL,
                            &drbg_info,
                            drbg_ctx,
                            256,
                            sizeof(zero),
                            0,
                            NULL);
    is(err, CCERR_OK, "crypto_rng_test_out_of_entropy schedule_try_reseed_ctx ccrng_crypto_init");

    cc_clear(sizeof(random), random);
    err = ccrng_generate(&rng_ctx, sizeof(random), random);
    is(err, CCERR_OK, "crypto_rng_test_out_of_entropy schedule_try_reseed_ctx ccrng_generate");
    ok_notmemcmp(random, zero, sizeof(random), "crypto_rng_test_out_of_entropy schedule_try_reseed_ctx memcmp");

    // If the entropy source returns "out of entropy" after a "must
    // reseed" recommendation, we stop and return an error
    err = ccrng_crypto_init(&rng_ctx,
                            &entropy_ctx.entropy_ctx,
                            &schedule_must_reseed_ctx.schedule_ctx,
                            NULL,
                            &drbg_info,
                            drbg_ctx,
                            256,
                            sizeof(zero),
                            0,
                            NULL);
    is(err, CCERR_OK, "crypto_rng_test_out_of_entropy schedule_must_reseed_ctx ccrng_crypto_init");

    cc_clear(sizeof(random), random);
    err = ccrng_generate(&rng_ctx, sizeof(random), random);
    is(err, CCERR_RNG_NOT_SEEDED, "crypto_rng_test_out_of_entropy schedule_must_reseed_ctx ccrng_generate");
    ok_memcmp(random, zero, sizeof(random), "crypto_rng_test_out_of_entropy schedule_must_reseed_ctx memcmp");

    // If the entropy source returns "out of entropy" after an invalid
    // recommendation, we stop and return an error
    err = ccrng_crypto_init(&rng_ctx,
                            &entropy_ctx.entropy_ctx,
                            &schedule_invalid_ctx.schedule_ctx,
                            NULL,
                            &drbg_info,
                            drbg_ctx,
                            256,
                            sizeof(zero),
                            0,
                            NULL);
    is(err, CCERR_OK, "crypto_rng_test_out_of_entropy schedule_invalid_ctx ccrng_crypto_init");

    cc_clear(sizeof(random), random);
    err = ccrng_generate(&rng_ctx, sizeof(random), random);
    is(err, CCERR_INTERNAL, "crypto_rng_test_out_of_entropy schedule_invalid_ctx ccrng_generate");
    ok_memcmp(random, zero, sizeof(random), "crypto_rng_test_out_of_entropy schedule_invalid_ctx memcmp");
}

// Enable timers if the platform allows it
#define CCRNG_CRYPTO_TEST_TIMER_ENABLED !(CC_LINUX)
#if CCRNG_CRYPTO_TEST_TIMER_ENABLED
#if CC_KERNEL
#include <kern/clock.h>
static uint64_t cc_uptime_nsec(void)
{
    clock_sec_t sec;
    clock_usec_t usec;
    clock_get_calendar_microtime(&sec, &usec);
    return (sec * CC_NSEC_PER_SEC) + (usec * CC_NSEC_PER_USEC);
}
#else

static uint64_t cc_uptime_nsec(void)
{
    return cc_absolute_time_to_nsec(cc_absolute_time());
}
#endif
#endif /* CCRNG_CRYPTO_TIMER_ENABLED */

#define CCRNG_CRYPTO_TEST_TIMER_NSEC (5 * CC_NSEC_PER_SEC)
#define CCRNG_CRYPTO_TEST_SLEEP_SEC (2 * CCRNG_CRYPTO_TEST_TIMER_NSEC / CC_NSEC_PER_SEC)
#if defined(_WIN32)
#include <windows.h>
static void sleep_some() {
    Sleep(1000 * CCRNG_CRYPTO_TEST_SLEEP_SEC);
}
#else
#include <unistd.h>
static void sleep_some(void) {
    sleep(CCRNG_CRYPTO_TEST_SLEEP_SEC);
}
#endif

struct ccrng_crypto_hmac_drbg_test_vector {
    unsigned tcId;
    const struct ccdigest_info *(*di)(void);
    const uint8_t *init_seed;
    size_t init_seed_len;
    const uint8_t *init_nonce;
    size_t init_nonce_len;
    const uint8_t *init_ps;
    size_t init_ps_len;
    const uint8_t *gen1;
    size_t gen1_len;
    size_t ngens; // Number of generations
    const uint8_t *genn;
    size_t genn_len;
    const uint8_t *reseed_nonce;
    size_t reseed_nonce_len;
    const uint8_t *gen_after_reseed;
    size_t gen_after_reseed_len;
};
#include "../test_vectors/ccrng_crypto_hmac_tvs.kat"
#include "../test_vectors/ccrng_crypto_hmac_always_reseed_tvs.kat"
#include "../test_vectors/ccrng_crypto_hmac_timer_tvs.kat"

static bool crypto_rng_test_one(const struct ccrng_crypto_hmac_drbg_test_vector *tv,
                                ccrng_crypto_ctx_t *rng_ctx,
                                ccentropy_ctx_t *entropy_ctx,
                                ccrng_schedule_ctx_t *schedule_ctx,
                                const struct ccdrbg_info *drbg_info,
                                bool use_sleep)
{
    int err = 0;
    uint8_t gen1[tv->gen1_len];
    uint8_t genn[tv->genn_len];
    uint8_t gen_final[tv->gen_after_reseed_len];

    uint8_t cache[256];

    uint8_t drbg_state[1280];
    struct ccdrbg_state *drbg_ctx = (struct ccdrbg_state *)&drbg_state;

    err = ccdrbg_init(drbg_info,
                      drbg_ctx,
                      tv->init_seed_len,
                      tv->init_seed,
                      tv->init_nonce_len,
                      tv->init_nonce,
                      tv->init_ps_len,
                      tv->init_ps);
    if (err != CCERR_OK) {
        diag("ccdrbg init failure");
        return false;
    }

    err = ccrng_crypto_init(rng_ctx,
                            entropy_ctx,
                            schedule_ctx,
                            NULL,
                            drbg_info,
                            drbg_ctx,
                            256,
                            64,
                            sizeof(cache),
                            cache);
    if (err != CCERR_OK) {
        diag("ccrng_crypto init failure");
        return false;
    }

    err = ccrng_generate(rng_ctx, tv->gen1_len, gen1);
    //cc_printf("First GEN end...\n");
    if (err != CCERR_OK) {
        diag("ccrng_crypto generate failure");
        return false;
    }

    if (memcmp(gen1, tv->gen1, tv->gen1_len) != 0) {
        diag("ccrng_crypto gen1 failure");
        return false;
    }

    for (size_t n = 0; n <= tv->ngens; n++) {
        err = ccrng_generate(rng_ctx, tv->genn_len, genn);
        if (err != CCERR_OK) {
            diag("ccrng_crypto generate failure");
            return false;
        }
    }

    if (memcmp(genn, tv->genn, tv->genn_len) != 0) {
        diag("ccrng_crypto genn failure");
        return false;
    }

    if (use_sleep && CCRNG_CRYPTO_TEST_TIMER_ENABLED) {
        diag("Sleeping for %d seconds", CCRNG_CRYPTO_TEST_SLEEP_SEC);
        sleep_some();
        diag("Sleep complete\n");
    } else {
        uint8_t seed[64];
        ccentropy_get_seed(entropy_ctx, sizeof(seed), seed);
        err = ccrng_crypto_reseed(rng_ctx,
                                  sizeof(seed),
                                  seed,
                                  tv->reseed_nonce_len,
                                  tv->reseed_nonce);
        if (err != CCERR_OK) {
            diag("ccrng_crypto_reseed failure");
            return false;
        }
    }

    err = ccrng_generate(rng_ctx, tv->gen_after_reseed_len, gen_final);
    if (err != CCERR_OK) {
        diag("ccrng_crypto generate failure");
        return false;
    }

    ok_memcmp(gen_final, tv->gen_after_reseed, tv->gen_after_reseed_len, "GEN FINAL");

    if (memcmp(gen_final, tv->gen_after_reseed, tv->gen_after_reseed_len) != 0) {
        diag("ccrng_crypto gen_final failure");
        return false;
    }

    return true;

}

static bool crypto_rng_test_one_normal(const struct ccrng_crypto_hmac_drbg_test_vector *tv, bool use_sleep)
{
    struct ccrng_sequence_state entropy_rng_ctx;
    uint8_t entropy = 1;
    ccrng_sequence_init(&entropy_rng_ctx, sizeof(entropy), &entropy);

    ccentropy_rng_ctx_t entropy_ctx;
    ccentropy_rng_init(&entropy_ctx,
                       (struct ccrng_state *)&entropy_rng_ctx);

#if CCRNG_CRYPTO_TEST_TIMER_ENABLED
    ccrng_schedule_timer_ctx_t schedule_ctx;
    ccrng_schedule_timer_init(&schedule_ctx,
                              cc_uptime_nsec,
                              CCRNG_CRYPTO_TEST_TIMER_NSEC);
#else
    ccrng_schedule_constant_ctx_t schedule_ctx;
    ccrng_schedule_constant_init(&schedule_ctx,
                                 CCRNG_SCHEDULE_CONTINUE);
#endif

    ccrng_crypto_ctx_t rng_ctx;

    const struct ccdigest_info *di = tv->di();
    struct ccdrbg_nisthmac_custom drbg_custom;
    drbg_custom.di = di;
    drbg_custom.strictFIPS = 1;
    struct ccdrbg_info drbg_info;
    ccdrbg_factory_nisthmac(&drbg_info, &drbg_custom);

    return crypto_rng_test_one(tv,
                               &rng_ctx,
                               (ccentropy_ctx_t *)&entropy_ctx,
                               (ccrng_schedule_ctx_t *)&schedule_ctx,
                               &drbg_info,
                               use_sleep);
}

static int reseed_count = 0;
static ccrng_schedule_action_t
ccrng_crypto_test_schedule_read(CC_UNUSED ccrng_schedule_ctx_t *schedule_ctx) {
    return CCRNG_SCHEDULE_MUST_RESEED;
}

static void
ccrng_crypto_test_schedule_notify_reseed(CC_UNUSED ccrng_schedule_ctx_t *schedule_ctx) {
    reseed_count += 1;
}

static const ccrng_schedule_info_t
ccrng_crypto_test_schedule_info = {
    .read = ccrng_crypto_test_schedule_read,
    .notify_reseed = ccrng_crypto_test_schedule_notify_reseed,
};

static bool crypto_rng_test_one_aggressive(const struct ccrng_crypto_hmac_drbg_test_vector *tv, bool use_sleep)
{
    struct ccrng_sequence_state entropy_rng_ctx;
    uint8_t entropy = 1;
    ccrng_sequence_init(&entropy_rng_ctx, sizeof(entropy), &entropy);

    ccentropy_rng_ctx_t entropy_ctx;
    ccentropy_rng_init(&entropy_ctx,
                       (struct ccrng_state *)&entropy_rng_ctx);

    ccrng_schedule_ctx_t schedule_ctx = {
        .info = &ccrng_crypto_test_schedule_info,
    };

    ccrng_crypto_ctx_t rng_ctx;

    const struct ccdigest_info *di = tv->di();
    struct ccdrbg_nisthmac_custom drbg_custom;
    drbg_custom.di = di;
    drbg_custom.strictFIPS = 1;
    struct ccdrbg_info drbg_info;
    ccdrbg_factory_nisthmac(&drbg_info, &drbg_custom);

    return crypto_rng_test_one(tv,
                               &rng_ctx,
                               (ccentropy_ctx_t *)&entropy_ctx,
                               &schedule_ctx,
                               &drbg_info,
                               use_sleep);
}

#if CC_TSAN
#include <pthread.h>

static ccrng_crypto_ctx_t tsan_rng_ctx;

static void *ccrng_tsan_thread_generate(void *arg)
{
    (void) arg;
    uint8_t generate[32] = {0};
    for (int i = 0; i < 10000; i++) {
        ccrng_generate(&tsan_rng_ctx, sizeof(generate), generate);
    }
    return NULL;
}

static void *ccrng_tsan_thread_reseed(void *arg)
{
    (void) arg;
    uint8_t seed[64] = { 0 };
    uint8_t nonce[8] = { 0 };
    for (int i = 0; i < 10000; i++) {
        ccrng_crypto_reseed(&tsan_rng_ctx, sizeof(seed), seed, sizeof(nonce), nonce);
    }
    return NULL;
}

static int crypto_rng_tsan_test()
{
    struct ccrng_sequence_state entropy_rng_ctx;
    uint8_t entropy = 0;
    int err = ccrng_sequence_init(&entropy_rng_ctx,
                                  sizeof(entropy),
                                  &entropy);

    ccentropy_rng_ctx_t entropy_ctx;
    err = ccentropy_rng_init(&entropy_ctx,
                             (struct ccrng_state *)&entropy_rng_ctx,
                             UINT_MAX);

    ccrng_schedule_constant_ctx_t schedule_ctx;
    ccrng_schedule_constant_init(&schedule_ctx, CCRNG_SCHEDULE_MUST_RESEED);

    cc_lock_ctx_t lock_ctx;
    err = cc_lock_init(&lock_ctx, "crypto_rng_tsan_lock");

    struct ccdrbg_nisthmac_custom drbg_custom;
    drbg_custom.di = ccsha256_di();
    drbg_custom.strictFIPS = 1;
    struct ccdrbg_info drbg_info;
    ccdrbg_factory_nisthmac(&drbg_info, &drbg_custom);

    uint8_t drbg_buf[drbg_info.size];
    struct ccdrbg_state *drbg_ctx = (struct ccdrbg_state *)drbg_buf;

    uint8_t seed[64] = { 0 };
    uint8_t nonce[32] = { 0 };
    uint8_t ps[8] = { 0 };

    err = ccdrbg_init(&drbg_info,
                      drbg_ctx,
                      sizeof(seed), seed,
                      sizeof(nonce), nonce,
                      sizeof(ps), ps);

    err = ccrng_crypto_init(&tsan_rng_ctx,
                            (ccentropy_ctx_t *)&entropy_ctx,
                            (ccrng_schedule_ctx_t *)&schedule_ctx,
                            &lock_ctx,
                            &drbg_info,
                            drbg_ctx,
                            1024,
                            sizeof(seed),
                            0,
                            NULL);

    pthread_t t_generate, t_reseed;

    pthread_create(&t_generate, NULL, ccrng_tsan_thread_generate, NULL);
    pthread_create(&t_reseed, NULL, ccrng_tsan_thread_reseed, NULL);

    pthread_join(t_generate, NULL);
    pthread_join(t_reseed, NULL);

    return 0;
}

#endif

int crypto_rng_test_kat(void) {
    diag("Starting cryptographic RNG KAT Tests");

    diag("\tNormal KAT Tests");
    size_t nvectors = CC_ARRAY_LEN(ccrng_crypto_hmac_tvs);
    for (size_t i = 0; i < nvectors; i++)
    {
        const struct ccrng_crypto_hmac_drbg_test_vector *tv = ccrng_crypto_hmac_tvs[i];
        bool result = crypto_rng_test_one_normal(tv, false);
        is(result, true, "Failed crypto rng kat test vector %d\n", tv->tcId);
    }

    diag("\tAggressive Reseeding KAT Tests");
    nvectors = CC_ARRAY_LEN(ccrng_crypto_hmac_always_reseed_tvs);
    int expected_reseed_count = 0;
    for (size_t i = 0; i < nvectors; i++)
    {
        const struct ccrng_crypto_hmac_drbg_test_vector *tv = ccrng_crypto_hmac_always_reseed_tvs[i];
        expected_reseed_count += (3 + tv->ngens);
        bool result = crypto_rng_test_one_aggressive(tv, false);
        is(result, true, "Failed aggressive reseed crypto rng kat test vector %d\n", tv->tcId);
    }
    ok(expected_reseed_count == reseed_count, "Not reseeding properly");

    diag("\tTimer Based Reseeding KAT Tests");
    cc_assert(CC_ARRAY_LEN(ccrng_crypto_hmac_timer_tvs) == 1);
    const struct ccrng_crypto_hmac_drbg_test_vector *tv = ccrng_crypto_hmac_timer_tvs[0];
    bool result = crypto_rng_test_one_normal(tv, true);
    is(result, true, "Failed crypto rng kat test vector %d\n", tv->tcId);

    diag("Finished cryptographic RNG KAT Tests");

    diag("Starting cryptographic RNG Negative Tests");
    crypto_rng_test_config();
    crypto_rng_test_out_of_entropy();
    diag("Finished cryptographic RNG Negative Tests");

    int ret = 0;
#if CC_TSAN
    diag("Starting cryptographic RNG TSAN Tests");
    ret = crypto_rng_tsan_test();
    diag("Finished cryptographic RNG TSAN Tests");
#endif
    return ret;
}
