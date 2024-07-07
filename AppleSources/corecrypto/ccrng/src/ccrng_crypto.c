/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccentropy.h>
#include <corecrypto/ccrng_schedule.h>
#include <corecrypto/ccdrbg.h>
#include "cc_lock.h"
#include "ccrng_crypto.h"
#include "ccrng_internal.h"

#define CCRNG_CRYPTO_LOCK_LOCK(lock) if (lock) CC_LOCK_LOCK(lock)
#define CCRNG_CRYPTO_LOCK_UNLOCK(lock) if (lock) CC_LOCK_UNLOCK(lock)
#define CCRNG_CRYPTO_LOCK_ASSERT(lock) if (lock) CC_LOCK_ASSERT(lock)

static int
drbg_reseed(ccrng_crypto_ctx_t *ctx,
            size_t seed_nbytes, const void *seed,
            size_t nonce_nbytes, const void *nonce)
{
    CCRNG_CRYPTO_LOCK_ASSERT(ctx->lock_ctx);

    int err = ccdrbg_reseed(ctx->drbg_info,
                            ctx->drbg_ctx,
                            seed_nbytes,
                            seed,
                            nonce_nbytes,
                            nonce);
    cc_require(err == CCERR_OK, out);

    // Reseeding the DRBG invalidates the cache.
    ctx->cache_pos = ctx->cache_nbytes;

 out:
    return err;
}

static int
maybe_reseed(ccrng_crypto_ctx_t *ctx)
{
    CCRNG_CRYPTO_LOCK_ASSERT(ctx->lock_ctx);

    int err;

    uint8_t seed[CCRNG_CRYPTO_SEED_MAX_NBYTES];
    size_t seed_nbytes = ctx->seed_nbytes;

    ccrng_schedule_action_t action = ccrng_schedule_read(ctx->schedule_ctx);
    if (action == CCRNG_SCHEDULE_CONTINUE) {
        return CCERR_OK;
    }

    err = ccentropy_get_seed(ctx->entropy_ctx, seed_nbytes, seed);
    if (err == CCERR_OUT_OF_ENTROPY) {
        switch (action) {

        case CCRNG_SCHEDULE_TRY_RESEED:
            // This is acceptable.
            return CCERR_OK;

        case CCRNG_SCHEDULE_MUST_RESEED:
            // This is catastrophic.
            return CCERR_RNG_NOT_SEEDED;

        default:
            // This is unexpected.
            return CCERR_INTERNAL;
        }
    }

    cc_require(err == CCERR_OK, out);

    err = drbg_reseed(ctx,
                      seed_nbytes,
                      seed,
                      0,
                      NULL);
    cc_require(err == CCERR_OK, out);

    ccrng_schedule_notify_reseed(ctx->schedule_ctx);

 out:
    cc_clear(seed_nbytes, seed);
    return err;
}

static int
drbg_generate(ccrng_crypto_ctx_t *ctx,
              size_t rand_nbytes, void *rand)
{
    CCRNG_CRYPTO_LOCK_ASSERT(ctx->lock_ctx);

    return ccdrbg_generate(ctx->drbg_info,
                           ctx->drbg_ctx,
                           rand_nbytes,
                           rand,
                           0,
                           NULL);
}

static int
generate_chunk(ccrng_crypto_ctx_t *ctx,
               size_t chunk_nbytes,
               uint8_t *chunk,
               bool bypass_cache)
{
    CCRNG_CRYPTO_LOCK_ASSERT(ctx->lock_ctx);

    int err = CCERR_OK;

    if (!bypass_cache && (chunk_nbytes <= ctx->cache_nbytes)) {
        uint8_t *p = ctx->cache + ctx->cache_pos;
        uint8_t *end = ctx->cache + ctx->cache_nbytes;
        size_t left = (size_t)(end - p);
        size_t take = CC_MIN(chunk_nbytes, left);

        cc_memcpy(chunk, p, take);
        cc_clear(take, p);
        ctx->cache_pos += take;
        chunk += take;
        chunk_nbytes -= take;

        if (chunk_nbytes > 0) {
            err = drbg_generate(ctx,
                                ctx->cache_nbytes,
                                ctx->cache);
            cc_require(err == CCERR_OK, out);

            cc_memcpy(chunk, ctx->cache, chunk_nbytes);
            cc_clear(chunk_nbytes, ctx->cache);
            ctx->cache_pos = chunk_nbytes;
        }
    } else {
        err = drbg_generate(ctx,
                            chunk_nbytes,
                            chunk);
    }

 out:
    return err;
}

int
ccrng_crypto_generate(ccrng_crypto_ctx_t *ctx,
                      size_t rand_nbytes,
                      void *rand)
{
    int err = CCERR_OK;

    size_t buf_nbytes = rand_nbytes;
    uint8_t *buf = rand;

    bool bypass_cache = rand_nbytes >= CCRNG_FIPS_REQUEST_SIZE_THRESHOLD;

    while (buf_nbytes > 0) {
        CCRNG_CRYPTO_LOCK_LOCK(ctx->lock_ctx);

        err = maybe_reseed(ctx);
        cc_require(err == CCERR_OK, err_out);

        size_t nbytes = CC_MIN(buf_nbytes,
                               ctx->generate_chunk_nbytes);
        err = generate_chunk(ctx, nbytes, buf, bypass_cache);
        cc_require(err == CCERR_OK, err_out);

        buf_nbytes -= nbytes;
        buf += nbytes;

        CCRNG_CRYPTO_LOCK_UNLOCK(ctx->lock_ctx);
    }

    return err;

 err_out:
    CCRNG_CRYPTO_LOCK_UNLOCK(ctx->lock_ctx);
    cc_clear(rand_nbytes, rand);
    return err;
}

int
ccrng_crypto_reseed(ccrng_crypto_ctx_t *ctx,
                    size_t seed_nbytes,
                    const void *seed,
                    size_t nonce_nbytes,
                    const void *nonce)
{
    CCRNG_CRYPTO_LOCK_LOCK(ctx->lock_ctx);

    int err = drbg_reseed(ctx,
                          seed_nbytes,
                          seed,
                          nonce_nbytes,
                          nonce);

    CCRNG_CRYPTO_LOCK_UNLOCK(ctx->lock_ctx);

    return err;
}

static int
generate(struct ccrng_state *ctx,
         size_t nbytes,
         void *rand)
{
    return ccrng_crypto_generate((ccrng_crypto_ctx_t *)ctx, nbytes, rand);
}

int
ccrng_crypto_init(ccrng_crypto_ctx_t *ctx,
                  ccentropy_ctx_t *entropy_ctx,
                  ccrng_schedule_ctx_t *schedule_ctx,
                  cc_lock_ctx_t *lock_ctx,
                  const struct ccdrbg_info *drbg_info,
                  struct ccdrbg_state *drbg_ctx,
                  size_t generate_chunk_nbytes,
                  size_t seed_nbytes,
                  size_t cache_nbytes,
                  void *cache)
{
    if (seed_nbytes > CCRNG_CRYPTO_SEED_MAX_NBYTES) {
        return CCERR_CRYPTO_CONFIG;
    }

    ctx->generate = generate;

    ctx->entropy_ctx = entropy_ctx;
    ctx->schedule_ctx = schedule_ctx;
    ctx->lock_ctx = lock_ctx;
    ctx->drbg_info = drbg_info;
    ctx->drbg_ctx = drbg_ctx;
    ctx->generate_chunk_nbytes = generate_chunk_nbytes;
    ctx->seed_nbytes = seed_nbytes;
    ctx->cache_nbytes = cache_nbytes;
    ctx->cache = cache;
    ctx->cache_pos = cache_nbytes;

    return CCERR_OK;
}
