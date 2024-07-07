/* Copyright (c) (2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include "cc_internal.h"
#include "cc_absolute_time.h"
#include "ccrng_process.h"

static int
generate(struct ccrng_state *ctx,
         size_t nbytes,
         void *rand)
{
    ccrng_process_ctx_t *rng_process_ctx = (ccrng_process_ctx_t *)ctx;
    return ccrng_generate(&rng_process_ctx->rng_ctx, nbytes, rand);
}

int
ccrng_process_init(ccrng_process_ctx_t *ctx,
                   uint64_t (*get_time_nsec)(void),
                   struct ccrng_state *entropy_rng_ctx)
{
    ccrng_schedule_timer_init(&ctx->schedule_timer_ctx,
                              get_time_nsec,
                              CCRNG_PROCESS_RESEED_PERIOD_NSEC);
    ccrng_schedule_atomic_flag_init(&ctx->schedule_flag_ctx);
    ccrng_schedule_tree_init(&ctx->schedule_ctx,
                             &ctx->schedule_timer_ctx.schedule_ctx,
                             &ctx->schedule_flag_ctx.schedule_ctx);

    int err = cc_lock_init(&ctx->lock_ctx, "corecrypto process rng");
    cc_require(err == CCERR_OK, out);

    err = ccentropy_rng_init(&ctx->entropy_ctx,
                             entropy_rng_ctx);
    cc_require(err == CCERR_OK, out);

    err = ccdrbg_df_bc_init(&ctx->df_ctx,
                            ccaes_cbc_encrypt_mode(),
                            CCRNG_PROCESS_SEED_NBYTES);
    cc_require(err == CCERR_OK, out);

    struct ccdrbg_nistctr_custom drbg_custom = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = CCRNG_PROCESS_SEED_NBYTES,
        .strictFIPS = 1,
        .df_ctx = &ctx->df_ctx.df_ctx,
    };
    ccdrbg_factory_nistctr(&ctx->drbg_info, &drbg_custom);

    struct ccdrbg_state *drbg_ctx = (struct ccdrbg_state *)&ctx->drbg_state;

    uint8_t seed[CCRNG_PROCESS_SEED_NBYTES];
    err = ccrng_generate(entropy_rng_ctx, sizeof(seed), seed);
    cc_require(err == CCERR_OK, out);

    uint64_t nonce = get_time_nsec();
    const char ps[] = "corecrypto process rng";
    err = ccdrbg_init(&ctx->drbg_info,
                      drbg_ctx,
                      sizeof(seed),
                      seed,
                      sizeof(nonce),
                      &nonce,
                      sizeof(ps) - 1,
                      ps);
    cc_require(err == CCERR_OK, out);

    err = ccrng_crypto_init(&ctx->rng_ctx,
                            (ccentropy_ctx_t *)&ctx->entropy_ctx,
                            (ccrng_schedule_ctx_t *)&ctx->schedule_ctx,
                            &ctx->lock_ctx,
                            &ctx->drbg_info,
                            drbg_ctx,
                            CCRNG_PROCESS_MAX_REQUEST_NBYTES,
                            CCRNG_PROCESS_SEED_NBYTES,
                            sizeof(ctx->cache),
                            (uint8_t *)&ctx->cache);
    cc_require(err == CCERR_OK, out);

    ctx->generate = generate;

 out:
    return err;
}

int ccrng_process_atfork_prepare(ccrng_process_ctx_t *ctx)
{
    CC_LOCK_LOCK(&ctx->lock_ctx);

    ccrng_schedule_atomic_flag_set(&ctx->schedule_flag_ctx);

    return CCERR_OK;
}

int ccrng_process_atfork_parent(ccrng_process_ctx_t *ctx)
{
    CC_LOCK_UNLOCK(&ctx->lock_ctx);

    return CCERR_OK;
}

int ccrng_process_atfork_child(ccrng_process_ctx_t *ctx)
{
    return cc_lock_init(&ctx->lock_ctx, "corecrypto process rng");
}
