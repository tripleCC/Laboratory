/* Copyright (c) (2018-2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdatomic.h>

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccaes.h>

#include "cc_memory.h"
#include "cckprng_internal.h"
#include "ccrng_crypto.h"

static int32_t cckprng_getentropy_internal(size_t *entropy_nbytes,
                                           void *entropy,
                                           void *arg)
{
    struct cckprng_ctx *ctx = arg;

    // We don't have a dedicated lock to protect the
    // ctx->first_entropy_seed.done flag, but this function is the
    // only place it is read or written, and we are only called from
    // within Fortuna.
    CC_LOCK_ASSERT(&ctx->fortuna_ctx.lock);

    int32_t nsamples = ctx->getentropy(entropy_nbytes, entropy, ctx->getentropy_arg);

    if (CC_UNLIKELY(nsamples < 0)) {
        ccentropy_reset(&ctx->first_entropy_seed.entropy_ctx.entropy_ctx);
        ctx->first_entropy_seed.done = false;
        goto out;
    }

    if (CC_LIKELY(ctx->first_entropy_seed.done)) {
        goto out;
    }

    bool seed_ready;
    int err = ccentropy_add_entropy(&ctx->first_entropy_seed.entropy_ctx.entropy_ctx,
                                    (uint32_t)nsamples,
                                    *entropy_nbytes,
                                    entropy,
                                    &seed_ready);
    cc_abort_if(err != CCERR_OK, "ccentropy_add_entropy");

    if (seed_ready) {
        ctx->first_entropy_seed.done = true;
        ccrng_schedule_atomic_flag_set(&ctx->schedule_ctx);
    }

    nsamples = 0;
    cc_clear(*entropy_nbytes, entropy);

 out:
    return nsamples;
}

void cckprng_init(struct cckprng_ctx *ctx,
                  size_t seed_nbytes,
                  const void *seed,
                  size_t nonce_nbytes,
                  const void *nonce,
                  cckprng_getentropy getentropy,
                  void *getentropy_arg)
{
    cc_clear(sizeof(*ctx), ctx);

    ctx->getentropy = getentropy;
    ctx->getentropy_arg = getentropy_arg;

    ccrng_fortuna_init(&ctx->fortuna_ctx, cckprng_getentropy_internal, ctx);

    ccrng_schedule_atomic_flag_init(&ctx->schedule_ctx);

    int err = cc_lock_init(&ctx->lock_ctx, "corecrypto kext rng");
    cc_abort_if(err != CCERR_OK, "cc_lock_init");

    ctx->first_entropy_seed.done = false;

    // Assume one bit per interrupt timing sample.
    err = ccentropy_digest_init(&ctx->first_entropy_seed.entropy_digest_ctx,
                                ccsha512_di(),
                                CCSHA512_OUTPUT_SIZE * 8);
    cc_abort_if(err != CCERR_OK, "ccentropy_digest_init");

    err = cc_lock_init(&ctx->first_entropy_seed.lock_ctx,
                       "corecrypto kext first entropy seed");
    cc_abort_if(err != CCERR_OK, "cc_lock_init");

    err = ccentropy_lock_init(&ctx->first_entropy_seed.entropy_ctx,
                              &ctx->first_entropy_seed.entropy_digest_ctx.entropy_ctx,
                              &ctx->first_entropy_seed.lock_ctx);
    cc_abort_if(err != CCERR_OK, "ccentropy_lock_init");

    err = ccentropy_rng_init(&ctx->entropy_rng_ctx,
                             (struct ccrng_state *)&ctx->fortuna_ctx);
    cc_abort_if(err != CCERR_OK, "ccentropy_rng_init");

    ctx->entropy_list[0] = &ctx->first_entropy_seed.entropy_ctx.entropy_ctx;
    ctx->entropy_list[1] = &ctx->entropy_rng_ctx.entropy_ctx;

    err = ccentropy_list_init(&ctx->entropy_ctx,
                              CC_ARRAY_LEN(ctx->entropy_list),
                              ctx->entropy_list);
    cc_abort_if(err != CCERR_OK, "ccentropy_list_init");

    err = ccdrbg_df_bc_init(&ctx->drbg_df_ctx,
                            ccaes_cbc_encrypt_mode(),
                            32);
    cc_abort_if(err != CCERR_OK, "ccdrbg_df_bc_init");

    struct ccdrbg_nistctr_custom drbg_custom = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 32,
        .strictFIPS = 1,
        .df_ctx = &ctx->drbg_df_ctx.df_ctx,
    };
    ccdrbg_factory_nistctr(&ctx->drbg_info, &drbg_custom);

    struct ccdrbg_state *drbg_ctx = (struct ccdrbg_state *)&ctx->drbg_state;

    const uint8_t ps[] = CCKPRNG_LABEL(CCKPRNG_OP_INIT_RNG);
    err = ccdrbg_init(&ctx->drbg_info,
                      drbg_ctx,
                      seed_nbytes,
                      seed,
                      nonce_nbytes,
                      nonce,
                      sizeof(ps),
                      ps);
    cc_abort_if(err != CCERR_OK, "Failure to instantiate drbg");

    err = ccrng_crypto_init(&ctx->rng_ctx,
                            (ccentropy_ctx_t *)&ctx->entropy_ctx,
                            (ccrng_schedule_ctx_t *)&ctx->schedule_ctx,
                            &ctx->lock_ctx,
                            &ctx->drbg_info,
                            drbg_ctx,
                            CCKPRNG_MAX_REQUEST_SIZE,
                            CCKPRNG_ENTROPY_SIZE,
                            sizeof(ctx->cache),
                            (uint8_t *)&ctx->cache);
    cc_abort_if(err != CCERR_OK, "Failure to initialize ccrng_crypto");
}

void cckprng_init_with_getentropy(struct cckprng_ctx *ctx,
                                  CC_UNUSED unsigned max_ngens,
                                  size_t seed_nbytes,
                                  const void *seed,
                                  size_t nonce_nbytes,
                                  const void *nonce,
                                  cckprng_getentropy getentropy,
                                  void *getentropy_arg)

{
    cckprng_init(ctx, seed_nbytes, seed, nonce_nbytes, nonce, getentropy, getentropy_arg);
}
