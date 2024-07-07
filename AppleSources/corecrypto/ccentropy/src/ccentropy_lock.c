/* Copyright (c) (2023) Apple Inc. All rights reserved.
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
#include "cc_lock.h"
#include <corecrypto/ccentropy.h>

static
int ccentropy_lock_get_seed(ccentropy_ctx_t *ent_ctx,
                            size_t seed_nbytes,
                            void *seed)
{
    ccentropy_lock_ctx_t *ctx = (ccentropy_lock_ctx_t *)ent_ctx;

    CC_LOCK_LOCK(ctx->lock_ctx);

    int err = ccentropy_get_seed(ctx->inner_ctx, seed_nbytes, seed);

    CC_LOCK_UNLOCK(ctx->lock_ctx);

    return err;
}

static
int ccentropy_lock_add_entropy(ccentropy_ctx_t *ent_ctx,
                               uint32_t entropy_nsamples,
                               size_t entropy_nbytes,
                               const void *entropy,
                               bool *seed_ready)
{
    ccentropy_lock_ctx_t *ctx = (ccentropy_lock_ctx_t *)ent_ctx;

    CC_LOCK_LOCK(ctx->lock_ctx);

    int err = ccentropy_add_entropy(ctx->inner_ctx,
                                    entropy_nsamples,
                                    entropy_nbytes,
                                    entropy,
                                    seed_ready);

    CC_LOCK_UNLOCK(ctx->lock_ctx);

    return err;
}

static
int ccentropy_lock_reset(ccentropy_ctx_t *ent_ctx)
{
    ccentropy_lock_ctx_t *ctx = (ccentropy_lock_ctx_t *)ent_ctx;

    CC_LOCK_LOCK(ctx->lock_ctx);

    int err = ccentropy_reset(ctx->inner_ctx);

    CC_LOCK_UNLOCK(ctx->lock_ctx);

    return err;
}

static const ccentropy_info_t entropy_lock_info = {
    .get_seed = ccentropy_lock_get_seed,
    .add_entropy = ccentropy_lock_add_entropy,
    .reset = ccentropy_lock_reset,
};

int ccentropy_lock_init(ccentropy_lock_ctx_t *ctx,
                        ccentropy_ctx_t *inner_ctx,
                        cc_lock_ctx_t *lock_ctx)
{
    CC_ENSURE_DIT_ENABLED

    ccentropy_ctx_t *ent_ctx = &ctx->entropy_ctx;
    ent_ctx->info = &entropy_lock_info;
    ctx->inner_ctx = inner_ctx;
    ctx->lock_ctx = lock_ctx;

    return CCERR_OK;
}
