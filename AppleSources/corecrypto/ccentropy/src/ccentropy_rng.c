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

#include "cc_internal.h"
#include <corecrypto/ccentropy.h>
#include <corecrypto/ccrng.h>

static
int ccentropy_rng_get_seed(ccentropy_ctx_t *ent_ctx,
                           size_t seed_nbytes,
                           void *seed)
{
    ccentropy_rng_ctx_t *ctx = (ccentropy_rng_ctx_t *)ent_ctx;

    return ccrng_generate(ctx->rng_ctx, seed_nbytes, seed);
}

static const ccentropy_info_t entropy_rng_info = {
    .get_seed = ccentropy_rng_get_seed,
};

int ccentropy_rng_init(ccentropy_rng_ctx_t *ctx,
                       struct ccrng_state *rng_ctx)
{
    CC_ENSURE_DIT_ENABLED

    ccentropy_ctx_t *ent_ctx = &ctx->entropy_ctx;
    ent_ctx->info = &entropy_rng_info;
    ctx->rng_ctx = rng_ctx;

    return CCERR_OK;
}
