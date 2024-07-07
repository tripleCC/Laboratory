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
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccentropy.h>

static
int ccentropy_digest_get_seed(ccentropy_ctx_t *ent_ctx,
                              size_t seed_nbytes,
                              void *seed)
{
    ccentropy_digest_ctx_t *ctx = (ccentropy_digest_ctx_t *)ent_ctx;
    const struct ccdigest_info *digest_info = ctx->digest_info;
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];

    size_t seed_max_nbytes = ctx->digest_info->output_size;
    if (seed_nbytes > seed_max_nbytes) {
        return CCERR_CRYPTO_CONFIG;
    }

    if (ctx->nsamples < ctx->seed_nsamples) {
        return CCERR_OUT_OF_ENTROPY;
    }

    ctx->nsamples = 0;

    ccdigest_final(digest_info, ctx->digest_ctx, digest);
    ccdigest_init(digest_info, ctx->digest_ctx);

    cc_memcpy(seed, digest, seed_nbytes);
    cc_clear(sizeof(digest), digest);

    return CCERR_OK;
}

static
int ccentropy_digest_add_entropy(ccentropy_ctx_t *ent_ctx,
                                 uint32_t entropy_nsamples,
                                 size_t entropy_nbytes,
                                 const void *entropy,
                                 bool *seed_ready)
{
    ccentropy_digest_ctx_t *ctx = (ccentropy_digest_ctx_t *)ent_ctx;

    bool overflow = cc_add_overflow(ctx->nsamples, entropy_nsamples, &entropy_nsamples);
    if (CC_UNLIKELY(overflow)) {
        ctx->nsamples = UINT32_MAX;
    } else {
        ctx->nsamples = entropy_nsamples;
    }

    if (seed_ready) {
        *seed_ready = ctx->nsamples >= ctx->seed_nsamples;
    }

    ccdigest_update(ctx->digest_info, ctx->digest_ctx, entropy_nbytes, entropy);

    return CCERR_OK;
}

static
int ccentropy_digest_reset(ccentropy_ctx_t *ent_ctx)
{
    ccentropy_digest_ctx_t *ctx = (ccentropy_digest_ctx_t *)ent_ctx;

    ctx->nsamples = 0;

    return CCERR_OK;
}

static const ccentropy_info_t entropy_digest_info = {
    .get_seed = ccentropy_digest_get_seed,
    .add_entropy = ccentropy_digest_add_entropy,
    .reset = ccentropy_digest_reset,
};

int ccentropy_digest_init(ccentropy_digest_ctx_t *ctx,
                          const struct ccdigest_info *digest_info,
                          uint32_t seed_nsamples)
{
    CC_ENSURE_DIT_ENABLED

    ccentropy_ctx_t *ent_ctx = &ctx->entropy_ctx;
    ent_ctx->info = &entropy_digest_info;
    ctx->digest_info = digest_info;
    ctx->seed_nsamples = seed_nsamples;
    ctx->nsamples = 0;

    ccdigest_init(digest_info, ctx->digest_ctx);

    return CCERR_OK;
}
