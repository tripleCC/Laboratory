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
#include <corecrypto/ccentropy.h>

static
int ccentropy_list_get_seed(ccentropy_ctx_t *ent_ctx,
                            size_t seed_nbytes,
                            void *seed)
{
    ccentropy_list_ctx_t *ctx = (ccentropy_list_ctx_t *)ent_ctx;
    int err = CCERR_INTERNAL;

    for (size_t i = 0; i < ctx->nsources; i += 1) {
        ccentropy_ctx_t *e = ctx->sources[i];
        err = ccentropy_get_seed(e, seed_nbytes, seed);

        if (err != CCERR_OUT_OF_ENTROPY) {
            break;
        }
    }

    if (err != CCERR_OK) {
        cc_clear(seed_nbytes, seed);
    }

    return err;
}

static const ccentropy_info_t entropy_list_info = {
    .get_seed = ccentropy_list_get_seed,
};

int ccentropy_list_init(ccentropy_list_ctx_t *ctx,
                        size_t nsources,
                        ccentropy_ctx_t **sources)
{
    CC_ENSURE_DIT_ENABLED

    ccentropy_ctx_t *ent_ctx = &ctx->entropy_ctx;
    ent_ctx->info = &entropy_list_info;
    ctx->sources = sources;
    ctx->nsources = nsources;

    return CCERR_OK;
}
