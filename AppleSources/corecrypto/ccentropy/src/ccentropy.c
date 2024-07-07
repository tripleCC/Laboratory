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

int ccentropy_get_seed(ccentropy_ctx_t *ctx,
                       size_t seed_nbytes,
                       void *seed)
{
    CC_ENSURE_DIT_ENABLED

    return ctx->info->get_seed(ctx, seed_nbytes, seed);
}

int ccentropy_add_entropy(ccentropy_ctx_t *ctx,
                          uint32_t entropy_nsamples,
                          size_t entropy_nbytes,
                          const void *entropy,
                          bool *seed_ready)
{
    CC_ENSURE_DIT_ENABLED

    if (seed_ready) {
        *seed_ready = false;
    }

    ccentropy_add_entropy_fn_t add_entropy = ctx->info->add_entropy;

    int err = CCERR_NOT_SUPPORTED;
    cc_require(add_entropy != NULL, out);

    err = add_entropy(ctx, entropy_nsamples, entropy_nbytes, entropy, seed_ready);

 out:
    return err;
}

int ccentropy_reset(ccentropy_ctx_t *ctx)
{
    CC_ENSURE_DIT_ENABLED

    ccentropy_reset_fn_t reset = ctx->info->reset;

    int err = CCERR_NOT_SUPPORTED;
    cc_require(reset != NULL, out);

    err = reset(ctx);

 out:
    return err;
}
