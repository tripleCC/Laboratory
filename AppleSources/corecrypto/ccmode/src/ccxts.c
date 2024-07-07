/* Copyright (c) (2016-2019,2021,2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"
#include <corecrypto/ccmode.h>

#include "fipspost_trace.h"

size_t ccxts_context_size(const struct ccmode_xts *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->size;
}

size_t ccxts_block_size(const struct ccmode_xts *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->block_size;
}

int ccxts_init(const struct ccmode_xts *mode,
               ccxts_ctx *ctx,
               size_t key_nbytes,
               const void *cc_sized_by(key_nbytes) data_key,
               const void *cc_sized_by(key_nbytes) tweak_key)
{
    CC_ENSURE_DIT_ENABLED

    return mode->init(mode, ctx, key_nbytes, data_key, tweak_key);
}

int ccxts_set_tweak(const struct ccmode_xts *mode,
                    ccxts_ctx *ctx,
                    ccxts_tweak *tweak,
                    const void *cc_indexable iv)
{
    CC_ENSURE_DIT_ENABLED

    return mode->set_tweak(ctx, tweak, iv);
}

void *cc_unsafe_indexable ccxts_update(const struct ccmode_xts *mode,
                                       ccxts_ctx *ctx,
                                       ccxts_tweak *tweak,
                                       size_t nblocks,
                                       const void *cc_indexable in,
                                       void *cc_indexable out)
{
    CC_ENSURE_DIT_ENABLED

    return mode->xts(ctx, tweak, nblocks, in, out);
}

int ccxts_one_shot(const struct ccmode_xts *mode,
                   size_t key_nbytes, const void *data_key,
                   const void *tweak_key, const void *iv,
                   size_t nblocks, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    FIPSPOST_TRACE_EVENT;

    int rc;
    ccxts_ctx_decl(mode->size, ctx);
    ccxts_tweak_decl(mode->tweak_size, tweak);

    if ((rc = ccxts_init(mode, ctx, key_nbytes, data_key, tweak_key))) {
        goto cleanup;
    }

    if ((rc = mode->set_tweak(ctx, tweak, iv))) {
        goto cleanup;
    }

    if (mode->xts(ctx, tweak, nblocks, in, out) == NULL) {
        rc = CCERR_PARAMETER;
    }

cleanup:
    ccxts_ctx_clear(mode->size, ctx);
    ccxts_tweak_clear(mode->tweak_size, tweak);

    return rc;
}
