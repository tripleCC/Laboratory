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
#include <corecrypto/ccmode.h>

size_t ccomac_context_size(const struct ccmode_omac *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->size;
}

size_t ccomac_block_size(const struct ccmode_omac *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->block_size;
}

int ccomac_init(const struct ccmode_omac *mode,
                ccomac_ctx *ctx,
                size_t tweak_len,
                size_t key_len,
                const void *cc_sized_by(key_len) key)
{
    CC_ENSURE_DIT_ENABLED

    return mode->init(mode, ctx, tweak_len, key_len, key);
}

int ccomac_update(const struct ccmode_omac *mode,
                  ccomac_ctx *ctx,
                  size_t nblocks,
                  const void *tweak,
                  const void *cc_indexable in,
                  void *cc_indexable out)
{
    CC_ENSURE_DIT_ENABLED

    return mode->omac(ctx, nblocks, tweak, in, out);
}

int ccomac_one_shot(const struct ccmode_omac *mode,
                    size_t tweak_len,
                    size_t key_len,
                    const void *cc_sized_by(key_len) key,
                    const void *cc_sized_by(tweak_len) tweak,
                    size_t nblocks,
                    const void *cc_indexable in,
                    void *cc_indexable out)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    ccomac_ctx_decl(mode->size, ctx);
    rc = mode->init(mode, ctx, tweak_len, key_len, key);
    if (rc == 0) {
        rc = mode->omac(ctx, nblocks, tweak, in, out);
    }
    ccomac_ctx_clear(mode->size, ctx);
    return rc;
}
