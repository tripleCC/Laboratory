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

size_t ccofb_context_size(const struct ccmode_ofb *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->size;
}

size_t ccofb_block_size(const struct ccmode_ofb *mode)
{
    CC_ENSURE_DIT_ENABLED

    return mode->block_size;
}

int ccofb_init(const struct ccmode_ofb *mode,
               ccofb_ctx *ctx,
               size_t key_len,
               const void *cc_sized_by(key_len) key,
               const void *cc_indexable iv)
{
    CC_ENSURE_DIT_ENABLED

    return mode->init(mode, ctx, key_len, key, iv);
}

int ccofb_update(const struct ccmode_ofb *mode,
                 ccofb_ctx *ctx,
                 size_t nbytes,
                 const void *cc_sized_by(nbytes) in,
                 void *cc_sized_by(nbytes) out)
{
    CC_ENSURE_DIT_ENABLED

    return mode->ofb(ctx, nbytes, in, out);
}

int ccofb_one_shot(const struct ccmode_ofb *mode,
                   size_t key_len,
                   const void *cc_sized_by(key_len) key,
                   const void *cc_indexable iv,
                   size_t nbytes,
                   const void *cc_sized_by(nbytes) in,
                   void *cc_sized_by(nbytes) out)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    ccofb_ctx_decl(mode->size, ctx);
    rc = mode->init(mode, ctx, key_len, key, iv);
    if (rc == 0) {
        rc = mode->ofb(ctx, nbytes, in, out);
    }
    ccofb_ctx_clear(mode->size, ctx);
    return rc;
}
