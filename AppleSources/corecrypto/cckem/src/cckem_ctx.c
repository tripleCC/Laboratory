/* Copyright (c) (2022) Apple Inc. All rights reserved.
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
#include <corecrypto/cckem.h>
#include "cckem_internal.h"

size_t cckem_sizeof_full_ctx(const struct cckem_info *info)
{
    return sizeof(struct cckem_full_ctx) + info->fullkey_nbytes;
}

size_t cckem_sizeof_pub_ctx(const struct cckem_info *info)
{
    return sizeof(struct cckem_full_ctx) + info->pubkey_nbytes;
}

void cckem_full_ctx_init(cckem_full_ctx_t ctx, const struct cckem_info *info)
{
    CC_ENSURE_DIT_ENABLED

    cckem_full_ctx_clear(info, ctx);
    cckem_ctx_info(ctx) = info;
}

void cckem_pub_ctx_init(cckem_pub_ctx_t ctx, const struct cckem_info *info)
{
    CC_ENSURE_DIT_ENABLED

    cckem_pub_ctx_clear(info, ctx);
    cckem_ctx_info(ctx) = info;
}

cckem_pub_ctx_t cckem_public_ctx(cckem_full_ctx_t ctx)
{
    return (cckem_pub_ctx_t)ctx;
}
