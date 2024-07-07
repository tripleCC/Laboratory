/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccshake_internal.h"
#include "ccxof_internal.h"

void ccshake_init(const struct ccxof_info *xi, ccxof_state_t state)
{
    cc_clear(xi->state_nbytes, state);
}

void ccshake128(size_t in_nbytes, const uint8_t *in, size_t out_nbytes, uint8_t *out)
{
    const struct ccxof_info *xi = ccshake128_xi();

    ccshake128_ctx_decl(ctx);
    ccxof_init(xi, ctx);
    ccxof_absorb(xi, ctx, in_nbytes, in);
    ccxof_squeeze(xi, ctx, out_nbytes, out);
    ccshake128_ctx_clear(ctx);
}

void ccshake256(size_t in_nbytes, const uint8_t *in, size_t out_nbytes, uint8_t *out)
{
    const struct ccxof_info *xi = ccshake256_xi();

    ccshake256_ctx_decl(ctx);
    ccxof_init(xi, ctx);
    ccxof_absorb(xi, ctx, in_nbytes, in);
    ccxof_squeeze(xi, ctx, out_nbytes, out);
    ccshake256_ctx_clear(ctx);
}
