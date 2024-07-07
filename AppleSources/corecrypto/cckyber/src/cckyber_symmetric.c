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

#include "cckyber_internal.h"
#include "ccshake_internal.h"
#include "ccsha3_internal.h"

void cckyber_hash_h(size_t nbytes, const uint8_t *bytes, uint8_t out[32])
{
    ccdigest(ccsha3_256_di(), nbytes, bytes, out);
}

void cckyber_hash_g(size_t nbytes, const uint8_t *bytes, uint8_t out[64])
{
    ccdigest(ccsha3_512_di(), nbytes, bytes, out);
}

void cckyber_prf(const uint8_t seed[CCKYBER_SYM_NBYTES],
                 uint8_t nonce,
                 uint8_t out[128])
{
    const struct ccxof_info *xi = ccshake256_xi();

    ccshake256_ctx_decl(ctx);
    ccxof_init(xi, ctx);
    ccxof_absorb(xi, ctx, CCKYBER_SYM_NBYTES, seed);
    ccxof_absorb(xi, ctx, 1U, &nonce);
    ccxof_squeeze(xi, ctx, 128, out);
    ccshake256_ctx_clear(ctx);
}

void cckyber_rkprf(const uint8_t z[CCKYBER_SYM_NBYTES],
                   size_t ek_nbytes,
                   const uint8_t *ek,
                   uint8_t out[CCKYBER_SK_NBYTES])
{
    const struct ccxof_info *xi = ccshake256_xi();

    ccshake256_ctx_decl(ctx);
    ccxof_init(xi, ctx);
    ccxof_absorb(xi, ctx, CCKYBER_SYM_NBYTES, z);
    ccxof_absorb(xi, ctx, ek_nbytes, ek);
    ccxof_squeeze(xi, ctx, CCKYBER_SK_NBYTES, out);
    ccshake256_ctx_clear(ctx);
}
