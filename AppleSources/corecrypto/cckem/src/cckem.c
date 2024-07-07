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

#include "cc_internal.h"
#include <corecrypto/cckem.h>
#include "cckem_internal.h"
#include "cc_internal.h"
#include "cc_macros.h"

int cckem_generate_key(cckem_full_ctx_t ctx, struct ccrng_state *rng) {
    CC_ENSURE_DIT_ENABLED

    return cckem_ctx_info(ctx)->generate_key(ctx, rng);
}

int cckem_encapsulate(const cckem_pub_ctx_t ctx,
                      size_t ek_nbytes,
                      uint8_t *ek,
                      size_t sk_nbytes,
                      uint8_t *sk,
                      struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(ek_nbytes == cckem_encapsulated_key_nbytes_ctx(ctx), CCERR_PARAMETER);
    cc_require_or_return(sk_nbytes == cckem_shared_key_nbytes_ctx(ctx), CCERR_PARAMETER);
    
    return cckem_ctx_info(ctx)->encapsulate(ctx, ek, sk, rng);
}

int cckem_decapsulate(const cckem_full_ctx_t ctx,
                      size_t ek_nbytes,
                      const uint8_t *ek,
                      size_t sk_nbytes,
                      uint8_t *sk)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(ek_nbytes == cckem_encapsulated_key_nbytes_ctx(cckem_public_ctx(ctx)), CCERR_PARAMETER);
    cc_require_or_return(sk_nbytes == cckem_shared_key_nbytes_ctx(cckem_public_ctx(ctx)), CCERR_PARAMETER);
    
    return cckem_ctx_info(ctx)->decapsulate(ctx, ek, sk);
}

int cckem_export_pubkey(const cckem_pub_ctx_t ctx,
                        size_t *pubkey_nbytes,
                        uint8_t *pubkey)
{
    return cckem_ctx_info(ctx)->export_pubkey(ctx, pubkey_nbytes, pubkey);
}

int cckem_import_pubkey(const struct cckem_info *info,
                        size_t pubkey_nbytes,
                        const uint8_t * pubkey,
                        cckem_pub_ctx_t ctx)
{
    return info->import_pubkey(info, pubkey_nbytes, pubkey, ctx);
}

int cckem_export_privkey(const cckem_full_ctx_t ctx,
                         size_t *privkey_nbytes,
                         uint8_t *privkey)
{
    CC_ENSURE_DIT_ENABLED
    
    return cckem_ctx_info(ctx)->export_privkey(ctx, privkey_nbytes, privkey);
}

int cckem_import_privkey(const struct cckem_info *info,
                         size_t privkey_nbytes,
                         const uint8_t *privkey,
                         cckem_full_ctx_t ctx)
{
    CC_ENSURE_DIT_ENABLED
    
    return info->import_privkey(info, privkey_nbytes, privkey, ctx);
}

size_t cckem_pubkey_nbytes_info(const struct cckem_info *info) {
    return info->pubkey_nbytes;
}

size_t cckem_pubkey_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_pubkey_nbytes_info(cckem_ctx_info(ctx));
}

size_t cckem_privkey_nbytes_info(const struct cckem_info *info) {
    return info->fullkey_nbytes - info->pubkey_nbytes;
}

size_t cckem_privkey_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_privkey_nbytes_info(cckem_ctx_info(ctx));
}

size_t cckem_encapsulated_key_nbytes_info(const struct cckem_info *info) {
    return info->encapsulated_key_nbytes;
}

size_t cckem_encapsulated_key_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_encapsulated_key_nbytes_info(cckem_ctx_info(ctx));
}

size_t cckem_shared_key_nbytes_info(const struct cckem_info *info) {
    return info->shared_key_nbytes;
}

size_t cckem_shared_key_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_shared_key_nbytes_info(cckem_ctx_info(ctx));
}
