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

#ifndef _CORECRYPTO_CCKEM_INTERNAL_H_
#define _CORECRYPTO_CCKEM_INTERNAL_H_

#include <corecrypto/cckem.h>

#define cckem_ctx_info(ctx) (ctx->info)

struct cckem_info {
    size_t fullkey_nbytes;
    size_t pubkey_nbytes;
    size_t encapsulated_key_nbytes;
    size_t shared_key_nbytes;

    int(* CC_SPTR(cckem_info, generate_key))(cckem_full_ctx_t ctx, struct ccrng_state *rng);
    int(* CC_SPTR(cckem_info, encapsulate))(const cckem_pub_ctx_t ctx,
                                            uint8_t *cc_unsafe_indexable ek,
                                            uint8_t *cc_unsafe_indexable sk,
                                            struct ccrng_state *rng);
    int(* CC_SPTR(cckem_info, decapsulate))(const cckem_full_ctx_t ctx,
                                            const uint8_t *cc_unsafe_indexable ek,
                                            uint8_t *cc_unsafe_indexable sk);
    int(* CC_SPTR(cckem_info, export_pubkey))(const cckem_pub_ctx_t ctx,
                                              size_t *pubkey_nbytes,
                                              uint8_t *cc_sized_by(*pubkey_nbytes) pubkey);
    int(* CC_SPTR(cckem_info, import_pubkey))(const struct cckem_info *info,
                                               size_t pubkey_nbytes,
                                               const uint8_t *cc_sized_by(pubkey_nbytes) pubkey,
                                               cckem_pub_ctx_t ctx);
    int(* CC_SPTR(cckem_info, export_privkey))(const cckem_full_ctx_t ctx,
                                               size_t *privkey_nbytes,
                                               uint8_t *cc_sized_by(*privkey_nbytes) privkey);
    int(* CC_SPTR(cckem_info, import_privkey))(const struct cckem_info *info,
                                               size_t privkey_nbytes,
                                               const uint8_t *cc_sized_by(privkey_nbytes) privkey,
                                               cckem_full_ctx_t ctx);
};

CC_INLINE uint8_t* cckem_ctx_pubkey(cckem_pub_ctx_t ctx) {
    return ctx->key;
}

CC_INLINE uint8_t* cckem_ctx_fullkey(cckem_full_ctx_t ctx) {
    return ctx->key;
}

CC_INLINE uint8_t* cckem_ctx_privkey(cckem_full_ctx_t ctx) {
    return ctx->key + cckem_ctx_info(ctx)->pubkey_nbytes;
}

#endif // _CORECRYPTO_CCKEM_INTERNAL_H_
