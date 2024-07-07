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

#ifndef _CORECRYPTO_CCKEM_H_
#define _CORECRYPTO_CCKEM_H_

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng.h>

// MARK: - KEM info

struct cckem_info;

// MARK: - Context Initialization
// MARK: -- Full Context

struct cckem_full_ctx {
    const struct cckem_info *info;
    uint8_t key[];
};
typedef struct cckem_full_ctx *cckem_full_ctx_t;

/*!
 @function cckem_sizeof_full_ctx
 
 @param info The KEM info
 
 @return The size in bytes of a full KEM context given the input KEM info
 */
CC_NONNULL_ALL
size_t cckem_sizeof_full_ctx(const struct cckem_info *info);

/*!
 @function cckem_full_ctx_init
 @abstract Initialize a full context given the particular KEM info
 
 @param ctx The input full key context to be intialized
 @param info The KEM info
 */
CC_NONNULL_ALL
void cckem_full_ctx_init(cckem_full_ctx_t ctx, const struct cckem_info *info);

#define cckem_full_ctx_decl(_info_, _name_) cc_ctx_decl(struct cckem_full_ctx, cckem_sizeof_full_ctx(_info_), _name_)
#define cckem_full_ctx_clear(_info_, _name_) cc_memset(_name_, 0, cckem_sizeof_full_ctx(_info_))

// MARK: -- Public Context

struct cckem_pub_ctx {
    const struct cckem_info *info;
    uint8_t key[];
};
typedef struct cckem_pub_ctx *cckem_pub_ctx_t;

/*!
 @function cckem_public_ctx
 
 @return Return the public KEM context from a full KEM context
 */
cckem_pub_ctx_t cckem_public_ctx(cckem_full_ctx_t ctx);

/*!
 @function cckem_sizeof_pub_ctx
 
 @param info The KEM info
 
 @return The size in bytes of a public KEM context given the input KEM info
 */
CC_NONNULL_ALL
size_t cckem_sizeof_pub_ctx(const struct cckem_info *info);

/*! @function cckem_pub_ctx_init
 @abstract Initialize a public signature context.
 */
CC_NONNULL_ALL
void cckem_pub_ctx_init(cckem_pub_ctx_t ctx, const struct cckem_info *info);

#define cckem_pub_ctx_decl(_info_, _name_) cc_ctx_decl(struct cckem_pub_ctx, cckem_sizeof_pub_ctx(_info_), _name_)
#define cckem_pub_ctx_clear(_info_, _name_) memset(_name_, 0, cckem_sizeof_pub_ctx(_info_))

// MARK: - KEM Functions

/*!
 @function cckem_generate_key
 @discussion Generate a full key context into `ctx`
 
 @param ctx A full KEM context
 @param rng RNG state
 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL
int cckem_generate_key(cckem_full_ctx_t ctx, struct ccrng_state *rng);

/*!
 @function cckem_encapsulate
 @discussion Generate and encapsulate a shared key `sk` into an encapsulated key `ek`
 
 @param ctx A public KEM context
 @param ek_nbytes The size, in bytes, of the output buffer `ek`. Must be at least `cckem_encapsulated_key_nbytes_ctx(ctx)` bytes
 @param ek The output encapsulated key
 @param sk_nbytes The size, in bytes, of the output buffer `sk`. Must be at least `cckem_shared_key_nbytes_ctx(ctx)` bytes
 @param sk The output shared key
 @param rng RNG state
 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL
int cckem_encapsulate(const cckem_pub_ctx_t ctx,
                      size_t ek_nbytes,
                      uint8_t *cc_sized_by(ek_nbytes) ek,
                      size_t sk_nbytes,
                      uint8_t *cc_sized_by(sk_nbytes) sk,
                      struct ccrng_state *rng);


/*!
 @function cckem_decapsulate
 @discussion Decapsulate an input encapsulated key `ek` and output the shared key `sk`
 
 @param ctx A full KEM context
 @param ek_nbytes The size, in bytes, of the input buffer `ek`.  Must be exactly `cckem_encapsulated_key_nbytes_ctx(ctx)` bytes
 @param ek The input encapsulated key
 @param sk_nbytes The size, in bytes, of the output buffer `sk`. Must be exactly `cckem_shared_key_nbytes_ctx(ctx)` bytes
 @param sk The output shared key
 
 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL
int cckem_decapsulate(const cckem_full_ctx_t ctx,
                      size_t ek_nbytes,
                      const uint8_t *cc_sized_by(ek_nbytes) ek,
                      size_t sk_nbytes,
                      uint8_t *cc_sized_by(sk_nbytes) sk);

/*!
 @function cckem_export_pubkey
 @discussion Export the public key of a kem context
 
 @param ctx A public KEM context
 @param pubkey_nbytes The size of the output buffer `pubkey`. Needs to at least be `cckem_pubkey_nbytes_ctx(ctx)` bytes
 @param pubkey The output public key
 
 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL
int cckem_export_pubkey(const cckem_pub_ctx_t ctx,
                        size_t *pubkey_nbytes,
                        uint8_t *cc_sized_by(*pubkey_nbytes) pubkey);

/*!
 @function cckem_import_pubkey
 @discussion Import a public key into a kem context. Note that this function calls `cckem_pub_ctx_init`
 
 @param info The KEM info
 @param pubkey_nbytes The size of the input buffer `pubkey`. Must be `cckem_pubkey_nbytes_info(info)` bytes
 @param pubkey The input public key
 @param ctx A public KEM context
 */
CC_NONNULL_ALL
int cckem_import_pubkey(const struct cckem_info *info,
                        size_t pubkey_nbytes,
                        const uint8_t *cc_sized_by(pubkey_nbytes) pubkey,
                        cckem_pub_ctx_t ctx);

/*!
 @function cckem_export_privkey
 @discussion Export the private key of a kem context
 
 @param ctx A full KEM context
 @param privkey_nbytes The size of the output buffer `privkey`. Needs to at least be `cckem_privkey_nbytes_ctx(ctx)` bytes
 @param privkey The output private key
 
 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL
int cckem_export_privkey(const cckem_full_ctx_t ctx,
                         size_t *privkey_nbytes,
                         uint8_t *cc_sized_by(*privkey_nbytes) privkey);

/*!
 @function cckem_import_privkey
 @discussion Import a private key into a kem context. Note that this function calls `cckem_full_ctx_init`. Note that this function DOES not recover the originally generated public key.
 
 @param info The KEM info
 @param privkey_nbytes The size of the output buffer `privkey`. Must be `cckem_privkey_nbytes_info(ctx)` bytes
 @param privkey The input private key
 @param ctx A full KEM context
 
 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL
int cckem_import_privkey(const struct cckem_info *info,
                         size_t privkey_nbytes,
                         const uint8_t *cc_sized_by(privkey_nbytes) privkey,
                         cckem_full_ctx_t ctx);


// MARK: - KEM Size Information
// MARK: -- Encapsulated Key Size
/*!
 @function cckem_encapsulated_key_nbytes_info
 @param info The KEM info
 @return The size of the resultant encapsulated key
 */
CC_NONNULL_ALL
size_t cckem_encapsulated_key_nbytes_info(const struct cckem_info *info);

/*!
 @function cckem_encapsulated_key_nbytes_ctx
 @param ctx The KEM public key context
 @return The size of the resultant encapsulated key
 */
CC_NONNULL_ALL
size_t cckem_encapsulated_key_nbytes_ctx(const cckem_pub_ctx_t ctx);

// MARK: -- Shared Key Size
/*!
 @function cckem_shared_key_nbytes_info
 @param info The KEM info
 @return The size of the shared key
 */
CC_NONNULL_ALL
size_t cckem_shared_key_nbytes_info(const struct cckem_info *info);

/*!
 @function cckem_shared_key_nbytes_ctx
 @param ctx The KEM public key context
 @return The size of the shared key
 */
CC_NONNULL_ALL
size_t cckem_shared_key_nbytes_ctx(const cckem_pub_ctx_t ctx);

// MARK: -- Public Key Size
/*!
 @function cckem_pubkey_nbytes_info
 @param info The KEM info
 @return The size of the public key
 */
CC_NONNULL_ALL
size_t cckem_pubkey_nbytes_info(const struct cckem_info *info);

/*!
 @function cckem_pubkey_nbytes_ctx
 @param ctx The KEM public key context
 @return The size of the public key
 */
CC_NONNULL_ALL
size_t cckem_pubkey_nbytes_ctx(const cckem_pub_ctx_t ctx);

// MARK: -- Private Key Size
/*!
 @function cckem_privkey_nbytes_info
 @param info The KEM info
 @return The size of the private key
 */
CC_NONNULL_ALL
size_t cckem_privkey_nbytes_info(const struct cckem_info *info);

/*!
 @function cckem_privkey_nbytes_ctx
 @param ctx The KEM public key context
 @return The size of the private key
 */
CC_NONNULL_ALL
size_t cckem_privkey_nbytes_ctx(const cckem_pub_ctx_t ctx);

#endif // _CORECRYPTO_CCKEM_H_
