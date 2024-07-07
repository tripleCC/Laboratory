/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCCKG_H_
#define _CORECRYPTO_CCCKG_H_

#include <corecrypto/ccec.h>

CC_PTRCHECK_CAPABLE_HEADER()

/*
 API for Collaborative Key Generation (CKG).

 The protocol defines two roles: contributor and owner.

 The contributor contributes to the key generation by committing to a scalar
 and nonce at the beginning. Upon receival of the owner's key share and nonce
 it will combine those with the values committed to previously to compute the
 shared point and symmetric secret.

 The owner incorporates the scalar and nonce the contributor committed to by
 combining those with its own key share to also compute the shared point and
 symmetric secret. The key share is then sent to the contributor.

 Neither the contributor nor the owner can bias the resulting point and
 symmetric secret.

 Only the owner knows the private key d, for the shared point P = d * G.
 */

struct ccckg_ctx;
typedef struct ccckg_ctx *ccckg_ctx_t;
typedef const struct ccckg_ctx *ccckg_const_ctx_t;

typedef uint8_t ccckg_state_t;

struct ccckg_ctx {
    ccec_const_cp_t cp;
    const struct ccdigest_info *di;
    struct ccrng_state *rng;
    ccckg_state_t state;
    CC_ALIGNED(CCN_UNIT_SIZE) cc_unit ccn[];
};

/*! @function ccckg_sizeof_ctx
 @abstract Returns the size of a CKG context.

 @param cp EC curve parameters.
 @param di Hash function.

 @return Size of a CKG context.
 */
CC_NONNULL((1, 2))
size_t ccckg_sizeof_ctx(ccec_const_cp_t cp, const struct ccdigest_info *di);

/*! @function ccckg_sizeof_commitment
 @abstract Returns the size of a commitment.

 @param cp EC curve parameters.
 @param di Hash function.

 @return Size of a commitment.
 */
CC_NONNULL((1, 2))
size_t ccckg_sizeof_commitment(ccec_const_cp_t cp, const struct ccdigest_info *di);

/*! @function ccckg_sizeof_share
 @abstract Returns the size of a share.

 @param cp EC curve parameters.
 @param di Hash function.

 @return Size of a share.
 */
CC_NONNULL((1, 2))
size_t ccckg_sizeof_share(ccec_const_cp_t cp, const struct ccdigest_info *di);

/*! @function ccckg_sizeof_opening
 @abstract Returns the size of an opened commitment (called opening).

 @param cp EC curve parameters.
 @param di Hash function.

 @return Size of an opening.
 */
CC_NONNULL((1, 2))
size_t ccckg_sizeof_opening(ccec_const_cp_t cp, const struct ccdigest_info *di);

/*! @function ccckg_init
 @abstract Initialize a CKG context.

 @param ctx CKG context.
 @param cp  EC curve parameters.
 @param di  Hash function.
 @param rng RNG instance.
 */
CC_NONNULL((1, 2, 3, 4))
void ccckg_init(ccckg_ctx_t ctx, ccec_const_cp_t cp, const struct ccdigest_info *di, struct ccrng_state *rng);

/*! @function ccckg_contributor_commit
 @abstract Generates a contributor commitment.

 @param ctx            CKG context.
 @param commitment_len Length of the commitment buffer (must be equal to ccckg_sizeof_commitment).
 @param commitment     Commitment output buffer.
 */
CC_NONNULL((1, 3))
int ccckg_contributor_commit(ccckg_ctx_t ctx, size_t commitment_len, uint8_t *commitment);

/*! @function ccckg_owner_generate_share
 @abstract Generates an owner share.

 @param ctx               CKG context.
 @param commitment_nbytes Length of the commitment buffer in bytes.
 @param commitment        Commitment input buffer.
 @param share_nbytes      Length of the share buffer in bytes (must be equal to ccckg_sizeof_share).
 @param share             Share output buffer.
 */
CC_NONNULL((1, 3, 5))
int ccckg_owner_generate_share(ccckg_ctx_t ctx,
                               size_t commitment_nbytes,
                               const uint8_t *cc_counted_by(commitment_nbytes) commitment,
                               size_t share_nbytes,
                               uint8_t *cc_counted_by(share_nbytes) share);

/*! @function ccckg_contributor_finish
 @abstract Finishes the contributor protocol flow by opening the commitment
           and computing the shared point and symmetric secret.

 @param ctx         CKG context.
 @param share_len   Length of the share buffer (must be equal to ccckg_sizeof_share).
 @param share       Share input buffer.
 @param opening_len Length of the opening (must be equal to ccckg_sizeof_opening).
 @param opening     Opening output buffer.
 @param P           Shared public point (output).
 @param sk_len      Desired length of the symmetric secret.
 @param sk          Output buffer for the symmetric secret.
 */
CC_NONNULL_ALL
int ccckg_contributor_finish(ccckg_ctx_t ctx,
                             size_t share_len,
                             const uint8_t *cc_counted_by(share_len) share,
                             size_t opening_len,
                             uint8_t *cc_counted_by(opening_len) opening,
                             ccec_pub_ctx_t P,
                             size_t sk_len,
                             uint8_t *cc_counted_by(sk_len) sk);

/*! @function ccckg_owner_finish
 @abstract Finishes the owner protocol flow by computing the shared point and
           symmetric secret.

 @param ctx            CKG context.
 @param opening_nbytes Length of the opening in bytes (must be equal to ccckg_sizeof_opening).
 @param opening        Opening input buffer.
 @param P              Shared public point (output).
 @param sk_nbytes      Desired length of the symmetric secret in bytes.
 @param sk             Output buffer for the symmetric secret.
 */
CC_NONNULL_ALL
int ccckg_owner_finish(ccckg_ctx_t ctx,
                       size_t opening_nbytes,
                       const uint8_t *cc_counted_by(opening_nbytes) opening,
                       ccec_full_ctx_t P,
                       size_t sk_nbytes,
                       uint8_t *cc_counted_by(sk_nbytes) sk);

#endif // _CORECRYPTO_CCCKG_H_
