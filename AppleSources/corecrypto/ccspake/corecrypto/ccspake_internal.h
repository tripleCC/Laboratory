/* Copyright (c) (2018-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSPAKE_INTERNAL_H_
#define _CORECRYPTO_CCSPAKE_INTERNAL_H_

#include <corecrypto/ccspake.h>
#include "cc_memory.h"

// P-521 is the largest supported curve.
#define CCSPAKE_MAX_CURVE_NBYTES 66

// Maximum sizes for stack allocations.
#define CCSPAKE_MAX_CONFIRM_KEY_NBYTES CCSPAKE_MAX_DIGEST_OUTPUT_NBYTES
#define CCSPAKE_MAX_TAG_NBYTES CCSPAKE_MAX_DIGEST_OUTPUT_NBYTES

// 0x04 = uncompressed EC point for X9.63.
#define CCSPAKE_X963_UNCOMPRESSED 0x04

/*
 The SPAKE2+ protocol state machine.

 An initialized context will always start at INIT.

 The two functions of the KEX and MAC phase may be called in arbitrary order.
 Both functions have to be called to be able to proceed to the next phase.

 Valid: INIT -> KEX_GENERATE -> KEX_PROCESS -> MAC_GENERATE
 Valid: INIT -> KEX_PROCESS -> KEX_GENERATE -> MAC_VERIFY

 NOT Valid: INIT -> KEX_GENERATE -> MAC_GENERATE

 The *_BOTH values of a phase are used as preconditions for the next.
 */
extern const uint8_t CCSPAKE_STATE_INIT;

extern const uint8_t CCSPAKE_STATE_KEX_GENERATE;
extern const uint8_t CCSPAKE_STATE_KEX_PROCESS;
extern const uint8_t CCSPAKE_STATE_KEX_BOTH;

extern const uint8_t CCSPAKE_STATE_MAC_GENERATE;
extern const uint8_t CCSPAKE_STATE_MAC_VERIFY;
extern const uint8_t CCSPAKE_STATE_MAC_BOTH;

typedef enum {
    CCSPAKE_VARIANT_CCC_V1 = 0,
    CCSPAKE_VARIANT_RFC    = 1,
} ccspake_variant;

#define CCSPAKE_STATE_NEQ(_st_) (ccspake_ctx_state(ctx) != CCSPAKE_STATE_##_st_)

#define CCSPAKE_EXPECT_STATE(_st_)  \
    if (CCSPAKE_STATE_NEQ(_st_)) {  \
        return CCERR_CALL_SEQUENCE; \
    }

#define CCSPAKE_EXPECT_STATES(_st_, _st2_)                     \
    if (CCSPAKE_STATE_NEQ(_st_) && CCSPAKE_STATE_NEQ(_st2_)) { \
        return CCERR_CALL_SEQUENCE;                            \
    }

#define CCSPAKE_ADD_STATE(_st_) ccspake_ctx_state(ctx) |= CCSPAKE_STATE_##_st_

struct ccspake_cp {
    ccspake_variant var;
    ccec_const_cp_t (*CC_SPTR(ccspake_cp, cp))(void);
    const cc_unit *m;
    const cc_unit *n;
};

#define ccspake_mac_decl(_name_)                                  \
    struct _name_ {                                               \
        const struct ccdigest_info *(*CC_SPTR(_name_, di))(void); \
        const struct ccmode_cbc *(*CC_SPTR(_name_, cbc))(void);   \
        size_t confirm_key_nbytes;                                \
        size_t tag_nbytes;                                        \
        int (*CC_SPTR(_name_, derive))(ccspake_const_ctx_t ctx,   \
                       size_t ikm_nbytes,                         \
                       const uint8_t *ikm,                        \
                       uint8_t *keys);                            \
        int (*CC_SPTR(_name_, compute))(ccspake_const_ctx_t ctx,  \
                       size_t key_nbytes,                         \
                       const uint8_t *key,                        \
                       size_t info_nbytes,                        \
                       const uint8_t *info,                       \
                       size_t t_nbytes,                           \
                       uint8_t *t);                               \
    }

ccspake_mac_decl(ccspake_mac);

#define ccspake_cp_ec(_cp_) (_cp_->cp())

#define ccspake_ctx_scp(ctx) (ctx->scp)
#define ccspake_ctx_cp(ctx) (ctx->scp->cp())
#define ccspake_ctx_mac(ctx) (ctx->mac)
#define ccspake_ctx_variant(ctx) (ctx->scp->var)
#define ccspake_ctx_rng(ctx) (ctx->rng)
#define ccspake_ctx_aad_nbytes(ctx) (ctx->aad_nbytes)
#define ccspake_ctx_aad(ctx) (ctx->aad)
#define ccspake_ctx_is_prover(ctx) (ctx->is_prover)
#define ccspake_ctx_state(ctx) (ctx->state)
#define ccspake_ctx_hash(ctx) (ctx->hash)
#define ccspake_ctx_main_key(ctx) (ctx->main_key)

/*
 The SPAKE2+ protocol storage.

 We need to hold scalars, EC points, and shared keys.

 Each storage item takes the space of ccec_cp_n(cp) of the chosen curve.
 */
#define CCSPAKE_INTERNAL_STORAGE_NUNITS 8

#define ccspake_ctx_ccn(ctx, n) (ctx->ccn + ccec_cp_n(ccspake_ctx_cp(ctx)) * n)

// w0 and w1
#define ccspake_ctx_w0(ctx) ccspake_ctx_ccn(ctx, 0)
#define ccspake_ctx_w1(ctx) ccspake_ctx_ccn(ctx, 1)
// The L part of the verifier.
#define ccspake_ctx_L(ctx) ccspake_ctx_ccn(ctx, 1)
#define ccspake_ctx_L_x(ctx) ccspake_ctx_ccn(ctx, 1)
#define ccspake_ctx_L_y(ctx) ccspake_ctx_ccn(ctx, 2)
// The scalar for our key share.
#define ccspake_ctx_xy(ctx) ccspake_ctx_ccn(ctx, 3)
// The public share for the KEX phase.
#define ccspake_ctx_XY(ctx) ccspake_ctx_ccn(ctx, 4)
#define ccspake_ctx_XY_x(ctx) ccspake_ctx_ccn(ctx, 4)
#define ccspake_ctx_XY_y(ctx) ccspake_ctx_ccn(ctx, 5)
// MAC inputs Q (Y or X).
#define ccspake_ctx_Q(ctx) ccspake_ctx_ccn(ctx, 6)
#define ccspake_ctx_Q_x(ctx) ccspake_ctx_ccn(ctx, 6)
#define ccspake_ctx_Q_y(ctx) ccspake_ctx_ccn(ctx, 7)

/*! @function ccspake_cmp_pub_key
 @abstract Compares a public key to one in the internal storage

 @param pub The public key
 @param X   Pointer into the internal storage

 @return 0 on match, non-zero on mismatch.
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccspake_cmp_pub_key(ccec_pub_ctx_t pub, const cc_unit *X);

/*! @function ccspake_import_pub_ws
 @abstract Import a public share from a buffer

 @param ws    Workspace
 @param pub   Target public key
 @param x_len Length of the public share
 @param x     Public share sent by the peer

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccspake_import_pub_ws(cc_ws_t ws, ccec_pub_ctx_t pub, size_t x_len, const uint8_t *x);

/*! @function ccspake_store_pub_key
 @abstract Copy a public share into the internal storage

 @param pub  Public key to copy
 @param dest Pointer into the internal storage
 */
CC_NONNULL((1, 2))
void ccspake_store_pub_key(const ccec_pub_ctx_t pub, cc_unit *dest);

/*! @function ccspake_mac_hkdf_derive
 @abstract Derive a key from the shared secret using HKDF

 @param ctx      SPAKE2+ context
 @param ikm_len  Length of ikm
 @param ikm      Input key material
 @param keys     MAC key (of length ccspake_ctx_mac(ctx)->di->output_size bytes)

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int ccspake_mac_hkdf_derive(ccspake_const_ctx_t ctx, size_t ikm_len, const uint8_t *ikm, uint8_t *keys);

/*! @function ccspake_transcript_init
 @abstract Initialize a hashed transcript.

 @param ctx SPAKE2+ context
 */
CC_NONNULL_ALL
void ccspake_transcript_init(ccspake_ctx_t ctx);

/*! @function ccspake_transcript_begin
 @abstract Begin a hashed transcript and append the context and identities.

 @param ctx                SPAKE2+ context
 @param context_nbytes     Length of the transcript context in bytes
 @param context            Transcript context for domain separation
 @param id_prover_nbytes   Length of idProver in bytes
 @param id_prover          idProver
 @param id_verifier_nbytes Length of idVerifier in bytes
 @param id_verifier        idVerifier
 */
CC_NONNULL((1, 3))
void ccspake_transcript_begin(ccspake_ctx_t ctx,
                              size_t context_nbytes,
                              const uint8_t *context,
                              size_t id_prover_nbytes,
                              const uint8_t *id_prover,
                              size_t id_verifier_nbytes,
                              const uint8_t *id_verifier);

/*! @function ccspake_transcript_append
 @abstract Append a given data buffer and its length prefix to the hashed transcript.

 @param ctx    SPAKE2+ context
 @param nbytes Length of the buffer to append in bytes
 @param data   Buffer to append
 */
CC_NONNULL((1))
void ccspake_transcript_append(ccspake_ctx_t ctx, size_t nbytes, const uint8_t *data);

/*! @function ccspake_transcript_append_point
 @abstract Append a given EC point and its length prefix to the hashed transcript.

 @param ctx SPAKE2+ context
 @param cp  Curve parameters
 @param x   x-coordinate
 @param y   y-coordinate
 */
CC_NONNULL_ALL
void ccspake_transcript_append_point(ccspake_ctx_t ctx, ccec_const_cp_t cp, const cc_unit *x, const cc_unit *y);

/*! @function ccspake_transcript_append_scalar
 @abstract Append a given EC scalar and its length prefix to the hashed transcript.

 @param ctx SPAKE2+ context
 @param cp  Curve parameters
 @param x   Scalar
 */
CC_NONNULL_ALL
void ccspake_transcript_append_scalar(ccspake_ctx_t ctx, ccec_const_cp_t cp, const cc_unit *x);

/*! @function ccspake_transcript_finish
 @abstract Finalize the hashed transcript and write the digest to `main_key`.

 @param ctx      SPAKE2+ context
 @param main_key Digest output parameter
 */
CC_NONNULL_ALL
void ccspake_transcript_finish(ccspake_ctx_t ctx, uint8_t *main_key);

#endif /* _CORECRYPTO_CCSPAKE_INTERNAL_H_ */
