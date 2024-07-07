/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCCKG_INTERNAL_H_
#define _CORECRYPTO_CCCKG_INTERNAL_H_

#include <corecrypto/ccsha2.h>
#include "cc_internal.h"

#define CCCKG_HASH_MAX_NBYTES MAX_DIGEST_OUTPUT_SIZE
#define CCCKG_CURVE_MAX_NBYTES cc_ceiling(521, 8)

/*
 Collaborative Key Generation state machine.

 An initialized context will always start at INIT.

 VALID: INIT -> COMMIT -> FINISH
 VALID: INIT -> SHARE -> FINISH
 */
#define CCCKG_STATE_INIT 0
#define CCCKG_STATE_COMMIT 1
#define CCCKG_STATE_SHARE 2
#define CCCKG_STATE_FINISH 3

#define CCCKG_EXPECT_STATE(_st_)                      \
    if (ccckg_ctx_state(ctx) != CCCKG_STATE_##_st_) { \
        return CCERR_CALL_SEQUENCE;                   \
    }

#define CCCKG_SET_STATE(_st_) ccckg_ctx_state(ctx) = CCCKG_STATE_##_st_

#define ccckg_ctx_cp(ctx) (ctx->cp)
#define ccckg_ctx_di(ctx) (ctx->di)
#define ccckg_ctx_rng(ctx) (ctx->rng)
#define ccckg_ctx_state(ctx) (ctx->state)

#define ccckg_ctx_decl(_cp_, _di_, _name_) cc_ctx_decl(struct ccckg_ctx, ccckg_sizeof_ctx(_cp_, _di_), _name_)
#define ccckg_ctx_clear(_cp_, _di_, _name_) cc_clear(ccckg_sizeof_ctx(_cp_, _di_), _name_)

// The local scalar.
#define ccckg_ctx_s(ctx) (ctx->ccn)
// The local nonce.
#define ccckg_ctx_r(ctx) (ccckg_ctx_s(ctx) + ccec_cp_n(ccckg_ctx_cp(ctx)))
// The contributor's commitment (owner-only).
#define ccckg_ctx_c(ctx) (ccckg_ctx_r(ctx) + ccn_nof(ccckg_ctx_di(ctx)->output_size * 8))

/*! @function ccckg_derive_sk
 @abstract Derive the shared symmetric secret

 @param ctx     CKG context
 @param x       X coordinate of the shared point
 @param r1      Contributor's nonce
 @param r2      Owner's nonce
 @param key_len Desired length of SK
 @param key     Output buffer for SK

 @return Size of a CKG context
 */
CC_NONNULL_ALL
int ccckg_derive_sk(ccckg_ctx_t ctx, const cc_unit *x, const uint8_t *r1, const uint8_t *r2, size_t key_len, uint8_t *key);

#endif /* _CORECRYPTO_CCCKG_INTERNAL_H_ */
