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

#ifndef _CORECRYPTO_CCSAE_PRIV_H_
#define _CORECRYPTO_CCSAE_PRIV_H_

#include <corecrypto/ccsae.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

#define CCSAE_STATE_NEQ(_st_) (ccsae_ctx_state(ctx) != CCSAE_STATE_##_st_)

#define CCSAE_EXPECT_STATE(_st_)    \
    if (CCSAE_STATE_NEQ(_st_)) {    \
        return CCERR_CALL_SEQUENCE; \
    }

#define CCSAE_EXPECT_STATES(_st_, _st2_)                   \
    if (CCSAE_STATE_NEQ(_st_) && CCSAE_STATE_NEQ(_st2_)) { \
        return CCERR_CALL_SEQUENCE;                        \
    }

#define CCSAE_ADD_STATE(_st_) ccsae_ctx_state(ctx) |= CCSAE_STATE_##_st_

#define ccsae_ctx_cp(ctx) (ctx->cp)
#define ccsae_ctx_rng(ctx) (ctx->rng)
#define ccsae_ctx_di(ctx) (ctx->di)
#define ccsae_ctx_state(ctx) (ctx->state)
#define ccsae_ctx_max_loop_iterations(ctx) (ctx->iterations) // Number of hunt-and-peck iterations
#define ccsae_ctx_alg(ctx) (ctx->algorithm)
#define ccsae_ctx_kck_pmk_label(ctx) (ctx->kck_pmk_label)
#define ccsae_ctx_hunt_peck_label(ctx) (ctx->hunt_peck_label)
#define ccsae_ctx_KCK_and_PMK(ctx) ctx->kck
#define ccsae_ctx_KCK(ctx) ctx->kck
#define ccsae_ctx_PMK(ctx) ctx->pmk

#define ccsae_ctx_ccn(ctx, n) (ctx->ccn + ccec_cp_n(ccsae_ctx_cp(ctx)) * n)

// PWE
#define ccsae_ctx_PWE(ctx) ccsae_ctx_ccn(ctx, 0)
#define ccsae_ctx_PWE_x(ctx) ccsae_ctx_ccn(ctx, 0)
#define ccsae_ctx_PWE_y(ctx) ccsae_ctx_ccn(ctx, 1)
// Peer Commit Scalar
#define ccsae_ctx_peer_commitscalar(ctx) ccsae_ctx_ccn(ctx, 2)
// Commit Scalar
#define ccsae_ctx_commitscalar(ctx) ccsae_ctx_ccn(ctx, 3)
// Rand
#define ccsae_ctx_rand(ctx) ccsae_ctx_ccn(ctx, 4)
// Commit-Element
#define ccsae_ctx_CE(ctx) ccsae_ctx_ccn(ctx, 5)
#define ccsae_ctx_CE_x(ctx) ccsae_ctx_ccn(ctx, 5)
#define ccsae_ctx_CE_y(ctx) ccsae_ctx_ccn(ctx, 6)
// Peer commit-element
#define ccsae_ctx_peer_CE(ctx) ccsae_ctx_ccn(ctx, 7)
#define ccsae_ctx_peer_CE_x(ctx) ccsae_ctx_ccn(ctx, 7)
#define ccsae_ctx_peer_CE_y(ctx) ccsae_ctx_ccn(ctx, 8)

/*
    Scratch Space
 */
// If P192 & SHA-512 is used, we will overwrite values within peer_CE, but that's fine at this stage.
#define ccsae_ctx_S_PWD_SEED(ctx) (uint8_t *)(ccsae_ctx_CE(ctx))
#define ccsae_ctx_S_PWD_SEED_LSB(ctx, di) *(ccsae_ctx_S_PWD_SEED(ctx) + di->output_size - 1)
#define ccsae_ctx_S_PWD_VALUE(ctx) (ccsae_ctx_peer_CE_y(ctx))
// These re-use space from KCK, that's fine at this stage.
#define ccsae_ctx_temp_lsb(ctx) (ccsae_ctx_KCK(ctx)[0])
#define ccsae_ctx_current_loop_iteration(ctx) (ccsae_ctx_KCK(ctx)[1])
#define ccsae_ctx_found_qr(ctx) (ccsae_ctx_KCK(ctx)[2])

/*! @function ccsae_lexographic_order_key
 @abstract Lexographically orders the input parameters.

 @param A         Identity of the first participating party
 @param A_nbytes  Length of input A
 @param B         Identity of the second participating party
 @param B_nbytes  Length of input B
 @param output    Output buffer of size A_nbytes + B_nbytes
 */
void ccsae_lexographic_order_key(const uint8_t *A, size_t A_nbytes, const uint8_t *B, size_t B_nbytes, uint8_t *output);

#endif /* _CORECRYPTO_CCSAE_PRIV_H_ */
