/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_PROCESS_H_
#define _CORECRYPTO_CCRNG_PROCESS_H_

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_schedule.h>
#include <corecrypto/ccentropy.h>
#include "cc_lock.h"
#include "ccrng_crypto.h"

// This value depends on the data structures of supported AES
// implementations and of the DRBG itself. It may require periodic
// tuning.
#define CCRNG_PROCESS_DRBG_STATE_MAX_NBYTES ((size_t)1280)

#define CCRNG_PROCESS_CACHE_NBYTES ((size_t)256)

// Time elapsed in nanoseconds beyond which a reseed is requested,
// i.e. Maximum time a compromised state leads to predictable output
#define CCRNG_PROCESS_RESEED_PERIOD_NSEC (5 * CC_NSEC_PER_SEC)

#define CCRNG_PROCESS_MAX_REQUEST_NBYTES ((size_t)4096)

#define CCRNG_PROCESS_SEED_NBYTES ((size_t)32)

typedef struct ccrng_process_ctx {
    CCRNG_STATE_COMMON

    ccrng_crypto_ctx_t rng_ctx;
    ccrng_schedule_tree_ctx_t schedule_ctx;
    ccrng_schedule_timer_ctx_t schedule_timer_ctx;
    ccrng_schedule_atomic_flag_ctx_t schedule_flag_ctx;
    ccentropy_rng_ctx_t entropy_ctx;
    cc_lock_ctx_t lock_ctx;
    ccdrbg_df_bc_ctx_t df_ctx;
    struct ccdrbg_info drbg_info;
    uint8_t drbg_state[CCRNG_PROCESS_DRBG_STATE_MAX_NBYTES];
    uint8_t cache[CCRNG_PROCESS_CACHE_NBYTES];
} ccrng_process_ctx_t;

int ccrng_process_init(ccrng_process_ctx_t *ctx,
                       uint64_t (*get_time_nsec)(void),
                       struct ccrng_state *entropy_rng_ctx);

int ccrng_process_atfork_prepare(ccrng_process_ctx_t *ctx);

int ccrng_process_atfork_parent(ccrng_process_ctx_t *ctx);

int ccrng_process_atfork_child(ccrng_process_ctx_t *ctx);

#endif /* _CORECRYPTO_CCRNG_PROCESS_H_ */
