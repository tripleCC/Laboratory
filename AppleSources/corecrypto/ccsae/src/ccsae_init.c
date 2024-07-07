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
#include "cc_internal.h"
#include <corecrypto/ccsha2.h>
#include "ccsae.h"
#include "ccsae_priv.h"
#include "ccsae_internal.h"

int ccsae_init_p384_sha384(ccsae_ctx_t ctx, struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED
    
    ccec_const_cp_t cp = ccec_cp_384();
    const struct ccdigest_info *di = ccsha384_di();

    return ccsae_init(ctx, cp, rng, di);
}

int ccsae_init_p256_sha256(ccsae_ctx_t ctx, struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_256();
    const struct ccdigest_info *di = ccsha256_di();

    return ccsae_init(ctx, cp, rng, di);
}

int ccsae_init(ccsae_ctx_t ctx, ccec_const_cp_t cp, struct ccrng_state *rng, const struct ccdigest_info *di)
{
    CC_ENSURE_DIT_ENABLED

    ccsae_ctx_clear(cp, ctx);
    ccsae_ctx_cp(ctx) = cp;
    ccsae_ctx_rng(ctx) = rng;
    ccsae_ctx_di(ctx) = di;
    ccsae_ctx_alg(ctx) = CCSAE_ALG_NONE;
    ccsae_ctx_state(ctx) = CCSAE_STATE_INIT;
    ccsae_ctx_max_loop_iterations(ctx) = SAE_HUNT_AND_PECK_ITERATIONS;
    ccsae_ctx_kck_pmk_label(ctx) = SAE_KCK_PMK_LABEL;
    ccsae_ctx_hunt_peck_label(ctx) = SAE_HUNT_PECK_LABEL;

    return CCERR_OK;
}
