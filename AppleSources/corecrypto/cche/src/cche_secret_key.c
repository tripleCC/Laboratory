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

#include <corecrypto/cche_priv.h>
#include "cche_internal.h"
#include "ccpolyzp_po2cyc_random.h"

int cche_secret_key_generate_ws(cc_ws_t ws,
                                cche_secret_key_t secret_key,
                                cche_param_ctx_const_t param_ctx,
                                struct ccrng_state *rng)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_coeff_t secret_key_as_poly = (ccpolyzp_po2cyc_coeff_t)secret_key;
    secret_key_as_poly->context = cche_param_ctx_encrypt_key_context(param_ctx);
    // Note, cche_serialize_ciphertext_coeff_max_nskip_lsbs relies on a ternary secret key
    rv = ccpolyzp_po2cyc_random_ternary_ws(ws, (ccpolyzp_po2cyc_t)secret_key, rng);
    cc_require(rv == CCERR_OK, errOut);
    rv = ccpolyzp_po2cyc_fwd_ntt(secret_key_as_poly);
errOut:
    return rv;
}

int cche_secret_key_generate(cche_secret_key_t secret_key, cche_param_ctx_const_t param_ctx, struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_SECRET_KEY_GENERATE_WORKSPACE_N(cche_param_ctx_polynomial_degree(param_ctx)));
    int rv = cche_secret_key_generate_ws(ws, secret_key, param_ctx, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cche_secret_key_generate_from_seed_ws(cc_ws_t ws,
                                          cche_secret_key_t secret_key,
                                          cche_param_ctx_const_t param_ctx,
                                          cche_rng_seed_const_t seed)
{
    CC_DECL_BP_WS(ws, bp);
    ccpolyzp_po2cyc_block_rng_state_t block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
    int rv = ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed);
    cc_require(rv == CCERR_OK, errOut);
    rv = cche_secret_key_generate_ws(ws, secret_key, param_ctx, (struct ccrng_state *)block_rng);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cche_secret_key_generate_from_seed(cche_secret_key_t secret_key, cche_param_ctx_const_t param_ctx, cche_rng_seed_const_t seed)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCHE_SECRET_KEY_GENERATE_FROM_SEED_WORKSPACE_N(cche_param_ctx_polynomial_degree(param_ctx)));
    int rv = cche_secret_key_generate_from_seed_ws(ws, secret_key, param_ctx, seed);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
