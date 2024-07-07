/* Copyright (c) (2018-2021,2023) Apple Inc. All rights reserved.
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
#include "ccsae_priv.h"
#include "cczp_internal.h"
#include "ccsae_internal.h"


size_t ccsae_sizeof_kck(CC_UNUSED ccsae_const_ctx_t ctx)
{
    return CCSAE_HAP_KCK_SIZE;
}

size_t ccsae_sizeof_kck_h2c(ccsae_const_ctx_t ctx)
{
    return ccsae_ctx_di(ctx)->output_size;
}

size_t ccsae_sizeof_kck_internal(ccsae_const_ctx_t ctx)
{
    cc_assert(ccsae_ctx_alg(ctx) != CCSAE_ALG_NONE);
    switch (ccsae_ctx_alg(ctx)) {
        case CCSAE_ALG_NONE:
            return 0;
        case CCSAE_ALG_HAP:
            return ccsae_sizeof_kck(ctx);
        case CCSAE_ALG_H2C:
            return ccsae_sizeof_kck_h2c(ctx);
    }
}

static int ccsae_get_keys_ws(cc_ws_t ws, ccsae_const_ctx_t ctx, uint8_t *kck, uint8_t *pmk, uint8_t *pmkid)
{
    CCSAE_EXPECT_STATE(CONFIRMATION_BOTH);

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    cc_assert(n == ccn_nof_size(tn));
    cczp_const_t zq = ccec_cp_zq(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *pmkid_b = CC_ALLOC_WS(ws, n);
    uint8_t *scratch = (uint8_t *)CC_ALLOC_WS(ws, n);

    cczp_add_ws(ws, zq, pmkid_b, ccsae_ctx_commitscalar(ctx), ccsae_ctx_peer_commitscalar(ctx));
    ccn_write_uint_padded(n, pmkid_b, tn, scratch);

    cc_memcpy(kck, ccsae_ctx_KCK(ctx), ccsae_sizeof_kck_internal(ctx));
    cc_memcpy(pmk, ccsae_ctx_PMK(ctx), CCSAE_PMK_SIZE);
    cc_assert(CCSAE_PMKID_SIZE <= tn);
    cc_memcpy(pmkid, scratch, CCSAE_PMKID_SIZE);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int ccsae_get_keys(ccsae_const_ctx_t ctx, uint8_t *kck, uint8_t *pmk, uint8_t *pmkid)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_GET_KEYS_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccsae_get_keys_ws(ws, ctx, kck, pmk, pmkid);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
