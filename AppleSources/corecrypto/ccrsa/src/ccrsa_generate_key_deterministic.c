/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccaes.h>
#include "ccrsa_internal.h"
#include "cc_macros.h"

CC_INLINE cc_size CCRSA_GENERATE_KEY_DETERMINISTIC_WORKSPACE_N(size_t nbits, const struct ccdrbg_info *info)
{
    cc_size n = ccn_nof(nbits);
    return CCRSA_GENERATE_KEY_INTERNAL_WORKSPACE_N(n) + ccn_nof_size(info->size);
}

int ccrsa_generate_key_deterministic(size_t nbits,
                                     ccrsa_full_ctx_t fk,
                                     size_t e_nbytes,
                                     const uint8_t *e,
                                     size_t entropy_nbytes,
                                     const uint8_t *entropy,
                                     size_t nonce_nbytes,
                                     const uint8_t *nonce,
                                     uint32_t flags,
                                     struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    // This is the only mode currently supported.
    if (flags != CCRSA_GENKEY_DETERMINISTIC_LEGACY) {
        return CCERR_PARAMETER;
    }

    int rv;
    ccdrbg_df_bc_ctx_t df_ctx;
    rv = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           16);
    cc_require_or_return(rv == CCERR_OK, rv);

    struct ccdrbg_nistctr_custom custom = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 16,
        .strictFIPS = 0,
        .df_ctx = (ccdrbg_df_ctx_t *)&df_ctx,
    };

    struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_GENERATE_KEY_DETERMINISTIC_WORKSPACE_N(nbits, &info));

    uint8_t *state = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(info.size));
    struct ccdrbg_state *drbg_state = (struct ccdrbg_state *)state;

    rv = ccdrbg_init(&info, drbg_state, entropy_nbytes, entropy, nonce_nbytes, nonce, 0, NULL);
    cc_require(rv == CCERR_OK, errOut);

    struct ccrng_drbg_state drbg_ctx;
    rv = ccrng_drbg_init_withdrbg(&drbg_ctx, &info, drbg_state);
    cc_require(rv == CCERR_OK, errOut);

    struct ccrng_state *det_rng = (struct ccrng_state *)&drbg_ctx;
    rv = ccrsa_generate_key_internal_ws(ws, nbits, fk, e_nbytes, e, det_rng, rng);
    cc_require(rv == CCERR_OK, errOut);

    ccdrbg_done(&info, drbg_state);

errOut:
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
