/* Copyright (c) (2010-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccsha2.h>
#include "ccec_internal.h"
#include "cc_macros.h"

static const uint8_t DRBG_STRING[] = "ccec_generate_key_legacy ccec_pairwise_consistency_check";

CC_INLINE cc_size CCEC_GENERATE_KEY_LEGACY_WORKSPACE_N(cc_size n, const struct ccdrbg_info *info)
{
    return ccn_nof_size(info->size) + n +
        CC_MAX_EVAL(CCEC_GENERATE_KEY_INTERNAL_LEGACY_WORKSPACE_N(n),
                    CCEC_PAIRWISE_CONSISTENCY_CHECK_WORKSPACE_N(n));
}

// Use exactly
// 2 * ccn_sizeof(ccec_cp_order_bitlen(cp)) bytes of random in total.
// Half of the random for the actual generation, the other for the consistency check
// The consistency check may require more random, therefore a DRBG is set to cover
// this case.
int ccec_generate_key_legacy(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccec_cp_n(cp);

    // Create an rng using a drbg.
    // Signature may use a non deterministic amount of random
    // while input rng may be limited (this is the case for PBKDF2).
    // Agnostic of DRBG
    struct ccrng_drbg_state rng_drbg;

    // Set DRBG - NIST HMAC
    struct ccdrbg_nisthmac_custom custom = {
        .di = ccsha256_di(),
        .strictFIPS = 0,
    };

    struct ccdrbg_info info;
    ccdrbg_factory_nisthmac(&info, &custom);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_KEY_LEGACY_WORKSPACE_N(n, &info));

    int rv = ccec_generate_key_internal_legacy_ws(ws, cp, rng, key);
    cc_require(rv == CCERR_OK, errOut);

    // Init the rng drbg
    uint8_t *state = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(info.size));
    struct ccdrbg_state *drbg_state = (struct ccdrbg_state *)state;

    uint8_t *drbg_init_salt = (uint8_t *)CC_ALLOC_WS(ws, n);
    rv = ccrng_generate(rng, ccn_sizeof_n(n), drbg_init_salt);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccdrbg_init(&info, drbg_state, ccn_sizeof_n(n), drbg_init_salt,
                     sizeof(DRBG_STRING), DRBG_STRING, 0, NULL);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccrng_drbg_init_withdrbg(&rng_drbg, &info, drbg_state);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccec_pairwise_consistency_check_ws(ws, key, (struct ccrng_state *)&rng_drbg);
    cc_require_action(rv == CCERR_OK, errOut, rv = CCEC_GENERATE_KEY_CONSISTENCY);

    ccdrbg_done(&info, drbg_state);

errOut:
    CC_FREE_WORKSPACE(ws);
    return rv;
}
