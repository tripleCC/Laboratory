/* Copyright (c) (2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include "cc_macros.h"

/* Implementation per FIPS186-4 */
int ccec_generate_key_internal_fips_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       struct ccrng_state *rng,
                                       ccec_full_ctx_t key)
{
    int result = CCEC_GENERATE_KEY_DEFAULT_ERR;
    cc_size n = ccec_cp_n(cp);

    // Init key structure
    ccec_ctx_init(cp, key);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *random_buf = (uint8_t *)CC_ALLOC_WS(ws, n);

    // Generate the private scalar
    size_t random_size = ccn_sizeof(ccec_cp_prime_bitlen(cp)-1);

    // Burn some random to keep reproducible behavior with previous generated key (24057777)
    cc_require((result = ccrng_generate(rng, random_size, random_buf)) == CCERR_OK, errOut);
    cc_require((result = ccec_generate_scalar_fips_retry_ws(ws, cp, rng, ccec_ctx_k(key))) == CCERR_OK, errOut);

    // Generate the corresponding public key
    result = ccec_make_pub_from_priv_ws(ws, cp, rng, ccec_ctx_k(key), NULL, ccec_ctx_pub(key));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_generate_key_internal_fips(ccec_const_cp_t cp,
                                    struct ccrng_state *rng,
                                    ccec_full_ctx_t key)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_KEY_INTERNAL_FIPS_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_generate_key_internal_fips_ws(ws, cp, rng, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
