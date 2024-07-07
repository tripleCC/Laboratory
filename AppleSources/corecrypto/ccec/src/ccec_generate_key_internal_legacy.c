/* Copyright (c) (2010-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrng.h>
#include "ccec_internal.h"
#include "cc_macros.h"

// Use ccn_sizeof(ccec_cp_order_bitlen(cp)) bytes for the key generation
int ccec_generate_key_internal_legacy_ws(cc_ws_t ws, ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key)
{
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    // Init key structure
    ccec_ctx_init(cp, key);

    uint8_t *entropy = (uint8_t *)CC_ALLOC_WS(ws, n);
    int rv = ccrng_generate(rng, ccn_sizeof_n(n), entropy);
    cc_require(rv == CCERR_OK, errOut);

    // Generate the scalar
    rv = ccec_generate_scalar_legacy_ws(ws, cp, ccn_sizeof_n(n), entropy, ccec_ctx_k(key));
    cc_require(rv == CCERR_OK, errOut);

    // Calculate the public key for k
    rv = ccec_make_pub_from_priv_ws(ws, cp, NULL, ccec_ctx_k(key), NULL, ccec_ctx_pub(key));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
