/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include "cc_macros.h"
#include "ccec_internal.h"
#include "cc_workspaces.h"
#include "cc_debug.h"

#define MAX_RETRY 100

/* Make a scalar k in the good range and without bias */
/* Implementation per FIPS186-4 - "TestingCandidates" */
int ccec_generate_scalar_fips_retry_ws(cc_ws_t ws, ccec_const_cp_t cp,
                                       struct ccrng_state *rng, cc_unit *k)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zq);

    CC_DECL_BP_WS(ws, bp);

    /* Need to test candidate against q-2 */
    cc_unit *qm1 = CC_ALLOC_WS(ws, n);
    ccn_set(n, qm1, cczp_prime(zq));
    qm1[0] &= ~CC_UNIT_C(1);

    /* Generate adequate random for private key */
    size_t i;
    for (i = 0; i < MAX_RETRY; i++) {
        /* Random bits */
        cc_require(((result = ccn_random_bits_fips(ccec_cp_order_bitlen(cp), k, rng)) == 0),errOut);

        /* If k <= q-2, the number is valid */
        if (ccn_cmp(n, k, qm1) < 0) {
            break;
        }
    }
    cc_require_action(i < MAX_RETRY,errOut,result=CCEC_GENERATE_KEY_TOO_MANY_TRIES);

    /* k is now in range [ 0, q-2 ] ==> +1 for range [ 1, q-1 ] */
    ccn_add1_ws(ws, n, k, k, 1);
    result=0;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_generate_scalar_fips_retry(ccec_const_cp_t cp, struct ccrng_state *rng, cc_unit *k)
{
    CC_ENSURE_DIT_ENABLED

    cczp_const_t zq = ccec_cp_zq(cp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_SCALAR_FIPS_RETRY_WORKSPACE_N(cczp_n(zq)));
    int rv = ccec_generate_scalar_fips_retry_ws(ws, cp, rng, k);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
