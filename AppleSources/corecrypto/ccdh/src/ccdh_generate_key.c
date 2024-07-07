/* Copyright (c) (2011,2015-2022) Apple Inc. All rights reserved.
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
#include "ccdh_internal.h"
#include "cc_macros.h"

static int ccdh_generate_key_ws(cc_ws_t ws, ccdh_const_gp_t gp, struct ccrng_state *rng, ccdh_full_ctx_t key)
{
    int rv;
    ccdh_ctx_init(gp, ccdh_ctx_public(key));
    const cc_unit *g = ccdh_gp_g(gp);

    cc_unit *x = ccdh_ctx_x(key);
    cc_unit *y = ccdh_ctx_y(key);

    CC_DECL_BP_WS(ws, bp);

    /* Generate the private key: x per PKCS #3 */
    cc_require((rv = ccdh_generate_private_key_ws(ws, gp, x, rng)) == CCERR_OK, errOut);

    /* Get maximum bit length of the exponent. */
    size_t ebitlen = ccdh_generate_private_key_bitlen(gp);

    /* Generate the public key: y=g^x mod p */
    cc_require((rv = cczp_mm_power_ws(ws, ccdh_gp_zp(gp), y, g, ebitlen, x)) == CCERR_OK, errOut);

    /* Check that 1 < Y < p-1 and 1 = Y^q (mod p)  */
    cc_require((rv = ccdh_check_pub_ws(ws, gp, ccdh_ctx_public(key))) == CCERR_OK, errOut);

    if (!ccdh_pairwise_consistency_check_ws(ws, gp, rng, key)) {
        rv = CCDH_GENERATE_KEY_CONSISTENCY;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng, ccdh_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCDH_GENERATE_KEY_WORKSPACE_N(ccdh_gp_n(gp)));
    int rv = ccdh_generate_key_ws(ws, gp, rng, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
