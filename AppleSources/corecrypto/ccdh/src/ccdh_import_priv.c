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
#include <corecrypto/cczp.h>

static int ccdh_import_priv_ws(cc_ws_t ws, ccdh_const_gp_t gp,
                               size_t in_len, const uint8_t *in,
                               ccdh_full_ctx_t key)
{
    cc_size n = ccdh_gp_n(gp);
    const cc_unit *g = ccdh_gp_g(gp);
    ccdh_ctx_init(gp, ccdh_ctx_public(key));

    cc_unit *x = ccdh_ctx_x(key);
    cc_unit *y = ccdh_ctx_y(key);

    CC_DECL_BP_WS(ws, bp);

    int rv = ccn_read_uint(n, x, in_len, in);
    if (rv) {
        rv = CCDH_INVALID_INPUT;
        goto cleanup;
    }

    if (ccn_cmp(n, x, cczp_prime(ccdh_gp_zp(gp))) >= 0) {
        rv = CCDH_SAFETY_CHECK;
        goto cleanup;
    }

    /* Generate the public key: y=g^x mod p */
    rv = cczp_mm_power_ws(ws, ccdh_gp_zp(gp), y, g, ccdh_gp_prime_bitlen(gp), x);
    if (rv) {
        rv = CCDH_ERROR_DEFAULT;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccdh_import_priv(ccdh_const_gp_t gp,
                     size_t in_len, const uint8_t *in,
                     ccdh_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCDH_IMPORT_PRIV_WORKSPACE_N(ccdh_gp_n(gp)));
    int rv = ccdh_import_priv_ws(ws, gp, in_len, in, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
