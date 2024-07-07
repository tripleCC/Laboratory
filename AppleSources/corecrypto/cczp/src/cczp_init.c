/* Copyright (c) (2011,2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cczp_internal.h"
#include "ccn_internal.h"

/*! @function cczp_init_compute_r2_ws
 @abstract Computes R^2 (mod p).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 */
CC_NONNULL_ALL
static void cczp_init_compute_r2_ws(cc_ws_t ws, cczp_t zp)
{
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);

    // t := 2^(2*w*n) - p
    cc_memset(&t[n], 0xff, ccn_sizeof_n(n));
    ccn_neg(n, t, cczp_prime(zp));

    // r2 := 2^(2*w*n) (mod p)
    ccn_mod_ws(ws, 2 * n, t, n, cczp_r2(zp), cczp_prime(zp));

    CC_FREE_BP_WS(ws, bp);
}

int cczp_init_ws(cc_ws_t ws, cczp_t zp)
{
    const cc_unit *p = cczp_prime(zp);
    cc_size n = cczp_n(zp);

    // Odd moduli >= 3 supported only.
    if ((p[0] & 1) == 0 || (ccn_n(n, p) == 1 && p[0] < 3)) {
        return CCERR_PARAMETER;
    }

    CCZP_FUNCS(zp) = CCZP_FUNCS_DEFAULT;
    CCZP_BITLEN(zp) = ccn_bitlen(cczp_n(zp), cczp_prime(zp));

    // -p[0]^(-1) (mod 2^w)
    cczp_p0inv(zp) = -ccn_invert(p[0]);

    // R^2 (mod p)
    cczp_init_compute_r2_ws(ws, zp);

    return CCERR_OK;
}

int cczp_init(cczp_t zp)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_INIT_WORKSPACE_N(cczp_n(zp)));
    int rv = cczp_init_ws(ws, zp);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
