/* Copyright (c) (2010,2011,2014-2021,2023) Apple Inc. All rights reserved.
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

void cczp_sqr_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_size n = cczp_n(zp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, n, rbig, x);
    cczp_mod_ws(ws, zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

CC_WORKSPACE_OVERRIDE(cczp_sqr_ws, cczp_sqr_default_ws)

void cczp_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CCZP_FUNCS_GET(zp, cczp_sqr)(ws, zp, r, x);
}

int cczp_sqr(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_SQR_WORKSPACE_N(cczp_n(zp)));
    cczp_sqr_ws(ws, zp, r, x);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
