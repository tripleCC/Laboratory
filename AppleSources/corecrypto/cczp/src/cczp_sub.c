/* Copyright (c) (2010-2012,2015-2023) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "cc_workspaces.h"

void cczp_sub_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = cczp_n(zp);

    cc_unit b = ccn_sub_ws(ws, n, r, x, y);
    (void)ccn_cond_add(n, b, r, r, cczp_prime(zp));

    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);

    CC_FREE_BP_WS(ws, bp);
}

CC_WORKSPACE_OVERRIDE(cczp_sub_ws, cczp_sub_default_ws)

void cczp_sub_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    CCZP_FUNCS_GET(zp, cczp_sub)(ws, zp, r, x, y);
}

int cczp_sub(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_SUB_WORKSPACE_N(cczp_n(zp)));
    cczp_sub_ws(ws, zp, r, x, y);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
