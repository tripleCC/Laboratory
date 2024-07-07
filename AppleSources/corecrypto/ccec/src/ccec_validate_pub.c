/* Copyright (c) (2017-2019,2021,2023) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"

int ccec_validate_pub_ws(cc_ws_t ws, ccec_pub_ctx_t key)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    ccec_projective_point *Q = CCEC_ALLOC_POINT_WS(ws, n);
    int rv = ccec_validate_point_and_projectify_ws(ws, cp, Q, (ccec_const_affine_point_t)ccec_ctx_point(key), NULL);

    CC_FREE_BP_WS(ws, bp);
    return rv;
}

bool ccec_validate_pub(ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);

    int rv;
    CC_DECL_WORKSPACE_RV(ws, CCEC_VALIDATE_PUB_WORKSPACE_N(ccec_cp_n(cp)), rv);
    if (rv != CCERR_OK) {
        return false;
    }

    rv = ccec_validate_pub_ws(ws, key);
    CC_FREE_WORKSPACE(ws);
    return rv == CCERR_OK;
}
