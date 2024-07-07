/* Copyright (c) (2014,2015,2018,2019,2021) Apple Inc. All rights reserved.
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
#include "cc_memory.h"
#include "ccec_internal.h"
#include "cczp_internal.h"

static bool ccec_is_compactable_point_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_const_affine_point_t point)
{
    cc_size n = ccec_cp_n(cp);
    
    if (!ccn_is_one(n, ccec_point_z(point, cp))) {
        return false;
    }
    
    bool is_compactable = true;

    CC_DECL_BP_WS(ws, bp);
    cc_unit* t = CC_ALLOC_WS(ws, n);
    
    // Compute t = p - y
    cczp_negate(ccec_cp_zp(cp), t, ccec_point_y(point, cp));
    if (ccn_cmp(n, t, ccec_point_y(point, cp)) < 0) {
        // If t < y, the point is not compactable.
        is_compactable = false;
    }
    
    CC_FREE_BP_WS(ws, bp);
    return is_compactable;
}

bool ccec_is_compactable_pub(ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    cc_size n = ccec_cp_n(cp);
    int status;

    CC_DECL_WORKSPACE_RV(ws, CCEC_IS_COMPACTABLE_POINT_WORKSPACE_N(n), status);
    if (status != CCERR_OK) {
        return false;
    }
    bool output = ccec_is_compactable_point_ws(ws, cp, (ccec_const_affine_point_t)ccec_ctx_point(key));
    CC_FREE_WORKSPACE(ws);

    return output;
}

int ccec_compact_export_pub(void *out, ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    size_t out_nbytes = ccec_compact_export_size_cp(0, cp);
    return ccec_export_affine_point(cp, CCEC_FORMAT_COMPACT, (ccec_const_affine_point_t)ccec_ctx_point(key), &out_nbytes, out);
}

