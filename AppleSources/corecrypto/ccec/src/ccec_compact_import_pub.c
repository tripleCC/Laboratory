/* Copyright (c) (2014-2021,2023) Apple Inc. All rights reserved.
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
#include "cc_macros.h"
#include "cc_workspaces.h"
#include "cc_debug.h"

size_t ccec_compact_import_pub_size(size_t in_len)
{
    CC_ENSURE_DIT_ENABLED

    switch (in_len) {
        case 24: return 192;
        case 28: return 224;
        case 32: return 256;
        case 48: return 384;
        case 66: return 521;
        default: return 0;
    }
}

int ccec_compact_import_pub_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    int rv;
    CC_DECL_BP_WS(ws, bp);
    ccec_ctx_init(cp, key);

    rv = ccec_import_affine_point_ws(ws, cp, CCEC_FORMAT_COMPACT, in_len, in, (ccec_affine_point_t)ccec_ctx_point(key));
    cc_require(rv == CCERR_OK, errOut);
    ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1); // Set z since internal representation use projective coordinates

    cc_size n = ccec_cp_n(cp);
    ccec_projective_point *Q = CCEC_ALLOC_POINT_WS(ws, n);
    rv = ccec_validate_point_and_projectify_ws(ws, cp, Q, (ccec_const_affine_point_t)ccec_ctx_point(key), NULL);

    errOut:
        CC_FREE_BP_WS(ws, bp);
        return rv;
}

int ccec_compact_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_COMPACT_IMPORT_PUB_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_compact_import_pub_ws(ws, cp, in_len, in, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
