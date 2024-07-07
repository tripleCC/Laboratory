/* Copyright (c) (2011,2012,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

size_t ccec_x963_import_priv_size(size_t in_len)
{
    CC_ENSURE_DIT_ENABLED

    switch (in_len) {
        case 73: return 192;
        case 85: return 224;
        case 97: return 256;
        case 145: return 384;
        case 199: return 521;
        default: return 0;
    }
}

int ccec_x963_import_priv_ws(cc_ws_t ws,
                             ccec_const_cp_t cp,
                             size_t in_len,
                             const uint8_t *in,
                             ccec_full_ctx_t key)
{
    // Type byte must be 4, 6 or 7 (with 6 and 7 being legacy).
    cc_require_or_return(in[0] == 4 || in[0] == 6 || in[0] == 7, CCERR_PARAMETER);

    // Check that the size contains at least the private key
    cc_require_or_return(in_len >= ccec_cp_order_size(cp), CCERR_PARAMETER);

    CC_DECL_BP_WS(ws, bp);

    // Read the public key
    int rv = ccec_x963_import_pub_ws(ws, cp, in_len - ccec_cp_order_size(cp), in, ccec_ctx_public(key));
    cc_require(rv == CCERR_OK, errOut);

    // Read the private key
    rv = ccn_read_uint(ccec_cp_n(cp), ccec_ctx_k(key), ccec_cp_order_size(cp), in + ccec_x963_export_size_cp(0, cp));
    cc_require(rv == CCERR_OK, errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_x963_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_X963_IMPORT_PRIV_WORKSPACE_N(ccec_cp_n(cp)));
    int result = ccec_x963_import_priv_ws(ws, cp, in_len, in, key);
    CC_FREE_WORKSPACE(ws);
    return result;
}
