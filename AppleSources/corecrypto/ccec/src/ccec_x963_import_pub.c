/* Copyright (c) (2010-2012,2015,2016,2019-2021,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "cc_memory.h"
#include "ccec_internal.h"

size_t ccec_x963_import_pub_size(size_t in_len)
{
    CC_ENSURE_DIT_ENABLED

    switch (in_len) {
    case 49:
        return 192;
    case 57:
        return 224;
    case 65:
        return 256;
    case 97:
        return 384;
    case 133:
        return 521;
    default:
        return 0;
    }
}

int ccec_x963_import_pub_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    if (in_len == 0) {
        return CCERR_PARAMETER;
    }

    // Does not import the point at infinity.
    if (in_len == 1 && in[0] == 0x00) {
        return CCEC_KEY_CANNOT_BE_UNIT;
    }
    
    // Deduce the format from the value of the first byte
    int format;
    if (in[0] == 0x02 || in[0] == 0x03) {
        format = CCEC_FORMAT_COMPRESSED;
    } else if (in[0] == 0x04) {
        format = CCEC_FORMAT_UNCOMPRESSED;
    } else if (in[0] == 0x06 || in[0] == 0x07) {
        format = CCEC_FORMAT_HYBRID;
    } else {
        return CCERR_PARAMETER;
    }
    
    int rv;
    CC_DECL_BP_WS(ws, bp);
    ccec_ctx_init(cp, key);
    rv = ccec_import_affine_point_ws(ws, cp, format, in_len, in, (ccec_affine_point_t)ccec_ctx_point(key));
    cc_require(rv == CCERR_OK, errOut);
    ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1);
    
    cc_size n = ccec_cp_n(cp);
    ccec_projective_point *Q = CCEC_ALLOC_POINT_WS(ws, n);
    rv = ccec_validate_point_and_projectify_ws(ws, cp, Q, (ccec_const_affine_point_t)ccec_ctx_point(key), NULL);
    
    errOut:
        CC_FREE_BP_WS(ws, bp);
        return rv;
}

int ccec_x963_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_X963_IMPORT_PUB_WORKSPACE_N(ccec_cp_n(cp)));
    int result = ccec_x963_import_pub_ws(ws, cp, in_len, in, key);
    CC_FREE_WORKSPACE(ws);
    return result;
}
