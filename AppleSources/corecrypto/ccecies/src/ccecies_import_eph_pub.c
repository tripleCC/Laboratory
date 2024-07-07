/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccecies_priv.h>
#include "ccecies_internal.h"
#include "ccec_internal.h"
#include "cc_macros.h"

int ccecies_import_eph_pub_ws(cc_ws_t ws,
                              ccec_const_cp_t cp,
                              const ccecies_gcm_t ecies,
                              size_t in_len,
                              const uint8_t *in,
                              ccec_pub_ctx_t key)
{
    int status = CCERR_INTERNAL;
    size_t pub_key_len = in_len;
    uint32_t options = ecies->options;

    CC_DECL_BP_WS(ws, bp);

    if (ECIES_EXPORT_PUB_STANDARD == (options & ECIES_EXPORT_PUB_STANDARD)) {
        pub_key_len = ccec_x963_export_size_cp(0, cp);
        cc_require_action(pub_key_len <= in_len, errOut, status = CCERR_PARAMETER);
        status = ccec_x963_import_pub_ws(ws, cp, pub_key_len, in, key);
    } else if (ECIES_EXPORT_PUB_COMPACT == (options & ECIES_EXPORT_PUB_COMPACT)) {
        pub_key_len = ccec_compact_export_size_cp(0, cp);
        cc_require_action(pub_key_len <= in_len, errOut, status = CCERR_PARAMETER);
        status = ccec_compact_import_pub_ws(ws, cp, pub_key_len, in, key);
    } else {
        status = CCERR_CRYPTO_CONFIG;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccecies_import_eph_pub(ccec_const_cp_t cp,
                           const ccecies_gcm_t ecies,
                           size_t in_len,
                           const uint8_t *in,
                           ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCECIES_IMPORT_EPH_PUB_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccecies_import_eph_pub_ws(ws, cp, ecies, in_len, in, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
