/* Copyright (c) (2014-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccder.h>
#include "ccec_internal.h"
#include "cc_macros.h"

/* version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), */
/* privateKey     OCTET STRING, */
/* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL, */
/* publicKey  [1] BIT STRING OPTIONAL */


size_t ccec_der_export_priv_size(ccec_full_ctx_t key, ccoid_t key_oid, int include_public)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    size_t priv_size = ccec_cp_order_size(cp);
    size_t pub_size = 0;

    if (include_public) {
        pub_size = ccec_export_pub_size(ccec_ctx_pub(key));
    }

    return ccder_encode_eckey_size(priv_size, key_oid, pub_size);
}

CC_NONNULL((1, 2, 6)) CC_WARN_RESULT
static int ccec_der_export_priv_ws(cc_ws_t ws, ccec_full_ctx_t key, ccoid_t key_oid, int include_public, size_t out_len, void *out)
{
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    size_t priv_size = ccec_cp_order_size(cp);
    uint8_t *priv_key = (uint8_t *)CC_ALLOC_WS(ws, n);

    int rv = ccn_write_uint_padded_ct(n, ccec_ctx_k(key), priv_size, priv_key);
    cc_require_action(rv >= 0, errOut, rv = CCERR_PARAMETER);

    size_t pub_size = 0;
    if (include_public) {
        pub_size = ccec_export_pub_size(ccec_ctx_pub(key));
    }

    cc_assert(ccn_sizeof_n(2 * n + 1) >= ccn_nof_size(pub_size));
    uint8_t *pub_key = (uint8_t *)CC_ALLOC_WS(ws, 2 * n + 1);

    if (include_public) {
        rv = ccec_export_pub(ccec_ctx_pub(key), pub_key);
        cc_require_or_return(rv == CCERR_OK, rv);
    }

    uint8_t *der_end = (uint8_t *)out + out_len;
    uint8_t *tmp = ccder_encode_eckey(priv_size, priv_key, key_oid, pub_size, pub_key, out, der_end);
    cc_require_action(tmp == out, errOut, rv = CCERR_INTERNAL);

    rv = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_der_export_priv(ccec_full_ctx_t key, ccoid_t key_oid, int include_public, size_t out_len, void *out)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_DER_EXPORT_PRIV_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_der_export_priv_ws(ws, key, key_oid, include_public, out_len, out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
