/* Copyright (c) (2015,2019,2021-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccder.h>

#include "cc_memory.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

/* ECRandomizedPublicKey ::=   SEQUENCE {
 generator    OCTET STRING,
 publicKey    OCTET STRING
 } */

size_t ccec_der_export_diversified_pub_size(ccec_pub_ctx_t diversified_generator,
                                            ccec_pub_ctx_t diversified_key,
                                            unsigned long flags)
{
    CC_ENSURE_DIT_ENABLED

    size_t len;

    if (flags & CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS) {
        len = ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE,
                           ccder_sizeof_raw_octet_string(ccec_compact_export_size(0, diversified_key))
                         + ccder_sizeof_raw_octet_string(ccec_compact_export_size(0, diversified_generator)));
    } else {
        len = ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE,
                           ccder_sizeof_raw_octet_string(ccec_x963_export_size(0, diversified_key))
                         + ccder_sizeof_raw_octet_string(ccec_x963_export_size(0, diversified_generator)));
    }

    return len;
}

static uint8_t* ccec_der_export_diversified_pub_ws(cc_ws_t ws,
                                                   ccec_pub_ctx_t diversified_generator,
                                                   ccec_pub_ctx_t diversified_key,
                                                   unsigned long flags,
                                                   size_t der_len,
                                                   uint8_t *der)
{
    int status;
    uint8_t *der_end = der + der_len;
    uint8_t *tmp_end = NULL;

    ccec_const_cp_t cp = ccec_ctx_cp(diversified_key);
    cc_size n = ccec_cp_n(cp);
    CC_DECL_BP_WS(ws, bp);

    size_t compact_nbytes = ccec_compact_export_size(0 /* full=false */, diversified_key);
    size_t x963_nbytes = ccec_x963_export_size(0 /* full=false */, diversified_key);

    cc_assert(ccn_sizeof_n(2 * n + 1) >= ccn_nof_size(compact_nbytes));
    uint8_t *tmp_key = (uint8_t *)CC_ALLOC_WS(ws, 2 * n + 1);
    uint8_t *tmp_gen = (uint8_t *)CC_ALLOC_WS(ws, 2 * n + 1);

    if (flags & CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS) {
        status = ccec_compact_export_pub(tmp_key, diversified_key);
        cc_require_or_return(status == CCERR_OK, NULL);
        status = ccec_compact_export_pub(tmp_gen, diversified_generator);
        cc_require_or_return(status == CCERR_OK, NULL);

        tmp_end = ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, der_end, der,
                                              ccder_encode_raw_octet_string(compact_nbytes, tmp_gen, der,
                                              ccder_encode_raw_octet_string(compact_nbytes, tmp_key, der, der_end)));
    } else {
        status = ccec_export_pub(diversified_key, tmp_key);
        cc_require_or_return(status == CCERR_OK, NULL);
        status = ccec_export_pub(diversified_generator, tmp_gen);
        cc_require_or_return(status == CCERR_OK, NULL);

        tmp_end = ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, der_end, der,
                                              ccder_encode_raw_octet_string(x963_nbytes, tmp_gen, der,
                                              ccder_encode_raw_octet_string(x963_nbytes, tmp_key, der, der_end)));
    }

    CC_FREE_BP_WS(ws, bp);
    return tmp_end;
}

uint8_t* ccec_der_export_diversified_pub(ccec_pub_ctx_t diversified_generator,
                                         ccec_pub_ctx_t diversified_key,
                                         unsigned long flags,
                                         size_t der_len,
                                         uint8_t *der)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(diversified_key);

    int rv;
    CC_DECL_WORKSPACE_RV(ws, CCEC_DER_EXPORT_DIVERSIFIED_PUB_WORKSPACE_N(ccec_cp_n(cp)), rv);
    if (rv) {
        return NULL;
    }

    uint8_t *der_end = ccec_der_export_diversified_pub_ws(ws, diversified_generator, diversified_key, flags, der_len, der);
    CC_FREE_WORKSPACE(ws);
    return der_end;
}
