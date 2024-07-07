/* Copyright (c) (2010-2012,2015-2021) Apple Inc. All rights reserved.
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

int ccec_x963_export(const int fullkey, void *out, ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    // Export in the uncompressed format
    int rv = ccec_export_pub(ccec_ctx_public(key), out);
    cc_require_or_return(rv == CCERR_OK, rv);
    
    // Export the secret key if it's a full key
    if (fullkey) {
        ccec_const_cp_t cp = ccec_ctx_cp(key);
        rv = ccn_write_uint_padded_ct(
            ccec_cp_n(cp), ccec_ctx_k(key), ccec_cp_order_size(cp), (uint8_t *)out + ccec_export_pub_size_cp(cp));
        rv = (rv >= 0) ? CCERR_OK : rv; // ignore padding
    }

    return rv;
}
