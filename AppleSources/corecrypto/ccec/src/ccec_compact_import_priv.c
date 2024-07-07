/* Copyright (c) (2014-2019,2021) Apple Inc. All rights reserved.
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
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccec_internal.h"

size_t ccec_compact_import_priv_size(size_t in_len)
{
    CC_ENSURE_DIT_ENABLED

    switch (in_len) {
        case 48: return 192;
        case 56: return 224;
        case 64: return 256;
        case 96: return 384;
        case 132: return 521;
        default: return 0;
    }
}

int ccec_compact_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    // Length must be that of an element mod p and an element mod q
    cc_require_or_return(in_len == (ccec_cp_prime_size(cp) + ccec_cp_order_size(cp)), CCEC_COMPACT_POINT_ENCODING_ERROR);

    int result;

    // Init struct
    ccec_ctx_init(cp, key);

    // Import the public part
    result = ccec_compact_import_pub(cp, ccec_cp_prime_size(cp), in, ccec_ctx_pub(key));
    cc_require(result == CCERR_OK, errOut);

    // Import the private part
    result = ccn_read_uint(ccec_cp_n(cp), ccec_ctx_k(key), ccec_cp_order_size(cp), in + ccec_cp_prime_size(cp));
errOut:
    return result;
}
