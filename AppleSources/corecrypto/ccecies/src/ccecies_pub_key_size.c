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
#include <corecrypto/ccecies.h>

size_t ccecies_pub_key_size(ccec_pub_ctx_t public_key, ccecies_gcm_t ecies)
{
    CC_ENSURE_DIT_ENABLED

    return ccecies_pub_key_size_cp(ccec_ctx_cp(public_key), ecies);
}

size_t ccecies_pub_key_size_cp(ccec_const_cp_t cp, ccecies_gcm_t ecies)
{
    CC_ENSURE_DIT_ENABLED

    size_t public_key_size = 0;

    if (ECIES_EXPORT_PUB_STANDARD == (ecies->options & ECIES_EXPORT_PUB_STANDARD)) {
        public_key_size = ccec_x963_export_size_cp(0, cp);
    } else if (ECIES_EXPORT_PUB_COMPACT == (ecies->options & ECIES_EXPORT_PUB_COMPACT)) {
        public_key_size = ccec_compact_export_size_cp(0, cp);
    } else {
        public_key_size = 0;
    }

    return public_key_size;
}
