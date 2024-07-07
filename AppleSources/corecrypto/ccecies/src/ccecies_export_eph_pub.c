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

#include <corecrypto/ccecies.h>
#include "ccecies_internal.h"

int ccecies_export_eph_pub(const uint32_t options, ccec_pub_ctx_t key, void *out)
{
    int status = CCERR_PARAMETER;

    if (ECIES_EXPORT_PUB_STANDARD == (options & ECIES_EXPORT_PUB_STANDARD)) {
        status = ccec_export_pub(key, out);
    } else if (ECIES_EXPORT_PUB_COMPACT == (options & ECIES_EXPORT_PUB_COMPACT)) {
        status = ccec_compact_export_pub(out, key);
    }

    return status;
}
