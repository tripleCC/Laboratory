/* Copyright (c) (2021-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccasn1.h>

bool ccoid_equal(ccoid_t oid1, ccoid_t oid2)
{
    CC_ENSURE_DIT_ENABLED

    if (oid1 == NULL && oid2 == NULL) {
        return true;
    } else if (oid1 == NULL || oid2 == NULL) {
        return false;
    } else {
        return (ccoid_size(oid1) == ccoid_size(oid2)
                && cc_memcmp(ccoid_payload(oid1),
                          ccoid_payload(oid2),
                          ccoid_size(oid1)) == 0);
    }
}

size_t ccoid_size(ccoid_t oid) {
    return 2 + CCOID(oid)[1];
}
