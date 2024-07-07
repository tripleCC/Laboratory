/* Copyright (c) (2012,2015,2019,2021,2022) Apple Inc. All rights reserved.
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

bool
ccder_blob_reserve(ccder_blob *to, size_t size, ccder_blob *reserved)
{
    if (size > ccder_blob_size(*to)) {
        reserved->der = NULL;
        reserved->der_end = NULL;
        return false;
    }

    // It's possible that the caller passed in the same object for `to` and `reserved`,
    // expecting the `reserved` result to prevail. Calculate in local variables and then
    // copy to output variables.
    ccder_blob _reserved = { to->der_end - size, to->der_end };
    ccder_blob _to = { to->der, to->der_end - size };
    *to = _to;
    *reserved = _reserved;
    return true;
}
