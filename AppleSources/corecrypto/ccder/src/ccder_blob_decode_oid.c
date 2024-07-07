/* Copyright (c) (2012,2015,2016,2021,2022) Apple Inc. All rights reserved.
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

bool ccder_blob_decode_oid(ccder_read_blob *from, ccoid_t *oidp)
{
    // if decoding succeeds, this is what we'll want to use
    ccoid_t oid;
    CCOID(oid) = from->der;

    ccder_read_blob skip_range;
    if (!ccder_blob_decode_range(from, CCDER_OBJECT_IDENTIFIER, &skip_range)) {
        CCOID(*oidp) = NULL;
        return false;
    }

    *oidp = oid;
    return true;
}
