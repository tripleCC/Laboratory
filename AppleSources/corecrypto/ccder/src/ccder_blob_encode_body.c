/* Copyright (c) (2012,2015,2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>

bool
ccder_blob_encode_body(ccder_blob *to, size_t size, const uint8_t *cc_sized_by(size) body)
{
    // Need to accept body == NULL for consistency with historical callers
    if (body == NULL) {
        return (size == 0);
    }

    ccder_blob body_blob;
    if (!ccder_blob_reserve(to, size, &body_blob)) {
        return false;
    }

    cc_memmove(body_blob.der, body, size);
    return true;
}
