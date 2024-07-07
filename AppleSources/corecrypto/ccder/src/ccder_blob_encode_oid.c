/* Copyright (c) (2012,2015,2016,2019,2021-2023) Apple Inc. All rights reserved.
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

const unsigned char *cc_indexable ccoid_payload(ccoid_t oid) {
    return cc_unsafe_forge_bidi_indexable(CCOID(oid), ccoid_size(oid));
}

bool
ccder_blob_encode_oid(ccder_blob *to, ccoid_t oid)
{
    return ccder_blob_encode_body(to, ccoid_size(oid), ccoid_payload(oid));
}
