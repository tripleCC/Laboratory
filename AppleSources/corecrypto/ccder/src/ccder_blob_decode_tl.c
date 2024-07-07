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
#include "ccder_internal.h"

bool
ccder_blob_decode_tl_internal(ccder_read_blob *from, ccder_tag expected_tag, size_t *lenp, bool strict)
{
    ccder_tag tag;
    *lenp = 0;
    
    if (!ccder_blob_decode_tag(from, &tag)) {
        return false;
    }
    
    if (tag != expected_tag) {
        return false;
    }
    
    if (strict) {
        return ccder_blob_decode_len_strict(from, lenp);
    } else {
        return ccder_blob_decode_len(from, lenp);
    }
}

bool ccder_blob_decode_tl_strict(ccder_read_blob *from, ccder_tag expected_tag, size_t *lenp)
{
    return ccder_blob_decode_tl_internal(from, expected_tag, lenp, true);
}

bool ccder_blob_decode_tl(ccder_read_blob *from, ccder_tag expected_tag, size_t *lenp)
{
    return ccder_blob_decode_tl_internal(from, expected_tag, lenp, false);
}
