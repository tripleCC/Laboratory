/* Copyright (c) (2012,2015,2017,2019,2021,2022) Apple Inc. All rights reserved.
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

static CC_NODISCARD
bool ccder_blob_decode_range_internal(ccder_read_blob *from, ccder_tag expected_tag, ccder_read_blob *range, bool strict) {
    size_t len;
    if (ccder_blob_decode_tl_internal(from, expected_tag, &len, strict)) {
        /* It's possible that the caller passed in the same object for `from` and `range`,
           expecting the `range` result to prevail. Calculate in local variables and then
           copy to output variables. */
        ccder_read_blob _range = { from->der, from->der + len };
        ccder_read_blob _from = { from->der + len, from->der_end };
        *from = _from;
        *range = _range;
        return true;
    } else {
        range->der = NULL;
        range->der_end = NULL;
        return false;
    }
}

bool ccder_blob_decode_range(ccder_read_blob *from, ccder_tag expected_tag, ccder_read_blob *range_blob)
{
    return ccder_blob_decode_range_internal(from, expected_tag, range_blob, false);
}

bool ccder_blob_decode_range_strict(ccder_read_blob *from, ccder_tag expected_tag, ccder_read_blob *range_blob)
{
    return ccder_blob_decode_range_internal(from, expected_tag, range_blob, true);
}
