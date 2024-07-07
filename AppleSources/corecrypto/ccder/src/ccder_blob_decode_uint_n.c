/* Copyright (c) (2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
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

bool ccder_blob_decode_uint_n(ccder_read_blob *from, cc_size *n)
{
    ccder_read_blob int_blob;
    if (!ccder_blob_decode_range(from, CCDER_INTEGER, &int_blob)) {
        return false;
    }
    if (!ccder_blob_decode_uint_skip_leading_zeroes(&int_blob)) {
        return false;
    }
    *n = ccn_nof_size(ccder_blob_size(int_blob));
    return true;
}
