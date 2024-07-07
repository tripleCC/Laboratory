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
ccder_blob_encode_implicit_octet_string(ccder_blob *to, ccder_tag implicit_tag,
                                        cc_size n, const cc_unit *cc_counted_by(n) s)
{
    ccder_blob int_body;
    if (!ccder_blob_reserve_tl(to, implicit_tag, ccn_write_uint_size(n, s), &int_body)) {
        return false;
    }
    ccn_write_int(n, s, ccder_blob_size(int_body), int_body.der);
    return true;
}
