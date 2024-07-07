/* Copyright (c) (2012,2015,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccder.h>

size_t
ccder_sizeof_implicit_raw_octet_string(ccder_tag implicit_tag,
                                       size_t s_size) {
    return ccder_sizeof(implicit_tag, s_size);
}


size_t ccder_sizeof_implicit_raw_octet_string_overflow(ccder_tag implicit_tag, size_t s_size, bool *overflowed)
{
    return ccder_sizeof_overflow(implicit_tag, s_size, overflowed);
}
