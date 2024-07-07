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
#include <corecrypto/cc_priv.h>
#include "cc_internal.h"

size_t
ccder_sizeof(ccder_tag tag, size_t len)
{
    return ccder_sizeof_tag(tag) + ccder_sizeof_len(len) + len;
}

size_t ccder_sizeof_overflow(ccder_tag tag, size_t nbytes, bool *overflowed)
{
    size_t total_nbytes = 0;
    *overflowed = *overflowed || cc_add_overflow(ccder_sizeof_tag(tag) + ccder_sizeof_len(nbytes), nbytes, &total_nbytes);
    return total_nbytes;
}


