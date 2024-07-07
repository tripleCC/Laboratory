/* Copyright (c) (2012,2015,2017,2019) Apple Inc. All rights reserved.
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
ccder_sizeof_implicit_uint64(ccder_tag implicit_tag, uint64_t value) {
    cc_unit s[ccn_nof_sizeof(value)] = { ccn64_v(value) };
    return ccder_sizeof_implicit_integer(implicit_tag, ccn_nof_sizeof(value), s);
}
