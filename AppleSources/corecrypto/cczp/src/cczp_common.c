/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cczp.h>

cc_size cczp_n(cczp_const_t zp)
{
    return CCZP_N(zp);
}

size_t cczp_bitlen(cczp_const_t zp)
{
    cc_assert(ccn_bitlen(cczp_n(zp), cczp_prime(zp)) == CCZP_BITLEN(zp));
    return (size_t)CCZP_BITLEN(zp);
}
