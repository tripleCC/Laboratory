/* Copyright (c) (2012,2015,2019) Apple Inc. All rights reserved.
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
ccder_sizeof_len(size_t l) {
#if SIZE_MAX <= UINT32_MAX
    /* Return sizeof the asn1 encoding of the length of an octets sized object. */
    return (
            l <= 0x0000007f ? (size_t)1 :
            l <= 0x000000ff ? (size_t)2 :
            l <= 0x0000ffff ? (size_t)3 :
            l <= 0x00ffffff ? (size_t)4 :
            (size_t)5
            );
#elif SIZE_MAX <= UINT64_MAX
    /* Optional 64 bit version */
    return (
            l <= 0x000000000000007f ? (size_t)1 :
            l <= 0x00000000000000ff ? (size_t)2 :
            l <= 0x000000000000ffff ? (size_t)3 :
            l <= 0x0000000000ffffff ? (size_t)4 :
            l <= 0x00000000ffffffff ? (size_t)5 :
            l <= 0x000000ffffffffff ? (size_t)6 :
            l <= 0x0000ffffffffffff ? (size_t)7 :
            l <= 0x00ffffffffffffff ? (size_t)8 :
            (size_t)9
            );
#else
#error unsupported sizeof(size_t)
#endif
}
