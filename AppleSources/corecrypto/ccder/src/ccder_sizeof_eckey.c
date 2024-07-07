/* Copyright (c) (2021) Apple Inc. All rights reserved.
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
ccder_sizeof_eckey(size_t priv_size, ccoid_t oid, size_t pub_size)
{
    size_t size =
    ccder_sizeof_uint64(1) +
    ccder_sizeof(CCASN1_OCTET_STRING, priv_size);

    if (CCOID(oid))
        size += ccder_sizeof(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|0, ccder_sizeof_oid(oid));

    if (pub_size) {
        size_t bitlen = ccder_sizeof(CCDER_BIT_STRING, pub_size + 1);
        size += ccder_sizeof(CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|1, bitlen);
    }

    return ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE, size);
}
