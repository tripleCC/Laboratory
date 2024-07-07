/* Copyright (c) (2012,2015,2019-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccder.h>

// Key is expected to be in PKCS #1 format
cc_size ccder_decode_rsa_pub_n(const uint8_t *der, const uint8_t *der_end)
{
    cc_size n;
    if((der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end)) == NULL) return 0;
    if(ccder_decode_uint_n(&n, der, der_end) == NULL) return 0;
    return n;
}
