/* Copyright (c) (2015,2019,2021,2022) Apple Inc. All rights reserved.
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

static const uint8_t *get_oid(const uint8_t *der, const uint8_t *der_end) {
    ccoid_t oid;
    if((der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end)) == NULL) return NULL;
    if((der = ccder_decode_oid(&oid, der, der_end)) == NULL) return NULL;
    if((der = ccder_decode_constructed_tl(CCASN1_NULL, &der_end, der, der_end)) == NULL) return NULL;
    return der;
}

static cc_size get_pub_n(const uint8_t *der, const uint8_t *der_end) {
    if((der = ccder_decode_constructed_tl(CCDER_BIT_STRING, &der_end, der, der_end)) == NULL) return 0;
    if(*der == 0) der++; // Skip the null byte
    return ccder_decode_rsa_pub_n(der, der_end);
}

cc_size ccder_decode_rsa_pub_x509_n(const uint8_t *der, const uint8_t *der_end)
{
    if((der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end)) == NULL) return 0;
    if((der = get_oid(der, der_end)) == NULL) return 0;
    return get_pub_n(der, der_end);
}
