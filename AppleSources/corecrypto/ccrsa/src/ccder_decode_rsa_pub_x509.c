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

static const uint8_t *get_pub_m_e(const ccrsa_pub_ctx_t pubkey, const uint8_t *der, const uint8_t *der_end) {
    if((der = ccder_decode_constructed_tl(CCDER_BIT_STRING, &der_end, der, der_end)) == NULL) return NULL;
    if(*der == 0) der++; // Skip the null byte
    if((der = ccder_decode_rsa_pub(pubkey, der, der_end)) == NULL) return NULL;
    return der;
}

const uint8_t *ccder_decode_rsa_pub_x509(const ccrsa_pub_ctx_t key, const uint8_t *der, const uint8_t *der_end)
{
    der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end);
    der = get_oid(der, der_end);
    der = get_pub_m_e(key, der, der_end);
    return der;
}
