/* Copyright (c) (2014,2015,2016,2019,2021) Apple Inc. All rights reserved.
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

/* RFC 5915 */
/* version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), */
/* privateKey     OCTET STRING, */
/* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL, */
/* publicKey  [1] BIT STRING OPTIONAL */

bool
ccder_blob_encode_eckey(ccder_blob *to,
                        size_t priv_byte_size, const uint8_t *cc_sized_by(priv_byte_size) priv_key,
                        ccoid_t oid,
                        size_t pub_byte_size, const uint8_t *cc_sized_by(pub_byte_size) pub_key)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t *der_end = to->der_end;
    
    if (priv_byte_size == 0) {
        return false;
    }
    
    /* publicKey  [1] BIT STRING OPTIONAL */
    if (pub_key && pub_byte_size) {
        const uint8_t zero = 0;
        uint8_t *pub_key_end = to->der_end;
        if (!ccder_blob_encode_body(to, pub_byte_size, pub_key)) {
            return false;
        }
        
        /* The first byte of a bit string's payload contains the number of padding
           bits in the last byte. Logically, the zero byte inserted here is part
           of the tag-length payload of the bit string, but there isn't a good ccder
           primitive to do this in a single operation. */
        if (!ccder_blob_encode_body(to, 1, &zero)) {
            return false;
        }
        if (!ccder_blob_encode_tl(to, CCDER_BIT_STRING, ccder_size(to->der_end, pub_key_end))) {
            return false;
        }
        
        if (!ccder_blob_encode_tl(to, CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|1, ccder_size(to->der_end, pub_key_end))) {
            return false;
        }
    }
    
    /* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL, */
    if (CCOID(oid)) {
        uint8_t *oid_end = to->der_end;
        if (!ccder_blob_encode_oid(to, oid)) {
            return false;
        }
        if (!ccder_blob_encode_tl(to, CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|0, ccder_size(to->der_end, oid_end))) {
            return false;
        }
    }
    
    /* privateKey     OCTET STRING, */
    if (!ccder_blob_encode_raw_octet_string(to, priv_byte_size, priv_key)) {
        return false;
    }
    
    /* version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), */
    if (!ccder_blob_encode_uint64(to, 1)) {
        return false;
    }
    
    /* wrapper */
    if (!ccder_blob_encode_tl(to, CCDER_CONSTRUCTED_SEQUENCE, ccder_size(to->der_end, der_end))) {
        return false;
    }
    
    return true;
}

