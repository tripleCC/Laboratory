/* Copyright (c) (2012,2015,2016,2019,2021) Apple Inc. All rights reserved.
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

/* RFC 5915

 ECPrivateKey ::= SEQUENCE {
 version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 privateKey     OCTET STRING,
 parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 publicKey  [1] BIT STRING OPTIONAL

 }
*/

bool
ccder_blob_decode_eckey(ccder_read_blob *from, uint64_t *version,
                        size_t *priv_key_byte_size, const uint8_t *cc_sized_by(*priv_key_byte_size) *priv_key,
                        ccoid_t *oid,
                        size_t *pub_key_byte_size, const uint8_t *cc_sized_by(*pub_key_byte_size) *pub_key,
                        size_t *pub_key_bit_count) {
    CC_ENSURE_DIT_ENABLED

    ccder_read_blob inner_blob;
    ccder_read_blob sequence;
    if (!ccder_blob_decode_sequence_tl(from, &sequence)) {
        return false;
    }
    
    /*  version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), */
    if (!ccder_blob_decode_uint64(&sequence, version)) {
        return false;
    }
    if (*version != 1) {
        return false;
    }
    
    /* privateKey     OCTET STRING, */
    if (!ccder_blob_decode_range(&sequence, CCDER_OCTET_STRING, &inner_blob)) {
        return false;
    }
    *priv_key = inner_blob.der;
    *priv_key_byte_size = ccder_blob_size(inner_blob);
    
    /* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL, */
    ccder_read_blob at_oid = sequence;
    if (!ccder_blob_decode_range(&at_oid, CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|0, &inner_blob)) {
        *oid = (ccoid_t) { NULL };
    } else if (ccder_blob_decode_oid(&inner_blob, oid)) {
        sequence = at_oid;
    } else {
        return false;
    }
    
    /* publicKey  [1] BIT STRING OPTIONAL */
    ccder_read_blob at_pub_key = sequence;
    if (!ccder_blob_decode_range(&at_pub_key, CCDER_CONTEXT_SPECIFIC|CCDER_CONSTRUCTED|1, &inner_blob)) {
        *pub_key = NULL;
        *pub_key_byte_size = 0;
        *pub_key_bit_count = 0;
    } else if (ccder_blob_decode_bitstring(&inner_blob, &inner_blob, pub_key_bit_count)) {
        *pub_key = inner_blob.der;
        *pub_key_byte_size = ccder_blob_size(inner_blob);
        sequence = at_pub_key;
    } else {
        return false;
    }
    
    return true;
}

