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

#include <corecrypto/ccrsa.h>
#include <corecrypto/ccrsa_priv.h>
#include "cc_internal.h"

cczp_t ccrsa_ctx_private_zp(ccrsa_full_ctx_t fk)
{
    return (cczp_t)ccrsa_unsafe_forge_bidi_indexable(fk, sizeof(struct cczp), 4 * ccrsa_ctx_n(fk) + 1);
}

ccrsa_pub_ctx_t ccrsa_ctx_public(ccrsa_full_ctx_t fk) {
    return (ccrsa_pub_ctx_t) fk;
}

size_t ccrsa_export_pub_size(const ccrsa_pub_ctx_t key) {
    return ccder_encode_rsa_pub_size(key);
}

cc_size ccrsa_import_pub_n(size_t inlen, const uint8_t *cc_sized_by(inlen) der) {
    const uint8_t *local_der = der;
    cc_size size = ccder_decode_rsa_pub_x509_n(local_der, local_der + inlen);
    if(size == 0) {
        size = ccder_decode_rsa_pub_n(local_der, local_der + inlen);
    }
    return size;
}

size_t ccrsa_export_priv_size(const ccrsa_full_ctx_t key) {
    CC_ENSURE_DIT_ENABLED
    
    return ccder_encode_rsa_priv_size(key);
}

int ccrsa_export_priv(const ccrsa_full_ctx_t key, size_t out_len, uint8_t *cc_sized_by(out_len) out) {
    CC_ENSURE_DIT_ENABLED
    
    uint8_t *local_out = out;
    return (ccder_encode_rsa_priv(key, local_out, local_out+out_len) != out);
}

cc_size ccrsa_import_priv_n(size_t inlen, const uint8_t *cc_sized_by(inlen) der) {
    CC_ENSURE_DIT_ENABLED
    
    const uint8_t *local_der = der;
    return ccder_decode_rsa_priv_n(local_der, local_der + inlen);
}

int ccrsa_import_priv(ccrsa_full_ctx_t key, size_t inlen, const uint8_t *cc_sized_by(inlen) der) {
    CC_ENSURE_DIT_ENABLED
    
    const uint8_t *local_der = der;
    return (ccder_decode_rsa_priv(key, local_der, local_der + inlen) == NULL);
}

int ccrsa_oaep_encode(const struct ccdigest_info* di,
                      struct ccrng_state *rng,
                      size_t r_size, cc_unit *cc_counted_by(r_size) r,
                      size_t message_len, const uint8_t *cc_counted_by(message_len) message)
{
    CC_ENSURE_DIT_ENABLED
    
    return ccrsa_oaep_encode_parameter(di, rng, r_size, r, message_len, message, 0, NULL);
}

int ccrsa_oaep_decode(const struct ccdigest_info* di,
                      size_t *r_len, uint8_t *cc_unsafe_indexable r,
                      size_t s_size, cc_unit *cc_counted_by(s_size) s)
{
    CC_ENSURE_DIT_ENABLED
    
    return ccrsa_oaep_decode_parameter(di, r_len, r, s_size, s, 0, NULL);
}

cc_size ccrsa_n_from_size(size_t size) {
    return ccn_nof_size(size);
}

size_t ccrsa_sizeof_n_from_size(size_t size) {
    return ccn_sizeof_n(ccn_nof_size(size));
}

uint8_t *ccrsa_block_start(size_t size, cc_unit *p, int clear_to_start) {
    cc_unit *local_p = p;
    size_t fullsize = ccrsa_sizeof_n_from_size(size);
    size_t offset = fullsize - size;
    if(clear_to_start) cc_clear(offset,local_p);
    return ((uint8_t *) local_p) + offset;
}

size_t ccrsa_block_size(ccrsa_pub_ctx_t key) {
    return ccn_write_uint_size(ccrsa_ctx_n(key), ccrsa_ctx_m(key));
}
