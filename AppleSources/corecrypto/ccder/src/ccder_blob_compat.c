/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
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

// MARK: - ccder_encode_ functions

/* Adapting the regular ccder functions to ccder_blob functions requires us to
   cast away constness on the `der` parameter. This is safe because it logically
   belongs to the same memory range as `der_end`, which is not `const`. The
   extra `const` on `der` is only a promise that it will not be dereferenced
   directly. */
CC_NONNULL((1)) CC_INLINE
uint8_t *_ccder_const_cast_der(const uint8_t *der) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    return (uint8_t *)der;
#pragma GCC diagnostic pop
}

#define CCDER_BLOB_INIT(BLOB, BEGIN, END) \
    do { \
        ccder_blob _ccder_blob_init_local_ = { _ccder_const_cast_der(BEGIN), (END) }; \
        if (_ccder_blob_init_local_.der_end == NULL) return NULL; \
        (BLOB) = _ccder_blob_init_local_; \
    } while (0)

#define CCDER_READ_BLOB_INIT(BLOB, BEGIN, END) \
    do { \
        ccder_read_blob _ccder_read_blob_init_local_ = { (BEGIN), (END) }; \
        if (_ccder_read_blob_init_local_.der == NULL) return NULL; \
        (BLOB) = _ccder_read_blob_init_local_; \
    } while (0)

CC_PURE
size_t ccder_encode_eckey_size(size_t priv_size, ccoid_t oid, size_t pub_size)
{
    return ccder_sizeof_eckey(priv_size, oid, pub_size);
}

CC_NONNULL((2))
uint8_t *ccder_encode_tag(ccder_tag tag, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_tag(&blob, tag) ? blob.der_end : NULL;
}

CC_NONNULL((2))
uint8_t *ccder_encode_len(size_t len, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_len(&blob, len) ? blob.der_end : NULL;
}

CC_NONNULL((3))
uint8_t *ccder_encode_tl(ccder_tag tag, size_t len, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_tl(&blob, tag, len) ? blob.der_end : NULL;
}

CC_PURE CC_NONNULL((2))
uint8_t *ccder_encode_body_nocopy(size_t size, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob, range;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_reserve(&blob, size, &range) ? blob.der_end : NULL;
}

CC_NONNULL((2, 3))
uint8_t *ccder_encode_constructed_tl(ccder_tag tag, const uint8_t *body_end, const uint8_t *der, uint8_t *der_end)
{
    return ccder_encode_tl(tag, (size_t)(body_end - der_end), der, der_end);
}

CC_NONNULL((1, 2))
uint8_t *ccder_encode_oid(ccoid_t oid, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_oid(&blob, oid) ? blob.der_end : NULL;
}

CC_NONNULL((3, 4))
uint8_t *ccder_encode_implicit_integer(ccder_tag implicit_tag, cc_size n, const cc_unit *s, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_implicit_integer(&blob, implicit_tag, n, s) ? blob.der_end : NULL;
}

CC_NONNULL((2, 3))
uint8_t *ccder_encode_integer(cc_size n, const cc_unit *s, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_integer(&blob, n, s) ? blob.der_end : NULL;
}

CC_NONNULL((3))
uint8_t *ccder_encode_implicit_uint64(ccder_tag implicit_tag, uint64_t value, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_implicit_uint64(&blob, implicit_tag, value) ? blob.der_end : NULL;
}

CC_NONNULL((2))
uint8_t *ccder_encode_uint64(uint64_t value, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_uint64(&blob, value) ? blob.der_end : NULL;
}

CC_NONNULL((3, 4))
uint8_t *
ccder_encode_implicit_octet_string(ccder_tag implicit_tag, cc_size n, const cc_unit *s, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_implicit_octet_string(&blob, implicit_tag, n, s) ? blob.der_end : NULL;
}

CC_NONNULL((2, 3))
uint8_t *ccder_encode_octet_string(cc_size n, const cc_unit *s, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_octet_string(&blob, n, s) ? blob.der_end : NULL;
}

CC_NONNULL((3, 4))
uint8_t *ccder_encode_implicit_raw_octet_string(ccder_tag implicit_tag,
                                                size_t s_size,
                                                const uint8_t *s,
                                                const uint8_t *der,
                                                uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_implicit_raw_octet_string(&blob, implicit_tag, s_size, s) ? blob.der_end : NULL;
}

CC_NONNULL((2, 3))
uint8_t *ccder_encode_raw_octet_string(size_t s_size, const uint8_t *s, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_raw_octet_string(&blob, s_size, s) ? blob.der_end : NULL;
}

CC_NONNULL((2, 5, 6))
uint8_t *ccder_encode_eckey(size_t priv_size,
                            const uint8_t *priv_key,
                            ccoid_t oid,
                            size_t pub_size,
                            const uint8_t *pub_key,
                            uint8_t *der,
                            uint8_t *der_end)
{
    CC_ENSURE_DIT_ENABLED

    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_eckey(&blob, priv_size, priv_key, oid, pub_size, pub_key) ? blob.der_end : NULL;
}

CC_NONNULL((3))
uint8_t *ccder_encode_body(size_t size, const uint8_t *body, const uint8_t *der, uint8_t *der_end)
{
    ccder_blob blob;
    CCDER_BLOB_INIT(blob, der, der_end);
    return ccder_blob_encode_body(&blob, size, body) ? blob.der_end : NULL;
}

// MARK: - ccder_decode_ functions, non-ptrcheck inline implementations

CC_NONNULL((1, 3))
const uint8_t *ccder_decode_tag(ccder_tag *tagp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_tag(&from, tagp) ? from.der : NULL;
}

CC_NONNULL((1, 3))
const uint8_t *ccder_decode_len(size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_len(&from, lenp) ? from.der : NULL;
}

CC_NONNULL((1, 3))
const uint8_t *ccder_decode_len_strict(size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_len_strict(&from, lenp) ? from.der : NULL;
}

CC_NONNULL((2, 4))
const uint8_t *ccder_decode_tl(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_tl(&from, expected_tag, lenp) ? from.der : NULL;
}

CC_NONNULL((2, 4))
const uint8_t *ccder_decode_tl_strict(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_tl_strict(&from, expected_tag, lenp) ? from.der : NULL;
}

CC_NONNULL((2, 4))
const uint8_t *
ccder_decode_constructed_tl(ccder_tag expected_tag, const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from, range;
    *body_end = der; // in case of error
    CCDER_READ_BLOB_INIT(from, der, der_end);
    if (ccder_blob_decode_range(&from, expected_tag, &range)) {
        *body_end = range.der_end;
        return range.der;
    } else {
        return NULL;
    }
}

CC_NONNULL((2, 4))
const uint8_t *ccder_decode_constructed_tl_strict(ccder_tag expected_tag, const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from, range;
    *body_end = der; // in case of error
    CCDER_READ_BLOB_INIT(from, der, der_end);
    if (ccder_blob_decode_range_strict(&from, expected_tag, &range)) {
        *body_end = range.der_end;
        return range.der;
    } else {
        return NULL;
    }
}

CC_NONNULL((1, 3))
const uint8_t *ccder_decode_sequence_tl(const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from, range;
    *body_end = der; // in case of error
    CCDER_READ_BLOB_INIT(from, der, der_end);
    if (ccder_blob_decode_sequence_tl(&from, &range)) {
        *body_end = range.der_end;
        return range.der;
    } else {
        return NULL;
    }
}

CC_NONNULL((1, 3))
const uint8_t *ccder_decode_sequence_tl_strict(const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from, range;
    *body_end = der; // in case of error
    CCDER_READ_BLOB_INIT(from, der, der_end);
    if (ccder_blob_decode_sequence_tl_strict(&from, &range)) {
        *body_end = range.der_end;
        return range.der;
    } else {
        return NULL;
    }
}

CC_NONNULL((3))
const uint8_t *ccder_decode_uint_n(cc_size *n, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_uint_n(&from, n) ? from.der : NULL;
}

CC_NONNULL((4))
const uint8_t *ccder_decode_uint(cc_size n, cc_unit *r, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_uint(&from, n, r) ? from.der : NULL;
}

CC_NONNULL((4))
const uint8_t *ccder_decode_uint_strict(cc_size n, cc_unit *r, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_uint_strict(&from, n, r) ? from.der : NULL;
}

CC_NONNULL((3))
const uint8_t *ccder_decode_uint64(uint64_t *r, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_uint64(&from, r) ? from.der : NULL;
}

CC_NONNULL((2, 3, 5))
const uint8_t *ccder_decode_seqii(cc_size n, cc_unit *r, cc_unit *s, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_seqii(&from, n, r, s) ? from.der : NULL;
}

CC_NONNULL((2, 3, 5))
const uint8_t *ccder_decode_seqii_strict(cc_size n, cc_unit *r, cc_unit *s, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_seqii_strict(&from, n, r, s) ? from.der : NULL;
}

CC_NONNULL((1, 3))
const uint8_t *ccder_decode_oid(ccoid_t *oidp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from;
    *oidp = NULL;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    return ccder_blob_decode_oid(&from, oidp) ? from.der : NULL;
}

CC_NONNULL((1, 2, 4))
const uint8_t *ccder_decode_bitstring(const uint8_t **bit_string, size_t *bit_length, const uint8_t *der, const uint8_t *der_end)
{
    ccder_read_blob from, returned_bit_string;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    if (ccder_blob_decode_bitstring(&from, &returned_bit_string, bit_length)) {
        *bit_string = returned_bit_string.der;
        return from.der;
    } else {
        *bit_length = 0;
        *bit_string = NULL;
        return NULL;
    }
}

CC_NONNULL((1, 2, 3, 4, 5, 6, 7))
const uint8_t *ccder_decode_eckey(uint64_t *version,
                                  size_t *priv_size,
                                  const uint8_t **priv_key,
                                  ccoid_t *oid,
                                  size_t *pub_bit_count,
                                  const uint8_t **pub_key,
                                  const uint8_t *der,
                                  const uint8_t *der_end)
{
    CC_ENSURE_DIT_ENABLED

    ccder_read_blob from;
    CCDER_READ_BLOB_INIT(from, der, der_end);
    size_t pub_byte_size;
    return ccder_blob_decode_eckey(&from, version, priv_size, priv_key, oid, &pub_byte_size, pub_key, pub_bit_count) ? from.der : NULL;
}
