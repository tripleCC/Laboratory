/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef CCDER_MULTIBYTE_TAGS
#define CCDER_MULTIBYTE_TAGS 1
#endif // CCDER_MULTIBYTE_TAGS

#include <corecrypto/ccder.h>

#include "testmore.h"
#include "testbyteBuffer.h"
#include "crypto_test_der.h"
#include "cc_priv.h"

#if (CCDER == 0)
entryPoint(ccder_tests, "ccder")
#else

//============================= ccder_sizeof ===================================

static void testSizeOf(void)
{
    is(ccder_sizeof(CCDER_EOL, 0), (size_t)2, "EOL");
    is(ccder_sizeof(CCDER_BOOLEAN, 0), (size_t)2, "BOOLEAN");
    is(ccder_sizeof(CCDER_INTEGER, 0), (size_t)2, "INTEGER");
    is(ccder_sizeof(CCDER_BIT_STRING, 0), (size_t)2, "BIT_STRING");
    is(ccder_sizeof(CCDER_OCTET_STRING, 0), (size_t)2, "OCTET_STRING");
    is(ccder_sizeof(CCDER_NULL, 0), (size_t)2, "NULL");
    is(ccder_sizeof(CCDER_OBJECT_IDENTIFIER, 0), (size_t)2, "OBJECT_IDENTIFIER");
    is(ccder_sizeof(CCDER_REAL, 0), (size_t)2, "REAL");
    is(ccder_sizeof(CCDER_ENUMERATED, 0), (size_t)2, "ENUMERATED");
    is(ccder_sizeof(CCDER_EMBEDDED_PDV, 0), (size_t)2, "EMBEDDED_PDV");
    is(ccder_sizeof(CCDER_UTF8_STRING, 0), (size_t)2, "UTF8_STRING");
    is(ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE, 0), (size_t)2, "CONSTRUCTED_SEQUENCE");
    is(ccder_sizeof(CCDER_CONSTRUCTED_SET, 0), (size_t)2, "CONSTRUCTED_SET");
    is(ccder_sizeof(CCDER_NUMERIC_STRING, 0), (size_t)2, "NUMERIC_STRING");
    is(ccder_sizeof(CCDER_PRINTABLE_STRING, 0), (size_t)2, "PRINTABLE_STRING");
    is(ccder_sizeof(CCDER_T61_STRING, 0), (size_t)2, "T61_STRING");
    is(ccder_sizeof(CCDER_VIDEOTEX_STRING, 0), (size_t)2, "VIDEOTEX_STRING");
    is(ccder_sizeof(CCDER_IA5_STRING, 0), (size_t)2, "IA5_STRING");
    is(ccder_sizeof(CCDER_UTC_TIME, 0), (size_t)2, "UTC_TIME");
    is(ccder_sizeof(CCDER_GENERALIZED_TIME, 0), (size_t)2, "GENERALIZED_TIME");
    is(ccder_sizeof(CCDER_GRAPHIC_STRING, 0), (size_t)2, "GRAPHIC_STRING");
    is(ccder_sizeof(CCDER_VISIBLE_STRING, 0), (size_t)2, "VISIBLE_STRING");
    is(ccder_sizeof(CCDER_GENERAL_STRING, 0), (size_t)2, "GENERAL_STRING");
    is(ccder_sizeof(CCDER_UNIVERSAL_STRING, 0), (size_t)2, "UNIVERSAL_STRING");
    is(ccder_sizeof(CCDER_BMP_STRING, 0), (size_t)2, "BMP_STRING");
    is(ccder_sizeof(CCDER_HIGH_TAG_NUMBER, 0), (size_t)3, "HIGH_TAG_NUMBER");
    is(ccder_sizeof(0x1f, 0), (size_t)3, "[31]");
    is(ccder_sizeof(0x20, 0), (size_t)3, "[32]");
    is(ccder_sizeof(0x7f, 0), (size_t)3, "[127]");
    is(ccder_sizeof(0x80, 0), (size_t)4, "[128]");
    is(ccder_sizeof(0x3fff, 0), (size_t)4, "[4095]");
    is(ccder_sizeof(0x4000, 0), (size_t)5, "[4096]");
    is(ccder_sizeof(0x1fffff, 0), (size_t)5, "[2097151]");
    is(ccder_sizeof(0x200000, 0), (size_t)6, "[2097152]");

    is(ccder_sizeof(CCDER_OCTET_STRING, 1), (size_t)3, "OCTET_STRING(1)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 127), (size_t)129, "OCTET_STRING(127)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 128), (size_t)131, "OCTET_STRING(128)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 129), (size_t)132, "OCTET_STRING(129)");
    
    size_t out_nbytes;
    bool overflowed = false;
    out_nbytes = ccder_sizeof_overflow(CCDER_OCTET_STRING, 1, &overflowed);
    is(overflowed, false, "Should not overflow");
    is(out_nbytes, (size_t)3, "OCTET_STRING(1)");
    
    // We should catch the overflow even if we call the function again
    out_nbytes = ccder_sizeof_overflow(CCDER_OCTET_STRING, (size_t) -1, &overflowed);
    out_nbytes += ccder_sizeof_overflow(CCDER_OCTET_STRING, 1, &overflowed);
    is(overflowed, true, "Should overflow");
}

//============================= ccder_sizeof_uint64 ============================

static void testSizeOfUInt64(void)
{
    is(ccder_sizeof_uint64(0), (size_t)3, "uint64(0)");
    is(ccder_sizeof_uint64(1), (size_t)3, "uint64(1)");
    is(ccder_sizeof_uint64(0x7f), (size_t)3, "uint64(0x7f)");
    is(ccder_sizeof_uint64(0x80), (size_t)4, "uint64(0x80)");
    is(ccder_sizeof_uint64(0x100), (size_t)4, "uint64(0x100)");
    is(ccder_sizeof_uint64(0x7fff), (size_t)4, "uint64(0x7fff)");
    is(ccder_sizeof_uint64(0x8000), (size_t)5, "uint64(0x8000)");
    is(ccder_sizeof_uint64(0x7fffff), (size_t)5, "uint64(0x7fffff)");
    is(ccder_sizeof_uint64(0x800000), (size_t)6, "uint64(0x800000)");
    is(ccder_sizeof_uint64(0x7fffffff), (size_t)6, "uint64(0x7fffffff)");
    is(ccder_sizeof_uint64(0x80000000), (size_t)7, "uint64(0x80000000)");
    is(ccder_sizeof_uint64(0x7fffffffff), (size_t)7, "uint64(0x7fffffffff)");
    is(ccder_sizeof_uint64(0x8000000000), (size_t)8, "uint64(0x8000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffff), (size_t)8, "uint64(0x7fffffffffff)");
    is(ccder_sizeof_uint64(0x800000000000), (size_t)9, "uint64(0x800000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffffff), (size_t)9, "uint64(0x7fffffffffffff)");
    is(ccder_sizeof_uint64(0x80000000000000), (size_t)10, "uint64(0x80000000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffffffff), (size_t)10, "uint64(0x7fffffffffffffff)");
}

//================================ ccder_encode_tag ============================

static void testEncodeTag(void)
{
    // Test that the result is NULL if der_end is NULL
    uint8_t begin;
    is(ccder_encode_tag(CCDER_BOOLEAN, &begin, NULL), NULL, "ccder_encode_tag NULL der_end");
    
    // These define the length bounds for tags
    unsigned long limits[] = {0x7f, 0x3fff, 0x1fffff, 0xfffffff, 0x10000000};
    for (size_t i = 0; i < CC_ARRAY_LEN(limits); i++) {
        ccder_tag tag = limits[i] & CCDER_TAGNUM_MASK;

        size_t length = i + 1; // this length is too short
        uint8_t *invalid_der = malloc(length);
        if (invalid_der) {
            uint8_t *der_start = invalid_der;
            uint8_t *der_end = invalid_der + length;
            uint8_t *new_der_end = ccder_encode_tag(tag, der_start, der_end);
            is(new_der_end, NULL, "ccder_encode_tag");
            free(invalid_der);
        }

        length = i + 2;
        uint8_t *valid_der = malloc(length);
        if (valid_der) {
            uint8_t *der_start = valid_der;
            uint8_t *der_end = valid_der + length;
            uint8_t *new_der_end = ccder_encode_tag(tag, der_start, der_end);
            isnt(new_der_end, NULL, "ccder_encode_tag");

            // We decode the first octet length, and then n, depending on what tag length we're decoding
            is(new_der_end, der_end - (i + 2), "ccder_encode_tag expected %p, got %p", der_end - (i + 2), new_der_end);
            free(valid_der);
        }
    }
}

//================================ ccder_encode_len ============================

static int _testEncodeLen(void)
{
    uint8_t tmp[5];
    
    // Test that the result is NULL if der_end is NULL
    uint8_t begin;
    is(ccder_encode_len(10, &begin, NULL), NULL, "ccder_encode_len NULL der_end");

    // 1 byte
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result1[5]={0};
    is(ccder_encode_len(0,(const uint8_t*)&tmp[0],&tmp[1]),&tmp[0],"ccder_encode_len return value for 1byte length");
    ok_memcmp_or_fail(tmp, expected_result1,sizeof(tmp),"ccder_encode_len output for 1byte length");

    // 2 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result2[5]={0x81,0x80};
    is(ccder_encode_len(0x80,(const uint8_t*)&tmp[0],&tmp[2]),&tmp[0],"ccder_encode_len return value for 2byte length");
    ok_memcmp_or_fail(tmp, expected_result2,sizeof(tmp),"ccder_encode_len output for 2byte length");

    // 3 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result3[5]={0x82,0xFF,0xFE};
    is(ccder_encode_len(0xFFFE,(const uint8_t*)&tmp[0],&tmp[3]),&tmp[0],"ccder_encode_len return value for 3byte length");
    ok_memcmp_or_fail(tmp, expected_result3,sizeof(tmp),"ccder_encode_len output for 3byte length");

    // 4 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result4[5]={0x83,0xFF,0xFE,0xFD};
    is(ccder_encode_len(0xFFFEFD,(const uint8_t*)&tmp[0],&tmp[4]),&tmp[0],"ccder_encode_len return value for 4byte length");
    ok_memcmp_or_fail(tmp, expected_result4,sizeof(tmp),"ccder_encode_len output for 4byte length");

    // 5 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result5[5]={0x84,0xFF,0xFE,0xFD,0xFC};
    is(ccder_encode_len(0xFFFEFDFC,(const uint8_t*)&tmp[0],&tmp[5]),&tmp[0],"ccder_encode_len return value for 5byte length");
    ok_memcmp_or_fail(tmp, expected_result5,sizeof(tmp),"ccder_encode_len output for 5byte length");

    if (sizeof(size_t)>4) {
        // 5 bytes
        is(ccder_encode_len((size_t)1<<33,&tmp[0],NULL),NULL, "length bigger than UINT32_MAX not supported"); // Expect error
    } else {
        pass("On 32bit platforms, the length can't exceed UINT32_MAX");
    }
    return 0;
}

static void testEncodeLen(void) {
    (void)_testEncodeLen();
}

//====================== ccder_decode_len ===================================

static void testDecodeLen(void)
{
    size_t len = 0;
    
    // Test that the result is NULL if der is NULL
    uint8_t end;
    is(ccder_decode_len(&len, NULL, &end), NULL, "ccder_decode_len NULL der");
    
    uint8_t one_der[] = {0x81}; // one additional octet, but missing
    uint8_t *der_start = one_der;
    uint8_t *der_end = one_der + sizeof(one_der);
    const uint8_t *new_der = ccder_decode_len(&len, der_start, der_end);
    is(new_der, NULL, "ccder_decode_len");

    uint8_t two_der[] = {0x82, 0x01}; // two additional octets, but missing
    der_start = two_der;
    der_end = two_der + sizeof(two_der);
    new_der = ccder_decode_len(&len, der_start, der_end);
    is(new_der, NULL, "ccder_decode_len");

    uint8_t three_der[] = {0x83, 0x01, 0x02}; // three additional octets, but missing
    der_start = three_der;
    der_end = three_der + sizeof(three_der);
    new_der = ccder_decode_len(&len, der_start, der_end);
    is(new_der, NULL, "ccder_decode_len");

    size_t length;

    length = 0x112233;
    uint8_t *valid_three_der = malloc(length + 4);
    if (valid_three_der) {
        valid_three_der[0] = 0x83;
        valid_three_der[1] = (uint8_t)(length >> 16);
        valid_three_der[2] = (uint8_t)(length >> 8);
        valid_three_der[3] = (uint8_t)(length >> 0);
        der_start = valid_three_der;
        der_end = valid_three_der + length + 4;
        new_der = ccder_decode_len(&len, der_start, der_end);
        isnt(new_der, NULL, "ccder_decode_len");
        is(new_der, valid_three_der + 4, "ccder_decode_len");
        is(len, length, "ccder_decode_len");

        free(valid_three_der);
    }

    length = 0x11223344;
    uint8_t *valid_four_der = malloc(length + 5);
    if (valid_four_der) {
        valid_four_der[0] = 0x84;
        valid_four_der[1] = (uint8_t)(length >> 24);
        valid_four_der[2] = (uint8_t)(length >> 16);
        valid_four_der[3] = (uint8_t)(length >> 8);
        valid_four_der[4] = (uint8_t)(length >> 0);
        der_start = valid_four_der;
        der_end = valid_four_der + length + 5;
        new_der = ccder_decode_len(&len, der_start, der_end);
        isnt(new_der, NULL, "ccder_decode_len");
        is(new_der, valid_four_der + 5, "ccder_decode_len");
        is(len, length, "ccder_decode_len");

        free(valid_four_der);
    }
}

//================================ ccder_encode_body ============================

static void testEncodeBody(void)
{
    uint8_t der[] = {0x00};
    // Test that the result is NULL if der_end is NULL
    uint8_t derb = 0;
    is(ccder_encode_body(1, &derb, &derb, NULL), NULL, "ccder_encode_body NULL der_end");
    
    size_t length = sizeof(der) + 1; // invalid size
    uint8_t body[length];
    uint8_t *new_der = ccder_encode_body(length, body, der, der + sizeof(der));
    is(new_der, NULL, "ccder_encode_body");
}

static void testBlobEncodeBody(void)
{
    ccder_blob blob;
    is(ccder_blob_encode_body(&blob, 0, NULL), true, "ccder_blob_encode_body with size 0 and body = NULL should be true");
    is(ccder_blob_encode_body(&blob, 1, NULL), false, "ccder_blob_encode_body with size !=0 and body = NULL should be false");
}


static void testEncodeBodyNoCopy(void)
{
    // Test that the result is NULL if der_end is NULL
    uint8_t begin;
    is(ccder_encode_body_nocopy(1, &begin, NULL), NULL, "ccder_encode_body_nocopy NULL der_end");
    
    uint8_t der[] = {0x00};
    size_t length = sizeof(der) + 1; // invalid size
    uint8_t *new_der = ccder_encode_body_nocopy(length, der, der + sizeof(der));
    is(new_der, NULL, "ccder_encode_body");
}

//====================== ccder_decode_uint_n ===================================

typedef struct der_decode_uint_n_struct {
    char  *der_str_buf;
    cc_size n;
    int err;
} der_decode_uint_n_t;

der_decode_uint_n_t test_der_decode_uint_n[]={
    {"0200",0,1}, // Must have one byte content
    {"020100",0,0},
    {"020101",1,0},
    {"02020080",1,0},
    {"028109008000000000000001",ccn_nof_size(8),0},
    {"0281110080000000000000000000000000000001",ccn_nof_size(16),0},
    {"02020040",0,1},                   // Too many padding zeroes
    {"0203000080",1,1},                 // Too many padding zeroes
    {"02810A00000000000000000001",1,1}, // Too many padding zeroes
    {"0281088000000000000001",0,1},     // Negative
    };

static void testDecodeUInt_n(void)
{
    // Test that the result is NULL if der is NULL
    cc_size n=0;
    uint8_t end;
    is(ccder_decode_uint_n(&n, NULL, &end), NULL, "ccder_decode_uint_n NULL der");
    
    for (size_t i = 0; i < CC_ARRAY_LEN(test_der_decode_uint_n); i++) {
        n=0;
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint_n[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        if (!test_der_decode_uint_n[i].err) {
            is(ccder_decode_uint_n(&n,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint_n return value");
            is(n,test_der_decode_uint_n[i].n, "ccder_decode_uint_n expected output");
        } else {
            is(ccder_decode_uint_n(&n,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint_n return value");
        }
        free(der_buf);
    }
}

//====================== ccder_decode_uint64 ===================================

typedef struct der_decode_uint64_struct {
    char  *der_str_buf;
    uint64_t v;
    int err;
} der_decode_uint64_t;

der_decode_uint64_t test_der_decode_uint64[]={
    {"0200",0,1}, // Must have one byte content
    {"020100",0,0},
    {"020101",1,0},
    {"02020080",0x80,0},
    {"02084070605040302010",0x4070605040302010,0},
    {"0209008070605040302010",0x8070605040302010,0},
    {"0209018070605040302010",0x8070605040302010,1}, // Too big to be uint64_t
    {"02020040",1,1},                      // Too many padding zeroes
    {"0203000080",1,1},                    // Too many padding zeroes
    {"0281088000000000000001",0,1},        // Negative
    {"02810A00000000000000000001",1,1},    // Too many padding zeroes
    {"0281110001000000000000000000000000000001",0,1}, // Too big to be uint64_t
};

static void testDecodeUInt64(void)
{
    // Test that the result is NULL if der is NULL
    uint64_t n=0;
    uint8_t end;
    is(ccder_decode_uint64(&n, NULL, &end), NULL, "ccder_decode_uint64 NULL der");
    
    for (size_t i = 0; i < CC_ARRAY_LEN(test_der_decode_uint64); i++) {
        uint64_t computed_v=0;
        uint64_t expected_v=0;
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint64[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        if (!test_der_decode_uint64[i].err) {
            expected_v=test_der_decode_uint64[i].v;
            is(ccder_decode_uint64(&computed_v,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint64 return value");
            is(computed_v,expected_v, "ccder_decode_uint64 expected output");
        }
        else {
            is(ccder_decode_uint64(&computed_v,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint64 return value");
        }
        free(der_buf);
    }
}

static void testDecodeEmptyBitstring(void)
{
    uint8_t malformed_der_buffer[] = { CCDER_BIT_STRING, 0x00 };
    size_t malformed_der_buffer_len = sizeof(malformed_der_buffer);

    uint8_t *der_ptr = malformed_der_buffer;
    size_t der_ptr_len = malformed_der_buffer_len;
    const uint8_t *string = NULL;
    size_t string_len = 0;
    const uint8_t *new_der_ptr = ccder_decode_bitstring(&string, &string_len,
                                                        (const uint8_t *)der_ptr, (const uint8_t *)(der_ptr + der_ptr_len));
    isnt(new_der_ptr, NULL, "ccder_decode_bitstring");
    is(string_len, (size_t)0, "ccder_decode_bitstring returned non-empty bit string for empty bitstring container");
}

static void testDecodeNullBitstring(void)
{
    uint8_t *der_ptr = NULL;
    uint8_t der_end[] = { '\0' };
    const uint8_t *string = NULL;
    size_t string_len = 0;
    const uint8_t *new_der_ptr = ccder_decode_bitstring(&string, &string_len,
                                                        (const uint8_t *)der_ptr, der_end);
    is(new_der_ptr, NULL, "ccder_decode_bitstring");
}

static void testDecodeBitstringNullDER(void) {
    // Test that the result is NULL if der is NULL
    uint8_t end;
    const uint8_t *string = NULL;
    size_t string_len = 0;
    is(ccder_decode_bitstring(&string, &string_len, NULL, &end), NULL, "ccder_decode_bitstring NULL der");
}

static void testDecodeOID(void) {
    ccoid_t oid;
    uint8_t *der_ptr;
    size_t der_ptr_len;
    const uint8_t *new_der_ptr;

    // Test that the result is NULL if der is NULL
    uint8_t end;
    is(ccder_decode_oid(&oid, NULL, &end), NULL, "ccder_decode_oid NULL der");
    is(oid, NULL, "ccder_decode_oid NULL der");

    // Test that the result is NULL if der is just the OID identifier
    uint8_t short_der_buffer[] = { CCDER_OBJECT_IDENTIFIER };
    der_ptr = short_der_buffer;
    der_ptr_len = sizeof(short_der_buffer);
    new_der_ptr = ccder_decode_oid(&oid, (const uint8_t *)der_ptr,
                                         (const uint8_t *)(der_ptr + der_ptr_len));
    is(new_der_ptr, NULL, "ccder_decode_oid OID-only der");
    is(oid, NULL, "ccder_decode_oid OID-only der");

    // Test that the result and oid are valid for der of length 0
    uint8_t der_length_zero[] = { CCDER_OBJECT_IDENTIFIER, 0x00 };
    der_ptr = der_length_zero;
    der_ptr_len = sizeof(der_length_zero);
    new_der_ptr = ccder_decode_oid(&oid, (const uint8_t *)der_ptr,
                                         (const uint8_t *)(der_ptr + der_ptr_len));
    is(new_der_ptr, (const uint8_t *)(der_ptr + der_ptr_len), "ccder_decode_oid length-0 OID");
    is(oid, der_ptr, "ccder_decode_oid length-0 OID");
    
    // Invalidate the tag length -- 0x84 is an invalid tag length
    der_length_zero[1] = 0x84;
    new_der_ptr = ccder_decode_oid(&oid, (const uint8_t *)der_ptr,
                                         (const uint8_t *)(der_ptr + der_ptr_len));
    is(new_der_ptr, NULL, "ccder_decode_oid invalid-length OID");
    is(oid, NULL, "ccder_decode_oid invalid-length OID");

    // Test that the result and oid are valid for der of length 1
    uint8_t der_length_one[] = { CCDER_OBJECT_IDENTIFIER, 0x01, 0x02 };
    der_ptr = der_length_one;
    der_ptr_len = sizeof(der_length_one);
    new_der_ptr = ccder_decode_oid(&oid, (const uint8_t *)der_ptr,
                                         (const uint8_t *)(der_ptr + der_ptr_len));
    is(new_der_ptr, (const uint8_t *)(der_ptr + der_ptr_len), "ccder_decode_oid length-1 OID");
    is(oid, der_ptr, "ccder_decode_oid length-1 OID");
    
    // Valid OID
    ccoid_t valid_oid = CC_EC_OID_SECP192R1;
    der_ptr_len = ccoid_size(valid_oid);
    
    uint8_t der_buf[16];
    uint8_t *loc = ccder_encode_oid(valid_oid, der_buf, der_buf + sizeof(der_buf));
    isnt(loc, NULL, "ccder_encode_oid");
    
    new_der_ptr = ccder_decode_oid(&oid, loc, der_buf + sizeof(der_buf));
    is(new_der_ptr, (const uint8_t *)(loc + der_ptr_len), "ccder_decode_oid valid OID");
    is(ccoid_equal(oid, valid_oid), true, "ccder_decode_oid valid OID");
}

//====================== ccder_decode_uint ===================================

typedef struct der_decode_uint_struct {
    char  *der_str_buf;
    cc_unit v[CCN192_N];
    int err;
} der_decode_uint_t;

der_decode_uint_t test_der_decode_uint[]={
    {"0200",                        {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Must have one byte content
    {"020100",                      {CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00)},0},
    {"02020080",                    {CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,80)},0},
    {"02020040",                    {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"0203000001",                  {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"02810A00000000000000000001",  {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"0281088000000000000001",      {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Negative
    {"02811901000000000000000000000000000000000000000000000000",
                                    {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too big
};

static void testDecodeUInt(void)
{
    cc_unit computed_v[CCN192_N];
    // Test that the result is NULL if der is NULL
    uint8_t end;
    is(ccder_decode_uint(CCN192_N, computed_v, NULL, &end), NULL, "ccder_decode_uint NULL der");
    
    for (size_t i = 0; i < CC_ARRAY_LEN(test_der_decode_uint); i++) {
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        memset(computed_v,0xAA,sizeof(computed_v)); // Fill with a different value to start with.
        
        if (!test_der_decode_uint[i].err) {
            cc_unit *expected_v=test_der_decode_uint[i].v;
            is(ccder_decode_uint(CCN192_N,computed_v,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint return value");
            ok_memcmp(computed_v,expected_v,sizeof(test_der_decode_uint[i].v), "ccder_decode_uint expected output");
        }
        else {
            is(ccder_decode_uint(CCN192_N, computed_v,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint64 return value");
        }
        free(der_buf);
    }
}

const uint8_t derbuf1[] = { 0x30, 0x01, 0xAA };
const uint8_t derbuf2[] = { 0x30, 0x01, 0xAA, 0xBB }; // Too much data, but still valid
const uint8_t derbuf3[] = { 0x30, 0x03, 0xAA }; // No enough data for len
const uint8_t derbuf4[] = { 0x30, 0x84, 0xAA }; // Invalid length

typedef struct der_decode_tl_struct {
    const uint8_t  *der;
    size_t der_len;
    size_t next_der_offset; // 0 is test is invalid
    size_t end_der_offset;  // 0 is test is invalid
    const char *description;
} der_decode_tl_t;

der_decode_tl_t test_der_decode_tl[] = {
    {&derbuf1[0],0,0,0,"Wrong der_end"},
    {&derbuf1[0],1,0,0,"Wrong der_end"},
    {&derbuf1[0],2,0,0,"Wrong der_end"},
    {&derbuf1[0],sizeof(derbuf1),2,3,"valid test, exactly enough data"},
    {&derbuf2[0],sizeof(derbuf2),2,3,"valid test, too much data"},
    {&derbuf3[0],sizeof(derbuf3),0,0,"No enough data for length"},
    {&derbuf4[0],sizeof(derbuf4),0,0,"Invalid length"},

};

static void testDecode_tl(void)
{
    const uint8_t *der_body_end = NULL;
    // Test that the result is NULL if der is NULL
    uint8_t end;
    is(ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_body_end, NULL, &end), NULL, "ccder_decode_constructed_tl NULL der");
    
    for (size_t i = 0; i < CC_ARRAY_LEN(test_der_decode_tl); i++) {
        const der_decode_tl_t test = test_der_decode_tl[i];
        const uint8_t *der_end = test.der+test.der_len;
        der_body_end = NULL;
        const uint8_t *expected_return = NULL; // for errors
        const uint8_t *expected_body_end = test.der; // for errors
        if (test.next_der_offset) {
            expected_return = test.der + test.next_der_offset;
            expected_body_end = test.der + test.end_der_offset;
        }

        is(ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_body_end,
                                       test.der,der_end), expected_return,
                                       "%zu: %s", i, test.description);
        is(der_body_end, expected_body_end, "%zu: %s", i, test.description);
    }
}

static void testDecodeTag(void)
{
    ccder_tag tag;
    // Test that the result is NULL if der is NULL
    uint8_t end;
    is(ccder_decode_tag(&tag, NULL, &end), NULL, "ccder_decode_tag NULL end");
    
    // The second byte of this multi-byte tag does not have the top-three bits reserved.
    uint8_t malformed_der_buffer[sizeof(ccder_tag)];
    for (size_t i = 0; i < sizeof(ccder_tag); i++) {
        malformed_der_buffer[i] = 0xFF;
    }
    size_t malformed_der_buffer_len = sizeof(malformed_der_buffer);

    uint8_t *der_ptr = malformed_der_buffer;
    size_t der_ptr_len = malformed_der_buffer_len;
    const uint8_t *body = ccder_decode_tag(&tag, der_ptr, der_ptr + der_ptr_len);

    is(body, NULL, "ccder_decode_tag");

    for (size_t i = 0; i < sizeof(ccder_tag); i++) {
        malformed_der_buffer[i] = 0x00;
    }
    malformed_der_buffer[0] = 0xFF;
    body = ccder_decode_tag(&tag, der_ptr, der_ptr + der_ptr_len);

    isnt(body, NULL, "ccder_decode_tag");
}

static void testSizeofTag(void)
{
    unsigned long limits[] = {0x1e, 0x7f, 0x3fff, 0x1fffff, 0xfffffff, 0x10000000};
    for (size_t i = 0; i < CC_ARRAY_LEN(limits); i++) {
        ccder_tag tag = limits[i] & CCDER_TAGNUM_MASK;
        size_t size = ccder_sizeof_tag(tag);
        is(size, i + 1, "ccder_sizeof_tag expected %zu, got %zu", i + 1, size);
    }
}

ccder_sig_test_vector sig_test_vectors[] = {
#include "ccder_signature_strict_vectors.inc"
    {.signature = NULL}
};

static void test_ccder_decode_seqii_strict(void) {
    // Test that the result is NULL if der is NULL
    uint8_t end;
    cc_unit r_null[CCN192_N], s_null[CCN192_N];
    is(ccder_decode_seqii_strict(CCN192_N, r_null, s_null, NULL, &end), NULL, "ccder_decode_seqii_strict NULL end");
    
    for (int i = 0; sig_test_vectors[i].signature != NULL; i++) {
        const ccder_sig_test_vector tv = sig_test_vectors[i];
        
        cc_size n = ccn_nof(tv.nbits);
        byteBuffer sig = hexStringToBytes(tv.signature);
        const uint8_t *sig_end = sig->bytes + sig->len;
        cc_unit r[n], s[n];
        
        const uint8_t *result = ccder_decode_seqii_strict(n, r, s, sig->bytes, sig_end);
        is(result != NULL, tv.valid, "Strict signature decoding error on test vector %d, %s", i, tv.signature);
        
        if (tv.valid && result) {
            cc_unit rp[n], sp[n];
            byteBuffer tv_r = hexStringToBytes(tv.r);
            byteBuffer tv_s = hexStringToBytes(tv.s);
            
            ccn_read_uint(n, rp, tv_r->len, tv_r->bytes);
            ccn_read_uint(n, sp, tv_s->len, tv_s->bytes);
            free(tv_r);
            free(tv_s);
            
            ok_ccn_cmp(n, r, rp, "Incorrect r value on test vector %d", i);
            ok_ccn_cmp(n, s, sp, "Incorrect s value on test vector %d", i);
        } else {
            is(1, 1, "Dummy test1");
            is(1, 1, "Dummy test2");
        }
        
        free(sig);
    }
    return;
}

//=========================== ccder_encode_ecky ================================

typedef struct der_encode_eckey_struct {
    size_t priv_byte_size;
    uint8_t *priv_key;
    ccoid_t oid;
    size_t pub_byte_size;
    uint8_t *pub_key;
    
    const char *description;
} der_encode_eckey_t;

static uint8_t body = 0;

#define WITH_PRIV_KEY       5, (uint8_t[]) {1, 2, 3, 4, 5}
#define WITHOUT_PRIV_KEY    0, &body
#define WITH_OID            (ccoid_t)CC_EC_OID_SECP192R1
#define WITHOUT_OID         (ccoid_t){NULL}
#define WITH_PUB_KEY        5, (uint8_t[]) {6, 7, 8, 9, 10}
#define WITHOUT_PUB_KEY     0, &body

der_encode_eckey_t test_der_encode_eckey[] = {
    { WITHOUT_PRIV_KEY,     WITHOUT_OID,    WITHOUT_PUB_KEY,    "invalid (-oid, -public key)" },
    { WITHOUT_PRIV_KEY,     WITHOUT_OID,    WITH_PUB_KEY,       "invalid (-oid, +public key)" },
    { WITHOUT_PRIV_KEY,     WITH_OID,       WITHOUT_PUB_KEY,    "invalid (+oid, -public key)" },
    { WITHOUT_PRIV_KEY,     WITH_OID,       WITH_PUB_KEY,       "invalid (+oid, +public key)" },
    { WITH_PRIV_KEY,        WITHOUT_OID,    WITHOUT_PUB_KEY,    "valid (-oid, -public key)" },
    { WITH_PRIV_KEY,        WITHOUT_OID,    WITH_PUB_KEY,       "valid (-oid, +public key)" },
    { WITH_PRIV_KEY,        WITH_OID,       WITHOUT_PUB_KEY,    "valid (+oid, -public key)" },
    { WITH_PRIV_KEY,        WITH_OID,       WITH_PUB_KEY,       "valid (+oid, +public key)" },
};

static void testEncodeEckeyRoundtrip(void) {
    uint8_t der_buf[80];
    uint8_t *der_end = &der_buf[80];
    for (der_encode_eckey_t *test = test_der_encode_eckey; test < (&test_der_encode_eckey)[1]; ++test) {
        memset(der_buf, 0, sizeof(der_buf));
        uint8_t *next = ccder_encode_eckey(test->priv_byte_size, test->priv_key, test->oid, test->pub_byte_size, test->pub_key, der_buf, der_end);
        if (test->priv_byte_size == 0) {
            is(next, NULL, "%zi: %s", test - test_der_encode_eckey, test->description);
        } else {
            uint64_t version;
            size_t priv_byte_size;
            const uint8_t *priv_key;
            ccoid_t oid;
            size_t pub_bit_count;
            const uint8_t *pub_key;
            
            const uint8_t *end = ccder_decode_eckey(&version, &priv_byte_size, &priv_key, &oid, &pub_bit_count, &pub_key, next, der_end);
            is(end, der_end, "%zi.end: %s", test - test_der_encode_eckey, test->description);
            is(priv_byte_size, test->priv_byte_size, "%zi.priv_byte_size: %s", test - test_der_encode_eckey, test->description);
            ok_memcmp(priv_key, test->priv_key, test->priv_byte_size, "%zi.priv_key: %s", test - test_der_encode_eckey, test->description);
            if (test->oid) {
                is(ccoid_equal(oid, test->oid), true, "%zi.oid: %s", test - test_der_encode_eckey, test->description);
            }
            is(pub_bit_count, test->pub_byte_size * 8, "%zi.pub_bit_count: %s", test - test_der_encode_eckey, test->description);
            if (test->pub_byte_size) {
                ok_memcmp(pub_key, test->pub_key, test->pub_byte_size, "%zi.pub_key: %s", test - test_der_encode_eckey, test->description);
            }
        }
    }
}

//=============================== MAIN ccder ===================================

struct ccder_test_entry {
    void (*test_func)(void);
    int test_count;
};

#define ONE_PAST_THE_END(ARR) *(&(ARR) + 1)

int ccder_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    struct ccder_test_entry tests[] = {
        {&testSizeOf, 38},
        {&testSizeOfUInt64, 18},
        {&testEncodeTag,
            (1 /* NULL der_end */) +
            (5 * 3 /* limits * 3 tests */)},
        {&testEncodeLen, 12},
        {&testDecodeLen, 10},
        {&testEncodeBody, 2},
        {&testBlobEncodeBody, 2},
        {&testEncodeBodyNoCopy, 2},
        {&testDecodeUInt_n,
            (1 /* NULL der */) +
            (5 * 2 /* test vectors without the error bit */) +
            (5 * 1 /* test vectors with the error bit */)},
        {&testDecodeUInt64,
            (1 /* NULL der */) +
            (5 * 2 /* test vectors without the error bit */) +
            (7 * 1 /* test vectors with the error bit */)},
        {&testDecodeEmptyBitstring, 2},
        {&testDecodeNullBitstring, 1},
        {&testDecodeBitstringNullDER, 1},
        {&testDecodeOID, 13},
        {&testDecodeUInt,
            (1 /* NULL der */) +
            (2 * 2 /* test vectors without the error bit */) +
            (6 * 1 /* test vectors with the error bit */)},
        {&testDecode_tl,
            (1 /* NULL der */) +
            (7 * 2 /* test vectors */)},
        {&testDecodeTag, 3},
        {&testSizeofTag, 6},
        {&test_ccder_decode_seqii_strict,
            (1 /* NULL der */) +
            ((ONE_PAST_THE_END(sig_test_vectors) - sig_test_vectors - 1) * 3 /* test vectors */)},
        {&testEncodeEckeyRoundtrip,
            (1 * 4 /* vectors without a private key */) +
            (4 * 4 /* vectors with a private key */) +
            (2 * 1 /* vectors with a private key and an OID */) +
            (2 * 1 /* vectors with a private key and a public key */)},
    };
    
    int ntests = 0;
    for (size_t i = 0; i < CC_ARRAY_LEN(tests); i++) {
        ntests += tests[i].test_count;
    }
    plan_tests(ntests);

    for (size_t i = 0; i < CC_ARRAY_LEN(tests); i++) {
        tests[i].test_func();
    }

    return 0;
}

#endif // entryPoint(ccder,"ccder")
