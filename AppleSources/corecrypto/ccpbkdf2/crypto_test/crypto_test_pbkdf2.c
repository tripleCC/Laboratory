/* Copyright (c) (2012-2016,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"

static int verbose = 0;

#if (CCPBKDF2 == 0)
entryPoint(ccpbkdf2_tests,"ccpbkdf2 test")
#else
#include <corecrypto/ccasn1.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdigest_priv.h>
#include "ccdigest_internal.h"
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccripemd.h>

static const int kTestTestCount = 180;


/* Currently, ccpbkdf2 and friends won't work when length == 0 and the
 * data pointer is NULL.
 */

#define password1     "password"
#define saltstr128    "000102030405060708090a0b0c0d0e0f"


#define pbkdf2_DATA_POINTER_NULL_TOLERANT 0

typedef struct test_vector_t {
    char *password;
    char *saltStr;
    size_t iterations;
    size_t result_len;
    char *md2_answer;
    char *md4_answer;
    char *md5_answer;
    char *sha1_answer;
    char *sha224_answer;
    char *sha256_answer;
    char *sha384_answer;
    char *sha512_answer;
    char *rmd160_answer;
} test_vector;

static char *
digest_name(const struct ccdigest_info *di) {
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD2)) return "MD2";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD4)) return "MD4";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD5)) return "MD5";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA1)) return "SHA1";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA224)) return "SHA224";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA256)) return "SHA256";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA384)) return "SHA384";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA512)) return "SHA512";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_RMD160)) return "RMD160";
    return NULL;
}

static int test_answer(const struct ccdigest_info *di, test_vector *vector, size_t answer_len, void*answer) {
    char *correct_answer = NULL;
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD2)) correct_answer = vector->md2_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD4)) correct_answer = vector->md4_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD5)) correct_answer = vector->md5_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA1)) correct_answer = vector->sha1_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA224)) correct_answer = vector->sha224_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA256)) correct_answer = vector->sha256_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA384)) correct_answer = vector->sha384_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA512)) correct_answer = vector->sha512_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_RMD160)) correct_answer = vector->rmd160_answer;
    byteBuffer answer_bb = bytesToBytes(answer, answer_len);
    if(correct_answer == NULL) {
        diag("Digest %s:", digest_name(di));
        cc_print("Output value",answer_bb->len,answer_bb->bytes);
        return 1;
    }
    byteBuffer correct_answer_bb = hexStringToBytes((char *) correct_answer);
    ok(bytesAreEqual(correct_answer_bb, answer_bb), "compare memory of answer");
    if(bytesAreEqual(correct_answer_bb, answer_bb) == 0) {
        printByteBuffer(correct_answer_bb, "Correct Answer");
        printByteBuffer(answer_bb, "Provided Answer");
    }
    free(correct_answer_bb);
    free(answer_bb);
    return 1;
}

static int test_oneshot(const struct ccdigest_info *di, test_vector *vector) {
    uint8_t answer[vector->result_len];
    byteBuffer salt = hexStringToBytes(vector->saltStr);
    ccpbkdf2_hmac(di, strlen(vector->password), vector->password, salt->len, salt->bytes, vector->iterations, vector->result_len, answer);
    ok(test_answer(di, vector, vector->result_len, answer), "check answer");
    free(salt);
    return 1;
}

static int test_size(const struct ccdigest_info *di) {
    size_t size_chk = 40;
    uint8_t output_buf[size_chk];
    static char *password = "test";
    static const uint8_t salt[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    if(sizeof(size_t) > 4) { // only valid for 64 bit.
        size_t hlen = di->output_size;
        size_t too_big = hlen * ((size_t) UINT32_MAX + 1);
        ok(ccpbkdf2_hmac(di, strlen(password), password, sizeof(salt), salt, 10, too_big, output_buf) != 0, "Fails with size too big");
        ok(ccpbkdf2_hmac(di, strlen(password), password, sizeof(salt), salt, 10, size_chk, output_buf) == 0, "Passes");
    }
    return 1;
    
}

static int test_pbkdf2(const struct ccdigest_info *di) {
    static test_vector vector[] = {
        { password1, saltstr128, 100, 16,
            "4fb479b7843efec99b2a9d137682bba2", // MD2
            "a941b5a1246eb37e7d8bbfb803257d29", // MD4
            "c21f6f8b192757dc79bfd67378255152", // MD5
            "f61e774036c4007d4402fe9912e29a85", // SHA1
            "78e396298731187a7e9a355694296b1f", // SHA224
            "854a1e9b6834413dc51b4316dbe405e1", // SHA256
            "813022dc740ec35fb4c4eaf67cd42539", // SHA384
            "9842d62607fa2b5d5165d6526f74e119", // SHA512
            "b68e9c0c55f521c3f2fcc84320a089de", // RMD160
        },
        { password1, saltstr128, 1000, 24,
            "ec806929819bb71b46b6552ac71d0e141af5360bfca0c03c", // MD2
            "b8d26c6338b43b11fe2c8c7a45d31b015f72ae7cfde36778", // MD4
            "cb2c261847e9e1c3141478bd084565da00024366ec9d167e", // MD5
            "0309e2fe4e0bdfe7d0fe4828d41c234416e2d9bfb61cdd8f", // SHA1
            "7d8603adef1af3704db8c7d2c471661ca73ac07c9044a5dc", // SHA224
            "25eb86acc76e43018f18b9a8f90c2fed462d1c799e83d48a", // SHA256
            "82d915ec6e30a50a987fe17cc6d260194c33fec4f2f14196", // SHA384
            "c74e4080d0fbb41fee5868c0ff60fd75acae2638215987e5", // SHA512
            "e4d14f220779d824d281b50a5c688a4071219411ce4ece1c", // RMD160
        },
        { password1, saltstr128, 10000, 8,
            "3e6698827388fc04", // MD2
            "a7e2590655919ffc", // MD4
            "d352d8ec8e276adc", // MD5
            "8e3e2f73c3eb6390", // SHA1
            "a7150cd1d2a90e2d", // SHA224
            "eb6c81535592203c", // SHA256
            "24f67028f09c4d89", // SHA384
            "5e5984ca905a5524", // SHA512
            "b35814741b948ecb", // RMD160
        },

    };
    int vector_size = (int)CC_ARRAY_LEN(vector);
    if(verbose) diag("pbkdf2 LT Test\n");

    for(int i=0; i<vector_size; i++) {
        ok(test_oneshot(di, &vector[i]), "test one-shot with data less than blocksize");
    }
    test_size(di);
    return 1;
}

int ccpbkdf2_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
	plan_tests(kTestTestCount);

    if(verbose) diag("Starting pbkdf2 tests\n");

    // Pure C versions
    ok(test_pbkdf2(&ccmd2_ltc_di), "ccmd2_di");
    ok(test_pbkdf2(&ccmd4_ltc_di), "ccmd4_ltc_di");
    ok(test_pbkdf2(&ccmd5_ltc_di), "ccmd5_ltc_di");
    ok(test_pbkdf2(&ccsha1_ltc_di), "ccsha1_ltc_di");
    ok(test_pbkdf2(&ccsha1_eay_di), "ccsha1_eay_di");
    ok(test_pbkdf2(&ccsha224_ltc_di), "ccsha224_ltc_di");
    ok(test_pbkdf2(&ccsha256_ltc_di), "ccsha256_ltc_di");
    ok(test_pbkdf2(&ccsha384_ltc_di), "ccsha384_ltc_di");
    ok(test_pbkdf2(&ccsha512_ltc_di), "ccsha512_ltc_di");
    ok(test_pbkdf2(&ccrmd160_ltc_di), "ccrmd160_ltc_di");

    // Default (optimized)
    ok(test_pbkdf2(ccsha1_di()),   "Default ccsha1_di");
    ok(test_pbkdf2(ccsha224_di()), "Default ccsha224_di");
    ok(test_pbkdf2(ccsha256_di()), "Default ccsha256_di");
    ok(test_pbkdf2(ccsha384_di()), "Default ccsha384_di");
    ok(test_pbkdf2(ccsha512_di()), "Default ccsha512_di");

    return 0;
}
#endif

