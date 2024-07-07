/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
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

#if (CCNISTKDF == 0)
entryPoint(ccnistkdf_cmac_tests,"ccnistkdf_cmac test")
#else
#include <corecrypto/ccnistkdf.h>
#include "ccnistkdf_internal.h"

typedef struct cmac_nist_test_vector_t {
    int testnum;
    char *key;
    char *fixedData;
    uint8_t r;
    size_t result_len;
    char *answer;
} nist_fixed_test_vector;

typedef struct cmac_generic_test_vector_t {
    int testnum;
    char *key;
    char *label;
    char *context;
    uint8_t r;
    uint8_t dkLen_size;
    size_t result_len;
    char *answer;
} generic_test_vector;

static void test_answer(char *correct_answer, size_t answer_len, void*answer) {
    byteBuffer correct_answer_bb = hexStringToBytes((char *) correct_answer);
    ok_memcmp(correct_answer_bb->bytes, answer, answer_len, "Check NISTKDF-CMAC vector failed.");
    free(correct_answer_bb);
}

static void test_ctr_cmac_oneshot(generic_test_vector *vector) {
    uint8_t answer[vector->result_len];
    byteBuffer key       = hexStringToBytes(vector->key);
    byteBuffer label     = hexStringToBytes(vector->label);
    byteBuffer context   = hexStringToBytes(vector->context);

    is(ccnistkdf_ctr_cmac(ccaes_cbc_encrypt_mode(), vector->r, key->len, key->bytes, label->len, label->bytes, context->len, context->bytes, vector->result_len, vector->dkLen_size, answer),
       CCERR_OK,
       "ccnistkdf_ctr_cmac failed");
    
    test_answer(vector->answer, vector->result_len, answer);
    
    free(label);
    free(context);
    free(key);
}

static void test_ctr_cmac_fixed_oneshot(nist_fixed_test_vector *vector) {
    uint8_t answer[vector->result_len];
    byteBuffer key       = hexStringToBytes(vector->key);
    byteBuffer fixedData = hexStringToBytes(vector->fixedData);
    
    is(ccnistkdf_ctr_cmac_fixed(ccaes_cbc_encrypt_mode(), vector->r, key->len, key->bytes, fixedData->len, fixedData->bytes, vector->result_len, answer),
       CCERR_OK,
       "ccnistkdf_ctr_cmac failed");
    
    test_answer(vector->answer, vector->result_len, answer);
    
    free(fixedData);
    free(key);
}

static generic_test_vector vector_test_fixed_special_values[] = {
    {
        9,
        "d98b5317ed153597f3629629045ab22dccd95f70d472d3a4a885672ded84be96",
        "414b455f53657373696f6e536565640a",
        "00000000",
        16,
        2,
        72,
        "84afed2e7137a56ae77f2d333012867cd0a14a3ce0ddf831b202b84e88625002dafd7b221e6b9"\
        "218fcfc3e8d188a7698d5f5c13480c83c251b77f4c22b77d6f5e006e4ee7d89e53e"
    },
    {
        10,
        "5a21cabdfaa0c712162d49268acbe775d527975ce31134c8345929c3e4117833",
        "414b455f53657373696f6e536565640a",
        "01010000",
        16,
        2,
        72,
        "66ecd4e6ccf0fac626568823b96c21aef279cd7863f7268adf2647b37ca985cb5ae7d48d8bef2ee4"\
        "bb152afc688958575c3c4cbc61484a8bc3d13cd20140143f89ce769528625f3b"
    },
    {
        11,
        "e93ef369525b67cd609681c845329cce588781307bc0c70ea7a92fa6fc4765d7",
        "414b455f53657373696f6e536565640a",
        "01020000",
        16,
        2,
        72,
        "38884a4e4d3f74b097a8ff6c9f03e6ed4817c3bfa1585ff5f486e31aebc6725249d1b23fed187e70"\
        "31bfdc63c74e3e17e1606457a4207ad3055665bc49f07ee0b108ca1cf7b2d97e"
    },
    {
        12,
        "5d36017ebdeadb39246c630920c2f0a3eb7f065576c2a95c0ccc41ebbd0c5470",
        "414b455f53657373696f6e536565640a",
        "01030000",
        16,
        2,
        72,
        "1db0807b9e2f5488fd35ca9a113981e40509993443880dd34fa9a9b7aab4bab617e88ab5f2825518"\
        "95d09e5edfb1fa74f4453276c4510299fd947e8784d264b40bb385bfae7b6c0f"
    },
    {
        13,
        "223c8f70d819c5c60889ba212139b8e1b9adca66b4c315c2a2b0da0705a2e1c7",
        "414b455f53657373696f6e536565640a",
        "01040000",
        16,
        2,
        72,
        "adc67e29d7b6c5f46ef901df47f0775dd5d3ccbe7a618c7d8f81410b25e7157e15cd2f7d34141586"\
        "3c137d3c467a2539457723d28c6c5ee5080ae7968f601022f85accd4a6dd9be0"
    }
};

static void test_fixed_special_values(void) {
    for(size_t i=0; i < CC_ARRAY_LEN(vector_test_fixed_special_values); i++) {
        test_ctr_cmac_oneshot(&vector_test_fixed_special_values[i]);
    }
}

static nist_fixed_test_vector vector_test_nistkdf_cmac[] = {
    { // from published NIST KAT for CMAC_AES128, R=32
        1,
        "c10b152e8c97b77e18704e0f0bd38305",
        "98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad"\
        "0e78e9cf94ffdba89d03e97eadf6c4f7b806caf52aa38f"\
        "09d0eb71d71f497bcc6906b48d36c4",
        32,
        16,
        "26faf61908ad9ee881b8305c221db53f"
    },
    { // from published NIST KAT for CMAC_AES128, R=24
        2,
        "ca1cf43e5ccd512cc719a2f9de41734c",
        "e3884ac963196f02ddd09fc04c20c88b60faa775b5ef6"\
        "feb1faf8c5e098b5210e2b4e45d62cc0bf907fd68022ee"\
        "7b15631b5c8daf903d99642c5b831",
        24,
        16,
        "1cb2b12326cc5ec1eba248167f0efd58"
    },
    { // from published NIST KAT for CMAC_AES128, R=16
        3,
        "30ec5f6fa1def33cff008178c4454211",
        "c95e7b1d4f2570259abfc05bb00730f0284c3bb9a61d07"\
        "259848a1cb57c81d8a6c3382c500bf801dfc8f70726b082"\
        "cf4c3fa34386c1e7bf0e5471438",
        16,
        16,
        "00018fff9574994f5c4457f461c7a67e"
    },
    { // from published NIST KAT for CMAC_AES128, R=8
        4,
        "dff1e50ac0b69dc40f1051d46c2b069c",
        "c16e6e02c5a3dcc8d78b9ac1306877761310455b4e414699"\
        "51d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c46"\
        "48b707d2607935699316ea5",
        8,
        16,
        "8be8f0869b3c0ba97b71863d1b9f7813"
    },
    { // from published NIST KAT for CMAC_AES256, R=32
        5,
        "d0b1b3b70b2393c48ca05159e7e28cbeadea93f28a7cdae964e5136070c45d5c",
        "dd2f151a3f173492a6fbbb602189d51ddf8ef79fc8e96b8fcbe6dabe73a35b4810"\
        "4f9dff2d63d48786d2b3af177091d646a9efae005bdfacb61a1214",
        32,
        16,
        "8c449fb474d1c1d4d2a33827103b656a"
    },
    { // from published NIST KAT for CMAC_AES256, R=24
        6,
        "4d71923280fb4a11b25f9d58d67704d8f8bb2d64d89edb9ee6f3de32e4601efc",
        "e27b8f350bc1360ddc476cb0cae886f0161da22ee8159c330f545af1d782a0f0"\
        "aacc3c3de6215807161df09336d470b5b4db1cc0ce73ed1d3ea24380",
        24,
        32,
        "b5b2bb675fe7b04a52340bd5cf248d5258a1f837dad747ee8a4e904608a8977d"
    },
    { // from published NIST KAT for CMAC_AES256, R=16
        7,
        "4df60800bf8e2f6055c5ad6be43ee3deb54e2a445bc88a576e111b9f7f66756f",
        "962adcaf12764c87dad298dbd9ae234b1ff37fed24baee0649562d466a80c0dcf"\
        "0a65f04fe5b477fd00db6767199fa4d1b26c68158c8e656e740ab4d",
        16,
        16,
        "eca99d4894cdda31fe355b82059a845c"
    },
    { // from published NIST KAT for CMAC_AES256, R=8
        8,
        "aeb7201d055f754212b3e497bd0b25789a49e51da9f363df414a0f80e6f4e42c",
        "11ec30761780d4c44acb1f26ca1eb770f87c0e74505e15b7e456b019ce0c38103"\
        "c4d14afa1de71d340db51410596627512cf199fffa20ef8c5f4841e",
        8,
        16,
        "2a9e2fe078bd4f5d3076d14d46f39fb2"
    }
};

static void test_nistkdf_cmac(void) {
    for(size_t i=0; i < CC_ARRAY_LEN(vector_test_nistkdf_cmac); i++) {
        test_ctr_cmac_fixed_oneshot(&vector_test_nistkdf_cmac[i]);
    }
}

int ccnistkdf_cmac_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int ntests = 0;
    ntests += (int)CC_ARRAY_LEN(vector_test_fixed_special_values) * 2;
    ntests += (int)CC_ARRAY_LEN(vector_test_nistkdf_cmac) * 2;
    plan_tests(ntests);
    
    test_fixed_special_values();
    test_nistkdf_cmac();

    return 0;
}

#endif

