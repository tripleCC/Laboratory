/* Copyright (c) (2012,2013,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
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
#include "cc_priv.h"

static int verbose = 0;

#if (CCCMAC == 0)
entryPoint(cccmac_tests,"cccmac test")
#else
#include "crypto_test_cmac.h"

/* Currently, cccmac and friends won't work when length == 0 and the
 * data pointer is NULL.
 */

int showBytesAreEqual(byteBuffer bb1, byteBuffer bb2, char *label) {
        ok(bytesAreEqual(bb1, bb2), label);
    if(bytesAreEqual(bb1, bb2) == 0) {
        printByteBuffer(bb1, "Want");
        printByteBuffer(bb2, "Got ");
        return 0;
    }
    return 1;
}

int test_cmac_answer(char *mode_name, const test_vector *vector, void*answer, char *test_type) {
    byteBuffer answer_bb;
    byteBuffer correct_answer_bb;
    int isEqual;
    if(vector->Mac == NULL) {
        answer_bb = bytesToBytes(answer, CMAC_BLOCKSIZE);
        diag("/* CMAC-%d test %d */", vector->Key_len*8, vector->Count);
        diag("\t\t\"%s\",\n", bytesToHexString(answer_bb));
        return 1;
    } else {
        correct_answer_bb = hexStringToBytes((char *) vector->Mac);
        answer_bb = bytesToBytes(answer, correct_answer_bb->len);
    }
    isEqual=bytesAreEqual(correct_answer_bb, answer_bb);
    ok((isEqual && vector->Result==0) || (!isEqual && vector->Result!=0), "compare memory of answer");
    if(!isEqual && vector->Result==0) {
        diag("Failed Test (%d) for CMAC-%d-%s %s", vector->Count, vector->Key_len*8, mode_name, test_type);
        printByteBuffer(correct_answer_bb, "Correct Answer");
        printByteBuffer(answer_bb, "Provided Answer");
    }
    free(correct_answer_bb);
    free(answer_bb);
    return 1;
}

/* =============================================================================

 Test for new CMAC

 ==============================================================================*/

static int test_oneshot(const struct ccmode_cbc *cbc, char *mode_name, const test_vector *vector) {
    uint8_t answer[CMAC_BLOCKSIZE];
    byteBuffer key = hexStringToBytes(vector->Key);
    byteBuffer in = hexStringToBytes(vector->Msg);
    byteBuffer expected_answer = hexStringToBytes(vector->Mac);
    if (vector->Result==0) {
        is(cccmac_one_shot_generate(cbc, key->len, key->bytes,
                                    in->len, in->bytes,
                                    expected_answer->len, answer),0,"generate cmac");
        ok(test_cmac_answer(mode_name, vector, answer, "one-shot"), "check answer");
        is(cccmac_one_shot_verify(cbc, key->len, key->bytes,
                                  in->len, in->bytes,
                                  expected_answer->len, expected_answer->bytes),0,"valid cmac");
    } else {
        isnt(cccmac_one_shot_verify(cbc, key->len, key->bytes,
                                    in->len, in->bytes,
                                    expected_answer->len, expected_answer->bytes),0,"detect invalid cmac");
        ok(test_cmac_answer(mode_name, vector, answer, "one-shot"), "check answer");
    }
    free(key);
    free(in);
    free(expected_answer);
    return 1;
}


static int test_discrete(const struct ccmode_cbc *cbc, char *mode_name, const test_vector *vector) {

    uint8_t answer[CMAC_BLOCKSIZE];
    cccmac_mode_decl(cbc, cmac);

    byteBuffer key = hexStringToBytes(vector->Key);
    byteBuffer in = hexStringToBytes(vector->Msg);
    size_t  nbytes = in->len;
    uint8_t *data = in->bytes;

    is(cccmac_init(cbc, cmac, key->len, key->bytes),0,"init");

    byteBuffer correct_answer_k1 = hexStringToBytes(vector->SubKey1);
    byteBuffer correct_answer_k2 = hexStringToBytes(vector->SubKey2);
    byteBuffer answer_k1 = bytesToBytes(cccmac_k1(cmac), 16);
    byteBuffer answer_k2 = bytesToBytes(cccmac_k2(cmac), 16);
    byteBuffer expected_answer = hexStringToBytes(vector->Mac);
    if (correct_answer_k1->len) {
        showBytesAreEqual(correct_answer_k1, answer_k1, "Subkey K1 is correct");
    }
    if (correct_answer_k2->len) {
        showBytesAreEqual(correct_answer_k2, answer_k2, "Subkey K2 is correct");
    }

    // Process some bytes
    size_t rbytes=cc_rand(32);
    size_t i;
    for(i=0; (i<rbytes) && nbytes; i++) {
        is(cccmac_update(cmac, 1, data), 0, "update one byte");
        data+=1;
        nbytes-=1;
    }
    for(; i<32; i++) pass("update one byte");

    // Process 2 blocks
    size_t blockchunck=2;
    if (nbytes >= blockchunck*CMAC_BLOCKSIZE) {
        is(cccmac_update(cmac, blockchunck*CMAC_BLOCKSIZE, data), 0, "update 2 blocks");
        data += blockchunck*CMAC_BLOCKSIZE;
        nbytes -= blockchunck*CMAC_BLOCKSIZE;
    } else pass("update 2 blocks");

    // Process the rest
    is(cccmac_update(cmac, nbytes, data),0,"update");

    if (vector->Result==0) {
        cccmac_mode_decl(cbc, cmac2);
        memcpy(cmac2, cmac, cccmac_ctx_size(cccmac_cbc(cmac)));

        // Test generate
        is(cccmac_final_generate(cmac, expected_answer->len, answer),0,"final_generate");
        ok(test_cmac_answer(mode_name, vector, answer, "one-shot"), "check answer");

        // Test verify
        is(cccmac_final_verify(cmac2, expected_answer->len, expected_answer->bytes),0,"final_generate");
    } else {
        isnt(cccmac_final_verify(cmac, expected_answer->len, expected_answer->bytes),0,"detect invalid cmac");
    }
    free(key);
    free(in);
    free(correct_answer_k1);
    free(correct_answer_k2);
    free(answer_k1);
    free(answer_k2);
    free(expected_answer);
    return 1;
}


static int test_negative(const struct ccmode_cbc *cbc) {
    uint8_t key[32];
    cccmac_mode_decl(cbc, cmac);
    isnt(cccmac_init(cbc, cmac, 15,key),0,"init");
    return 0;
}


static int test_cmac(const struct ccmode_cbc *cbc, char *mode_name) {

    static const test_vector vector[] = {
#define keystr128    "000102030405060708090a0b0c0d0e0f"
#include "../test_vectors/CMACGenAES128.inc"
#include "../test_vectors/CMACVerAES128.inc"
#include "../test_vectors/CMACGenAES192.inc"
#include "../test_vectors/CMACVerAES192.inc"
#include "../test_vectors/CMACGenAES256.inc"
#include "../test_vectors/CMACVerAES256.inc"
        {
            .Count = 1, // cnt
            .Key_len = 16,
            .Key = "2b7e151628aed2a6abf7158809cf4f3c", // keyStr
            .SubKey1 = "fbeed618357133667c85e08f7236a8de", // k1Str
            .SubKey2 = "f7ddac306ae266ccf90bc11ee46d513b", // k2Str
            .Msg = "", // in
            .Mac = "bb1d6929e95937287fa37d129b756746", // out
            .Result = 0
        },
        {
            .Count = 2, // cnt
            .Key_len = 16,
            .Key = "2b7e151628aed2a6abf7158809cf4f3c", // keyStr
            .SubKey1 = "fbeed618357133667c85e08f7236a8de", // k1Str
            .SubKey2 = "f7ddac306ae266ccf90bc11ee46d513b", // k2Str
            .Msg = "6bc1bee22e409f96e93d7e117393172a", // in
            .Mac = "070a16b46b4d4144f79bdd9dd04a287c", // out
            .Result = 0
        },
        {
            .Count = 3, // cnt
            .Key_len = 16,
            .Key = "2b7e151628aed2a6abf7158809cf4f3c", // keyStr
            .SubKey1 = "fbeed618357133667c85e08f7236a8de", // k1Str
            .SubKey2 = "f7ddac306ae266ccf90bc11ee46d513b", // k2Str
            .Msg = "6bc1bee22e409f96e93d7e117393172a"\
            "ae2d8a571e03ac9c9eb76fac45af8e51"\
            "30c81c46a35ce411", // in
            .Mac = "dfa66747de9ae63030ca32611497c827", // out
            .Result = 0
        },
        {
            .Count = 4, // cnt
            .Key_len = 16,
            .Key = "2b7e151628aed2a6abf7158809cf4f3c", // keyStr
            .SubKey1 = "fbeed618357133667c85e08f7236a8de", // k1Str
            .SubKey2 = "f7ddac306ae266ccf90bc11ee46d513b", // k2Str
            .Msg = "6bc1bee22e409f96e93d7e117393172a"\
            "ae2d8a571e03ac9c9eb76fac45af8e51"\
            "30c81c46a35ce411e5fbc1191a0a52ef"\
            "f69f2445df4f9b17ad2b417be66c3710", // in
            .Mac = "51f0bebf7e3b9d92fc49741779363cfe", // out
            .Result = 0
        },
        {
            .Count = 5, // cnt
            .Key_len = 16,
            .Key = "2b7e151628aed2a6abf7158809cf4f3c", // keyStr
            .SubKey1 = "fbeed618357133667c85e08f7236a8de", // k1Str
            .SubKey2 = "f7ddac306ae266ccf90bc11ee46d513b", // k2Str
            .Msg = "00000000000000000000000000000001", // in
            .Mac = "d9fa25e90d2fa42543939a85b543e233", // out
            .Result = 0
        },
    };

    size_t vector_size = CC_ARRAY_LEN(vector);

    for(size_t i = 0; i < vector_size; i++) {
        ok(test_oneshot(cbc, mode_name, &vector[i]), "test one-shot AES%d_CMAC",vector[i].Key_len*8);
        ok(test_discrete(cbc, mode_name, &vector[i]), "test discrete AES%d_CMAC",vector[i].Key_len*8);
    }
    test_negative(cbc);
    return 1;
}


int cccmac_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
	plan_tests(50469);
    if(verbose) diag("Starting cmac tests");
    ok(test_cmac(ccaes_cbc_encrypt_mode(), "system cbc di"), "CMAC Tests");
    return 0;
}
#endif
