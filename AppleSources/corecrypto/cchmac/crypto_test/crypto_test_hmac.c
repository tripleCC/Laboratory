/* Copyright (c) (2012,2014-2016,2018,2019,2021-2023) Apple Inc. All rights reserved.
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

#if (CCHMAC == 0)
entryPoint(cchmac_tests,"cchmac test")
#else
#include <corecrypto/ccasn1.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdigest_priv.h>
#include "ccdigest_internal.h"
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>
#include <corecrypto/ccripemd.h>
#include "ccsha3_internal.h"

/* Python script to generate the test vectors.

from cryptography.hazmat.primitives import hashes, hmac

# Add the buffer for the specific unit test
# buffer = ...
 
HASHES = [
    hashes.MD5(),
    hashes.SHA1(),
    hashes.SHA224(),
    hashes.SHA256(),
    hashes.SHA384(),
    hashes.SHA512(),
    hashes.SHA512_256(),
    hashes.SHA3_224(),
    hashes.SHA3_256(),
    hashes.SHA3_384(),
    hashes.SHA3_512()
]
key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
for HASH in HASHES:
    HMAC = hmac.HMAC(key, HASH)
    HMAC.update(buffer)
    print("            \"{}\", // {}".format(HMAC.finalize().hex(), HASH.name))

*/

/* Currently, cchmac and friends won't work when length == 0 and the
 * data pointer is NULL.
 */

#define keystr128    "000102030405060708090a0b0c0d0e0f"


#define HMAC_DATA_POINTER_NULL_TOLERANT 0

typedef struct test_vector_t {
    char *keyStr;
    uint8_t *data;
    size_t data_len;
    char *md2_answer;
    char *md4_answer;
    char *md5_answer;
    char *sha1_answer;
    char *sha224_answer;
    char *sha256_answer;
    char *sha384_answer;
    char *sha512_answer;
    char *sha512_256_answer;
    char *sha3_224_answer;
    char *sha3_256_answer;
    char *sha3_384_answer;
    char *sha3_512_answer;
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
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA512)) return "SHA512-256";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_224)) return "SHA3-224";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_256)) return "SHA3-256";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_384)) return "SHA3-384";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_512)) return "SHA3-512";
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_RMD160)) return "RMD160";
    return NULL;
}

static int test_answer(const struct ccdigest_info *di, test_vector *vector, void*answer) {
    char *correct_answer = NULL;
    if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD2)) correct_answer = vector->md2_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD4)) correct_answer = vector->md4_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD5)) correct_answer = vector->md5_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA1)) correct_answer = vector->sha1_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA224)) correct_answer = vector->sha224_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA256)) correct_answer = vector->sha256_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA384)) correct_answer = vector->sha384_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA512)) correct_answer = vector->sha512_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA512_256)) correct_answer = vector->sha512_256_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_224)) correct_answer = vector->sha3_224_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_256)) correct_answer = vector->sha3_256_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_384)) correct_answer = vector->sha3_384_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA3_512)) correct_answer = vector->sha3_512_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_RMD160)) correct_answer = vector->rmd160_answer;
    byteBuffer answer_bb = bytesToBytes(answer, di->output_size);
    if(correct_answer == NULL) {
        diag("Digest %s: ", digest_name(di));
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

static int guard_ok(uint8_t *p, int chr, size_t len) {
    for(size_t i=0; i<len; i++) if(p[i] != chr) return 0;
    return 1;
}

static int test_discrete(const struct ccdigest_info *di, test_vector *vector) {
    uint8_t answer[MAX_DIGEST_OUTPUT_SIZE];
    size_t total = vector->data_len;
    size_t chunk = vector->data_len/2;
    uint8_t *p = vector->data;
    uint8_t ctxfrontguard[4096];
    cchmac_di_decl(di, ctx);
    uint8_t ctxrearguard[4096];
    memset(ctxfrontguard, 0xee, 4096);
    memset(ctxrearguard, 0xee, 4096);
    // break it up into pieces.
    byteBuffer key = hexStringToBytes(vector->keyStr);
    cchmac_init(di, ctx, key->len, key->bytes);
    ok(guard_ok(ctxfrontguard, 0xee, 4096), "context is safe");
    ok(guard_ok(ctxrearguard, 0xee, 4096), "context is safe");
    do {
        cchmac_update(di, ctx, chunk, p);
        total -= chunk;
        p += chunk;
        chunk /= 2;
        if(chunk == 0) chunk = total;
    } while(total);
    ok(guard_ok(ctxfrontguard, 0xee, 4096), "context is safe");
    ok(guard_ok(ctxrearguard, 0xee, 4096), "context is safe");
    
    cchmac_final(di, ctx, answer);
    
    ok(guard_ok(ctxfrontguard, 0xee, 4096), "context is safe");
    ok(guard_ok(ctxrearguard, 0xee, 4096), "context is safe");
    ok(test_answer(di, vector, answer), "check answer");
    free(key);
    return 1;
}

static int test_oneshot(const struct ccdigest_info *di, test_vector *vector) {
    uint8_t answer[MAX_DIGEST_OUTPUT_SIZE];
    byteBuffer key = hexStringToBytes(vector->keyStr);
    cchmac(di, key->len, key->bytes, vector->data_len, vector->data, answer);
    ok(test_answer(di, vector, answer), "check answer");
    free(key);
    return 1;
}

static int test_hmac_many_blocks(const struct ccdigest_info *di) {
    static uint8_t buffer[16383];
    static test_vector vector[] = {
        { keystr128, buffer, sizeof(buffer),
            "7182daf0dc1007cbac6a0e719098f170", // MD2
            "877a48e58590d460090c7777f4a840c6", // MD4
            "7f883f92f8ef750adfa292125b9fbc55", // MD5
            "4ce3f19af4a6ef30a24a178407e9fdac3b28f99a", // SHA1
            "210db31bed8c58f6f79dcbce97a7cea7e2ae4a1ff5f9488b0bc45c45", // SHA224
            "4185e361836f030b1e72b3f799923405741f4c9676151f496a4a0c55d3682665", // SHA256
            "ae1de46bbe8045f03fa5c54a8033c9fa823bd1f244155fa479eb05f771c1f110a21d31488b40f54f710d30b2eeb23f20", // SHA384
            "58b28d36a039a8267d0ad5bcef1c062caf6682699cd1ec2fa201f6d042b85946a32daee9abbeabb6ec2f29b6cadd29ce333aaa146ca1cba55302f236e03ce97d", // SHA512
            "95aadd23e83e743df0e3aff6d8c831ae05f36102405aaeaa09e998c39e53ec4f", // SHA512-256
            "9762f170523126befc7a0dc97ffb76aaeb6213dd250fcb3455ac0348", // SHA3-224
            "636650c8c24364a34ee99b79c460389e1e0c1d34d5ff477661f1c5e0b9cd8c28", // SHA3-256
            "7faed44f63a69a415d379bdebe079958dde2edf00ca97fb78248490be8cf402f014d14c6527ee82e949a8297e509353f", // SHA3-384
            "e4fd0a65bb549a89db52ccb57db03b7949b49cf8bdbfd9ce7ccb3e2fc50645c90517737c2465a328f1897e0b7193d3e9b9c288c5156d21f3a1810439b870666b", // SHA3-512
            "8031f9ec1222c149ca224bd90ba9eadecba75f0f", // RMD160
        },
    };
    int vector_size = (int)CC_ARRAY_LEN(vector);
    for(size_t n = 0; n < sizeof(buffer); n++) buffer[n] = n&0xff;
    if(verbose) diag("hmac Large Test\n");
    for(int i=0; i<vector_size; i++) {
        ok(test_oneshot(di, &vector[i]), "test one-shot with data less than blocksize");
        ok(test_discrete(di, &vector[i]), "test discrete with data less than blocksize");
    }
    return 1;
}

static int test_hmac_eq_blocksize(const struct ccdigest_info *di) {
    static test_vector vector[] = {
        { keystr128, (uint8_t *) "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 128,
            "71aa63826caf519e696c04ce8a7766c7", // MD2
            "ca5312e0065d940d76fb5142c74c8402", // MD4
            "e48be2f550c05454fef7c84dd60d4ff4", // MD5
            "2597cdf90d6807154e157362510ea592f8468f03", // SHA1
            "c6e8ebf4630eaa709c0a2bb4475263491537228b6b7bb891a5bb8103", // SHA224
            "89e5037a3d76ac6f6ca17cee03049c9c96d4f4757405a6b16be29c3e5c118ca1", // SHA256
            "b8b562827c8d48fb408a31b1eb418694c588962a0f247fd44dc71306c6eaa32cf1f4d795546a41494313f78f3e19e8e3", // SHA384
            "520bb5e76f51229c70751a8ed4a8a31c6b5f0d6836ff5a5389da6c1eccc40ff1193541fbb3141b8c2344a1356f492ad0513abf1d7d3ad79908a97c38c65bf95a", // SHA512
            "8f38fdf998ce9210d2ef133a6213118286d55dfb471675ffd937a1bb31d75f7d", // SHA512-256
            "88cccf67d6b3a80eb38e2f80bde3a02a811cd20dc9c7caae1af44e30", // SHA3-224
            "a1350cd32afa146eb2cde0804950ebf4e992319d1cc0055a44cf25d3973ca56a", // SHA3-256
            "146b794c5751c629ee9a0bc1ba099c3f0a9dd21f624363bde9cec65aa8a138bc97a40ca4ee3ea91c821f4d23a665fce5", // SHA3-384
            "b0ee91ddc4eb087ec4df58dd6431845f9effb3a3d8b56bbd8f13a1eca349015c5b3a7901664dbad0f56aed760bcd24056d880f5eaa4187a7cd59e6422a2b0c46", // SHA3-512
            "bafe182a4fc5545054c99e55ce94b947387e0a8a", // RMD160
        },
    };
    int vector_size = (int)CC_ARRAY_LEN(vector);
    if(verbose) diag("hmac EQ Test\n");
    for(int i=0; i<vector_size; i++) {
        ok(test_oneshot(di, &vector[i]), "test one-shot with data less than blocksize");
        ok(test_discrete(di, &vector[i]), "test discrete with data less than blocksize");
    }
    return 1;
}

static int test_hmac_lt_blocksize(const struct ccdigest_info *di) {
    static test_vector vector[] = {
        { keystr128, (uint8_t *) "Test vector from febooti.com", 28,
            "2d42a2ed33bd579625cbeffcf734ea65", // MD2
            "b024b400fd0bad206d1102344dc36b24", // MD4
            "33c778da7bbc0011c0933c806f59c85a", // MD5
            "7d5a46909cd7e0c51c2a2a32bf356f32277948e3", // SHA1
            "4d656dcbd37a5911314e6ddccfdd1f7756e9449ed44615bbe006249f", // SHA224
            "d9d9e526ea6cc3a93797e23e34138322721cd7454103124073263834a00393c3", // SHA256
            "cf40060ad6784b2a85ad9a15611d1f408cb91e68591db71953f77681cba706cadab6897c509f1731cd9eaae6e9a97392", // SHA384
            "5c4ea434cc9e3e2e971d1c4f0e202b17354aa810ebb2699ff752f301981950cdc53fe6a1215afbc7e5306e6da21fd7b58f4906727c856931b0798cd977b43614", // SHA512
            "64520a152d03469f1b806b66c0d148a81aa5ad65da434945ec2bc277b7dc380d", // SHA512-256
            "ac82e31a3d6f9ce73268c548c0584f1e397ade544731bf0dab41301c", // SHA3-224
            "b1d2f9dbef53570d7bf94bd0c039556a01bde43f04a572276e8fe89ab5794f1a", // SHA3-256
            "e9c4e47b6a4e7a4f13f3c58309f5dc2f9cb9cb9b56d900145df38149088f0ee4e17dbee574336554637725bdbd776a80", // SHA3-384
            "c5a7109eec73904671a4082b6cf5b1a082b4f5cdee4cb7981d7227f5b58f37c39382242dec93250450d0664a2ac6ae8802c766c3ca925102a5cddca5a5fed621", // SHA3-512
            "fde553210d3591ca69404e7ef1c9d401a260688d", // RMD160
        },
    };
    int vector_size = (int)CC_ARRAY_LEN(vector);
    if(verbose) diag("hmac LT Test\n");

    for(int i=0; i<vector_size; i++) {
        ok(test_oneshot(di, &vector[i]), "test one-shot with data less than blocksize");
        ok(test_discrete(di, &vector[i]), "test discrete with data less than blocksize");
    }
    return 1;
}

static int test_hmac_of_zero(const struct ccdigest_info *di) {
#if HMAC_DATA_POINTER_NULL_TOLERANT
    static test_vector vectorNULL = { keystr128, NULL, 0,
 		"a4171a022881b477ebb77da9eccbdaf6", // MD2
 		"752e874f35085e497d5032112cc65131", // MD4
        "c91e40247251f39bdfe6a7b72a5857f9", // MD5
        "5433122f77bcf8a4d9b874b4149823ef5b7c207e", // SHA1
        "4e496054842798a861acb67a9fe85fb7ec7f4d91719f077ea3bd0f72", // SHA224
        "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d", // SHA256
        "6a0fdc1c54c664ad91c7c157d2670c5d44e4d44ebad2359a0206974c7088b1a867f76971e6c240c33b33a66ba295bb56", // SHA384
        "2fec800ca276c44985a35aec92067e5e53a1bb80a6fdab1d9c97d54068118f30ad4c33717466d372ea00bbf126e5b79c6f7143dd36c31f72028330e92ae3a359", // SHA512
        "87593d78b4fd8f312568c327a810afc2d3983f3b98e71b9868e2ea37c665323b", // SHA512-256
        "453bf709dc853124dc7845b24711648184f5dc3aa46c8f644639a789", // SHA3-224
        "72756291ff30f3e916bef99ec9cf5938b25d90bbcac1bdb1e1e6564e8ec6fda5", // SHA3-256
        "5b0196779bdaf859e99869a63c9fdf3821e9100a370b5e9b88f76b9da87410f99846e7dbb4f8a69368c5c5a834b3128d", // SHA3-384
        "908d1be1a2cc5cc4b8c62e98d09ab6e967529fcb24f4177cb94cb072f5968d01ca58633748dc80d4615e3d21228bb3a5f535fa1cb963df463cc28abaf1a9b2d1", // SHA3-512
 		"8e4b77206892943105b5ec25c0d7132c6f541895", // RMD160
    };
#endif /* HMAC_DATA_POINTER_NULL_TOLERANT */
    static test_vector vectorPOINTER = { keystr128, (uint8_t *) "XXXX", 0,
 		"a4171a022881b477ebb77da9eccbdaf6", // MD2
 		"752e874f35085e497d5032112cc65131", // MD4
        "c91e40247251f39bdfe6a7b72a5857f9", // MD5
        "5433122f77bcf8a4d9b874b4149823ef5b7c207e", // SHA1
        "4e496054842798a861acb67a9fe85fb7ec7f4d91719f077ea3bd0f72", // SHA224
        "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d", // SHA256
        "6a0fdc1c54c664ad91c7c157d2670c5d44e4d44ebad2359a0206974c7088b1a867f76971e6c240c33b33a66ba295bb56", // SHA384
        "2fec800ca276c44985a35aec92067e5e53a1bb80a6fdab1d9c97d54068118f30ad4c33717466d372ea00bbf126e5b79c6f7143dd36c31f72028330e92ae3a359", // SHA512
        "87593d78b4fd8f312568c327a810afc2d3983f3b98e71b9868e2ea37c665323b", // SHA512-256
        "453bf709dc853124dc7845b24711648184f5dc3aa46c8f644639a789", // SHA3-224
        "72756291ff30f3e916bef99ec9cf5938b25d90bbcac1bdb1e1e6564e8ec6fda5", // SHA3-256
        "5b0196779bdaf859e99869a63c9fdf3821e9100a370b5e9b88f76b9da87410f99846e7dbb4f8a69368c5c5a834b3128d", // SHA3-384
        "908d1be1a2cc5cc4b8c62e98d09ab6e967529fcb24f4177cb94cb072f5968d01ca58633748dc80d4615e3d21228bb3a5f535fa1cb963df463cc28abaf1a9b2d1", // SHA3-512
 		"8e4b77206892943105b5ec25c0d7132c6f541895", // RMD160
   };
#if HMAC_DATA_POINTER_NULL_TOLERANT
    if(verbose) diag("NULL-Oneshot\n");
    ok_or_fail(test_oneshot(di, &vectorNULL), "test one-shot with NULL pointer");
    ok_or_fail(test_discrete(di, &vectorNULL), "test discrete with NULL pointer");
#endif /* HMAC_DATA_POINTER_NULL_TOLERANT */
    if(verbose) diag("Pointer-Oneshot\n");
    ok(test_oneshot(di, &vectorPOINTER), "test one-shot with live pointer");
    ok(test_discrete(di, &vectorPOINTER), "test discrete with live pointer");
    return 1;
}

static int test_hmac(const struct ccdigest_info *di) {
    ok(test_hmac_of_zero(di), "test_hmac_of_zero");
    ok(test_hmac_lt_blocksize(di), "test_hmac_lt_blocksize");
    ok(test_hmac_eq_blocksize(di), "test_hmac_eq_blocksize");
    ok(test_hmac_many_blocks(di), "test_hmac_many_blocks");
    return 1;
}

int cchmac_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(1325);

    if(verbose) diag("Starting hmac tests\n");

    // Pure C versions
    ok(test_hmac(&ccmd2_ltc_di), "ccmd2_di");
    ok(test_hmac(&ccmd4_ltc_di), "ccmd4_ltc_di");
    ok(test_hmac(&ccmd5_ltc_di), "ccmd5_ltc_di");
    ok(test_hmac(&ccsha1_ltc_di), "ccsha1_ltc_di");
    ok(test_hmac(&ccsha1_eay_di), "ccsha1_eay_di");
    ok(test_hmac(&ccsha224_ltc_di), "ccsha224_ltc_di");
    ok(test_hmac(&ccsha256_ltc_di), "ccsha256_ltc_di");
    ok(test_hmac(&ccsha384_ltc_di), "ccsha384_ltc_di");
    ok(test_hmac(&ccsha512_ltc_di), "ccsha512_ltc_di");
    ok(test_hmac(&ccsha512_256_ltc_di), "ccsha512_256_ltc_di");
    ok(test_hmac(&ccsha3_224_c_di), "ccsha3_224_c_di");
    ok(test_hmac(&ccsha3_256_c_di), "ccsha3_256_c_di");
    ok(test_hmac(&ccsha3_384_c_di), "ccsha3_384_c_di");
    ok(test_hmac(&ccsha3_512_c_di), "ccsha3_512_c_di");
    ok(test_hmac(&ccrmd160_ltc_di), "ccrmd160_ltc_di");

    // Default (optimized)
    ok(test_hmac(ccsha1_di()),   "Default ccsha1_di");
    ok(test_hmac(ccsha224_di()), "Default ccsha224_di");
    ok(test_hmac(ccsha256_di()), "Default ccsha256_di");
    ok(test_hmac(ccsha384_di()), "Default ccsha384_di");
    ok(test_hmac(ccsha512_di()), "Default ccsha512_di");
    ok(test_hmac(ccsha512_256_di()), "Default ccsha512_256_di");
    ok(test_hmac(ccsha3_224_di()), "Default ccsha3_224_di");
    ok(test_hmac(ccsha3_256_di()), "Default ccsha3_256_di");
    ok(test_hmac(ccsha3_384_di()), "Default ccsha3_384_di");
    ok(test_hmac(ccsha3_512_di()), "Default ccsha3_512_di");

    return 0;
}
#endif

