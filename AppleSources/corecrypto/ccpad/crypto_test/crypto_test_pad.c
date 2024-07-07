/* Copyright (c) (2014-2016,2018-2022) Apple Inc. All rights reserved.
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
#include "testmore.h"
#include "testbyteBuffer.h"
#include "cc_debug.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccpad.h>
#include "cc_runtime_config.h"
#include <corecrypto/ccn.h>
#include <stdbool.h>
#include "ccconstanttime.h"

#if (CCPAD == 0)
entryPoint(ccpad_tests,"ccpad")
#else
#include "crypto_test_modes.h"
#include "ccsymmetric_pad.h"

static const int kTestTestCount = 1205;

static const int verbose=0;

#include <corecrypto/ccrng_test.h>
#include "cccycles.h"
#include "ccstats.h"

//======================================================================
// Constant time verification parameters
//======================================================================

// Number of iteration of test where timings are not taken into account.
// Made to reach a stable performance state
#define CCPAD_WARMUP        0

// Each sample is the average time for many iteration with identical inputs
#define CCPAD_TIMING_REPEAT  150

// Number of sample for the statistical analysis
// typically 100~1000 is a good range
#define CCPAD_TIMING_SAMPLES 200

// In case of failure, try many times
// This is to reduce false positives due to noise/timing accuracy.
// If implementation is not constant time, the behavior will be consistent
// So that this does not reduce the detection power.
#define CCPAD_TIMING_RETRIES 10

// Two statitical tools are available: T-test and Wilcoxon.
// T-test assumes that the distribution to be compared are normal
// Wilcoxon measure offset between distribution.
// Due to potential switches between performance state or occasional
// latencies, Wilcoxon is recommended.
// > Set to 1 to use T-test instead of Wilcoxon
#define T_TEST  1

// Number of iteration of the full test (to play with to evaluate chances of false positives)
#define CMP_TIMING_TEST_ITERATION 1

// Quantile for the repeated timing. Empirical value.
#define CCPAD_PERCENTILE 9

//======================================================================

// Local types
typedef struct {
    ccpad_select padding_mode;
    char *keyStr;
    char *init_ivStr;
    char *ptStr;
    char *outputStr;
} ccpad_test_vector_t;

static int
ccsymmetric_pad_ciphertext_tests(duplex_cryptor cryptor, const ccpad_test_vector_t *test);

static int
ccsymmetric_pad_plaintext_tests(duplex_cryptor cryptor, ccpad_select padding_mode, const ccpad_test_vector_t *test);

static int
ccsymmetric_pad_roundtrip_tests(duplex_cryptor cryptor, ccpad_select padding_mode, size_t message_size);

// Test vectors

// These are stock keys/IVs/blocks to encode - don't change them - add if you

#define keystr64     "0001020304050607"
#define keystr128    "000102030405060708090a0b0c0d0e0f"
#define ivstr64      "0f0e0d0c0b0a0908"
#define ivstr128     "0f0e0d0c0b0a09080706050403020100"

#define MSG_01       "00"
#define MSG_02       "0000"
#define MSG_03       "000000"
#define MSG_04       "00000000"
#define MSG_05       "0000000000"
#define MSG_06       "000000000000"
#define MSG_07       "00000000000000"
#define MSG_08       "0000000000000000"
#define MSG_09       "000000000000000000"
#define MSG_10       "00000000000000000000"
#define MSG_11       "0000000000000000000000"
#define MSG_12       "000000000000000000000000"
#define MSG_13       "00000000000000000000000000"
#define MSG_14       "0000000000000000000000000000"
#define MSG_15       "000000000000000000000000000000"
#define MSG_16       "00000000000000000000000000000000"
#define MSG_17       "0000000000000000000000000000000000"
#define MSG_18       "000000000000000000000000000000000000"
#define MSG_19       "00000000000000000000000000000000000000"
#define MSG_20       "0000000000000000000000000000000000000000"
#define MSG_21       "000000000000000000000000000000000000000000"
#define MSG_22       "00000000000000000000000000000000000000000000"
#define MSG_23       "0000000000000000000000000000000000000000000000"
#define MSG_24       "000000000000000000000000000000000000000000000000"
#define MSG_25       "00000000000000000000000000000000000000000000000000"
#define MSG_26       "0000000000000000000000000000000000000000000000000000"
#define MSG_27       "000000000000000000000000000000000000000000000000000000"
#define MSG_28       "00000000000000000000000000000000000000000000000000000000"
#define MSG_29       "0000000000000000000000000000000000000000000000000000000000"
#define MSG_30       "000000000000000000000000000000000000000000000000000000000000"
#define MSG_31       "00000000000000000000000000000000000000000000000000000000000000"
#define MSG_32       "0000000000000000000000000000000000000000000000000000000000000000"


#define PAD_16       "10101010101010101010101010101010"
#define PAD_15       "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
#define PAD_14       "0e0e0e0e0e0e0e0e0e0e0e0e0e0e"
#define PAD_13       "0d0d0d0d0d0d0d0d0d0d0d0d0d"
#define PAD_12       "0c0c0c0c0c0c0c0c0c0c0c0c"
#define PAD_11       "0b0b0b0b0b0b0b0b0b0b0b"
#define PAD_10       "0a0a0a0a0a0a0a0a0a0a"
#define PAD_09       "090909090909090909"
#define PAD_08       "0808080808080808"
#define PAD_07       "07070707070707"
#define PAD_06       "060606060606"
#define PAD_05       "0505050505"
#define PAD_04       "04040404"
#define PAD_03       "030303"
#define PAD_02       "0202"
#define PAD_01       "01"

#define END_VECTOR   {0,  NULL, NULL, NULL, NULL}

static const ccpad_test_vector_t aes_plaintext_vectors[] = {
    {ccpad_pkcs7,keystr128,ivstr128, MSG_01,  PAD_15},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_02,  PAD_14},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_03,  PAD_13},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_04,  PAD_12},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_05,  PAD_11},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_06,  PAD_10},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_07,  PAD_09},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_08,  PAD_08},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_09,  PAD_07},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_10,  PAD_06},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_11,  PAD_05},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_12,  PAD_04},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_13,  PAD_03},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_14,  PAD_02},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_15,  PAD_01},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_16,  PAD_16},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_17,  PAD_15},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_18,  PAD_14},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_19,  PAD_13},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_20,  PAD_12},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_21,  PAD_11},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_22,  PAD_10},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_23,  PAD_09},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_24,  PAD_08},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_25,  PAD_07},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_26,  PAD_06},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_27,  PAD_05},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_28,  PAD_04},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_29,  PAD_03},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_30,  PAD_02},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_31,  PAD_01},
    {ccpad_pkcs7,keystr128,ivstr128, MSG_32,  PAD_16},
    END_VECTOR
};

static const ccpad_test_vector_t des_plaintext_vectors[] = {
    {ccpad_pkcs7,keystr64, ivstr64, MSG_01,  PAD_07},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_02,  PAD_06},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_03,  PAD_05},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_04,  PAD_04},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_05,  PAD_03},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_06,  PAD_02},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_07,  PAD_01},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_08,  PAD_08},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_09,  PAD_07},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_10,  PAD_06},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_11,  PAD_05},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_12,  PAD_04},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_13,  PAD_03},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_14,  PAD_02},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_15,  PAD_01},
    {ccpad_pkcs7,keystr64, ivstr64, MSG_16,  PAD_08},
    END_VECTOR
};

#define keystr128_cts    "636869636b656e207465726979616b69"
#define ivstr128_cts     "0f0e0d0c0b0a09080706050403020100"
#define zeroX16          "00000000000000000000000000000000"

static const ccpad_test_vector_t aes_cbc_ciphertext_vectors[] = {
    {ccpad_pkcs7,  "badfd2102e1e180a634204249c5a6933", "84c06c16c151007ca9ed9bb926e66eec",
        "fb58510beb65062c525a3de42d934d4b4ec433d600a1467142751886a10e7bf96f236c196d12dcf0698e09efc79a4bea072bc0830da8886674cf6174206cca2d4e9e543f0016ec4dcc602ffd0a417c722879e259497f89aee5ad99a4f65887058242250fbe44f61eab5e668adbb780a4cba97393f6ff152c13c39b57ed727bb94cf19d1b4a55f45cceb22b6c4f26f736d20a48cb6230578591c8d33d72b778d30b304818b20d918ef654cabeae1038f2a0db5170d2b4df38c6efc887bc1f837fba34e97daf8920414b748a909ad5ef56fb47fa53c680aae808f3e6065689339728251e18cd264f5385c969f87104099563a411cfe681d19134e9479e059d09b69f5010912291d0232f733a2688b3042ec4e82ce5163c384ee54a9f10e48a8ab46fd7147351dd8514bda5d8c4ce8babcc3ef82dbf44799fc59e37d8f3c99506d2168c84d8381f4f9a84cbce7bd0bb4bbbcdef0c626356d3ca126c8776e3a291881af518e23dbd067016c5898bed5f64d6e8f8acefba83f92b0c318ec7b905165fb6b81bc60528c0a0e3db38ab1ee6f37e56dbf270c0751674e0ddb1a6076d8f78084ce31f0d3673e638e0110575b16d9d9f151c1b9aca8d15d7a8111c0de5acf5ae3b307e8064c90329e421e3434a1ecd253b153447c21c79c9946666dae444c49a31b1f94da603a8377168dc4f874e98fff5ae89dd35d44e89df5748223b7a24",
        "4b52b5e85aecaaaf886bd9e8805390c62e12e13357e4beb3b713e37d217c6f7a9e432a04f87bd8a4dd0ef79eb7bf41b5a2a27e63361d7cb7af7b3c9a8f0b56ae27dc9cfd6c10eb1a79c7be35d31c3965b8e7099775f7644029bd79321f5dd12c55280a30fabd1b95e27c2d4dec6ca4d8716f36e7abe3408f5120560b573e5495ae7aad668fa84d6a8a1156c231a5b6d983ece3e27d199a806dc629c1a60c08ccb0e4807d9fed88f28ce0f59583708f540f97110b2620b1679220abe13e3c4b727186b289794583b20154ce9a07a284df3e63572f462142cae8949d7dd6f2b26fb90d556ec75e93dd33b59d697883312af89e52945b9baedfebe28759cdba4dfbf6e6f201b087478642cf0b34f983593c68947e4ee05bd17716e6cfb7c74c876c0ba650f3979f5eceb72a71d0d46aac4474ae2048d2a9884aa12e292950c77b17de11e8d3e895e60b1c584b1c8d9edd40ba7917e396d1d3bfd1941923aa40213195e8b8f7f4d5ae1057cbecdf89c8959745d1fcece59115819dc661e7b097c132e8f98720a57a83469cb82c374fdebc97badd7cef8d160a7f27d50f35b7e4af6f1b78361828e32a55b25fd56efbc12f8fcb7e2e4f882afa0c7747a455a1fae00a561cbb878e01b32fafb23f397371a8b3441c8da654b902d8489383542188821859a44f0fb2b63a49835f8ba5f0231ff0f8f5fc3d5c812331b11e39bc03394e2875313166ac5f77e4900146c6faafba81"},
    {ccpad_cts1, keystr128_cts, zeroX16, "4920776f756c64206c696b652074686520", "97c6353568f2bf8cb4d8a580362da7ff7f"},
    {ccpad_cts1, keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320", "97687268d6ecccc0c07b25e25ecfe5fc00783e0efdb2c1d445d4c8eff7ed22"},
    {ccpad_cts1, keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8"},
    {ccpad_cts1, keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5b3fffd940c16a18c1b5549d2f838029e"},
    {ccpad_cts1, keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a89dad8bbb96c4cdc03bc103e1a194bbd8"},
    {ccpad_cts1, keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a89dad8bbb96c4cdc03bc103e1a194bbd84807efe836ee89a526730dbc2f7bc840"},
    {ccpad_cts1, keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee2dc88b70f6ae0243d2dbcd6822a1058604b1c432a7a71395b36d820e2c3de4ee"},
    {ccpad_cts1, keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
    "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee2dc88b70f6ae0243d2dbcd6822a105950b6576660739916d058623d688e27e"},
    {ccpad_cts1, keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee2dc88b70f6ae0243d2db751002ef7a0f9d915d15346571eee7aa"},
     // Test vectors from CommonCrypto
     {ccpad_cts2, keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee2dc88b70f6ae0243d2dbcd6822a1058604b1c432a7a71395b36d820e2c3de4ee"},
     {ccpad_cts2, keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
     "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee950b6576660739916d058623d688e27e2dc88b70f6ae0243d2dbcd6822a105"},
     {ccpad_cts2, keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
     "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee751002ef7a0f9d915d15346571eee7aa2dc88b70f6ae0243d2db"},
     // Test vectors from RFC3962
     {ccpad_cts3, keystr128_cts, zeroX16, "4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97"},
     {ccpad_cts3,  keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320", "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"},
     {ccpad_cts3,  keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"},
     {ccpad_cts3,  keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5"},
     {ccpad_cts3,  keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8"},
     {ccpad_cts3,  keystr128_cts, zeroX16, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8"},
      // Test vectors from CommonCrypto
     {ccpad_cts3,  keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee04b1c432a7a71395b36d820e2c3de4ee2dc88b70f6ae0243d2dbcd6822a10586"},
     {ccpad_cts3,  keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
     "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee950b6576660739916d058623d688e27e2dc88b70f6ae0243d2dbcd6822a105"},
     {ccpad_cts3,  keystr128_cts, ivstr128_cts, "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
     "e22abba9d2a201b18dc2f57e04aba21a16e0ed6358164c59ca64d204f33247ee751002ef7a0f9d915d15346571eee7aa2dc88b70f6ae0243d2db"},
     END_VECTOR
 };

// Compare the padded plaintext with what is expected
static int
ccsymmetric_pad_plaintext_tests(duplex_cryptor cryptor, ccpad_select padding_mode, const ccpad_test_vector_t *test) {
    // Retrieve test case info
    byteBuffer key =        hexStringToBytes(test->keyStr);
    byteBuffer init_iv =    hexStringToBytes(test->init_ivStr);
    byteBuffer message =    hexStringToBytes(test->ptStr);
    byteBuffer expected_padding =    hexStringToBytes(test->outputStr);
    size_t len = message->len;
    size_t result_len;
    size_t block_size=0;
    size_t padded_len=0;

    byteBuffer ciphertext,padded_message;

    // Set cipher
    cc_ciphermode_descriptor_s encrypt_desc;
    cc_ciphermode_descriptor_s decrypt_desc;

    encrypt_desc.cipher = cryptor->cipher;
    encrypt_desc.mode = cryptor->mode;
    encrypt_desc.direction = cc_Encrypt;
    encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;

    decrypt_desc.cipher = cryptor->cipher;
    decrypt_desc.mode = cryptor->mode;
    decrypt_desc.direction = cc_Decrypt;
    decrypt_desc.ciphermode = cryptor->decrypt_ciphermode;

    block_size=cc_symmetric_bloc_size(&encrypt_desc);
    padded_len=(len+block_size) & (~(block_size-1)); // Assumes block size is a power of 2.

    MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
    MAKE_GENERIC_MODE_CONTEXT(decrypt_ctx, &decrypt_desc);
    ok_or_fail((cc_symmetric_setup(&encrypt_desc, key->bytes, key->len, init_iv->bytes, encrypt_ctx) == 0), "Encrypted cipher-mode is initted");
    ok_or_fail((cc_symmetric_setup(&decrypt_desc, key->bytes, key->len, init_iv->bytes, decrypt_ctx) == 0), "Decrypted cipher-mode is initted");

    // Temporary buffers
    ciphertext  = mallocByteBuffer(padded_len);
    padded_message = mallocByteBuffer(padded_len);

    //----------------------------------
    // 1. Test padding encryption
    //----------------------------------

    // a. Encrypt using padding function
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) encrypt_ctx,padding_mode, init_iv->bytes, message->bytes, ciphertext->bytes, len);
    ok_or_fail(result_len >= len, "Encryption with padding failed");

    // b. Decrypt raw data
    cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx, init_iv->bytes, ciphertext->bytes, padded_message->bytes, result_len);

    // c. Compare last block with expected value
    ok_memcmp_or_fail(&padded_message->bytes[result_len-expected_padding->len], expected_padding->bytes, expected_padding->len, "Padding as expected");

    //----------------------------------
    // 2. Test padding decryption
    //----------------------------------

    // a. Construct the good padded zero message
    memcpy(padded_message->bytes,message->bytes, len);
    memcpy(&padded_message->bytes[len],expected_padding->bytes,expected_padding->len);

    // b. Encrypt with proper padding
    cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, init_iv->bytes, padded_message->bytes, ciphertext->bytes, len+expected_padding->len);
    memset(padded_message->bytes,0xff,padded_len); // Clean buffer to catch mismatches below

    // b. Decrypt with padding decrypt function
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) decrypt_ctx,padding_mode, init_iv->bytes, ciphertext->bytes, padded_message->bytes,len+expected_padding->len);
    ok_or_fail(result_len <= len+expected_padding->len, "Decryption with padding failed");

    // c. Compare that the message is all there.
    ok_memcmp_or_fail(padded_message->bytes,
                      message->bytes, len, "Decrypted handcrafted padding");

    ok_or_fail(len == result_len, "Decrypted length from handcrafted padding");

    free(ciphertext);
    free(padded_message);
    free(key);
    free(init_iv);
    free(message);
    free(expected_padding);
    return 1;
}

// Compare the ciphertext with what is expected
static int
ccsymmetric_pad_ciphertext_tests(duplex_cryptor cryptor, const ccpad_test_vector_t *test) {
    // Retrieve test case info
    byteBuffer key =                    hexStringToBytes(test->keyStr);
    byteBuffer init_iv =                hexStringToBytes(test->init_ivStr);
    byteBuffer plaintext =              hexStringToBytes(test->ptStr);
    byteBuffer expected_ciphertext =    hexStringToBytes(test->outputStr);
    ccpad_select padding_mode=test->padding_mode;
    size_t len = plaintext->len;
    size_t result_len;

    byteBuffer computed_ciphertext,recomputed_plaintext;

    // Set cipher
    cc_ciphermode_descriptor_s encrypt_desc;
    cc_ciphermode_descriptor_s decrypt_desc;

    encrypt_desc.cipher = cryptor->cipher;
    encrypt_desc.mode = cryptor->mode;
    encrypt_desc.direction = cc_Encrypt;
    encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;

    decrypt_desc.cipher = cryptor->cipher;
    decrypt_desc.mode = cryptor->mode;
    decrypt_desc.direction = cc_Decrypt;
    decrypt_desc.ciphermode = cryptor->decrypt_ciphermode;

    MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
    MAKE_GENERIC_MODE_CONTEXT(decrypt_ctx, &decrypt_desc);
    ok_or_fail((cc_symmetric_setup(&encrypt_desc, key->bytes, key->len, init_iv->bytes, encrypt_ctx) == 0), "Encrypted cipher-mode is initted");
    ok_or_fail((cc_symmetric_setup(&decrypt_desc, key->bytes, key->len, init_iv->bytes, decrypt_ctx) == 0), "Decrypted cipher-mode is initted");

    // Temporary buffers
    computed_ciphertext  = mallocByteBuffer(expected_ciphertext->len);
    recomputed_plaintext = mallocByteBuffer(expected_ciphertext->len );

    //----------------------------------
    // Round Trip, out of place
    //----------------------------------

    // a. Encrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) encrypt_ctx,padding_mode, init_iv->bytes, plaintext->bytes, computed_ciphertext->bytes, len);
    ok_or_fail(result_len == expected_ciphertext->len, "Ciphertext length mismatch");

    ok_memcmp_or_fail(computed_ciphertext->bytes,
                      expected_ciphertext->bytes, expected_ciphertext->len, "Wrong ciphertext");

    // b. Decrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) decrypt_ctx,padding_mode, init_iv->bytes, expected_ciphertext->bytes, recomputed_plaintext->bytes, expected_ciphertext->len);
    ok_or_fail(result_len == plaintext->len, "Recovered plaintext length mismatch");

    ok_memcmp_or_fail(recomputed_plaintext->bytes,
                      plaintext->bytes, plaintext->len, "Wrong decrypted message");

    //----------------------------------
    // Round Trip, in place
    //----------------------------------
    memcpy(computed_ciphertext->bytes,plaintext->bytes,len);

    // a. Encrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) encrypt_ctx,padding_mode, init_iv->bytes, computed_ciphertext->bytes, computed_ciphertext->bytes, len);
    ok_or_fail(result_len == expected_ciphertext->len, "Ciphertext computed in place length mismatch");

    ok_memcmp_or_fail(computed_ciphertext->bytes,
                      expected_ciphertext->bytes, expected_ciphertext->len, "Wrong ciphertext in place");

    // b. Decrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) decrypt_ctx,padding_mode, init_iv->bytes, computed_ciphertext->bytes, computed_ciphertext->bytes, result_len);
    ok_or_fail(result_len == plaintext->len, "Recovered plaintext length mismatch");

    // c. Compare with original messsage
    ok_memcmp_or_fail(computed_ciphertext->bytes,
                      plaintext->bytes, len, "Recovered in place plaintext length mismatch");

    //----------------------------------
    free(recomputed_plaintext);
    free(plaintext);
    free(computed_ciphertext);
    free(expected_ciphertext);
    free(key);
    free(init_iv);

    return 1;
}

// Roundtrip: does the encrypt/decrypt recover the plaintext.
static int
ccsymmetric_pad_roundtrip_tests(duplex_cryptor cryptor, ccpad_select padding_mode, size_t message_size) {
    // Retrieve test case info
    byteBuffer key;
    byteBuffer init_iv;
    byteBuffer message;
    size_t len = message_size;
    size_t result_len;
    size_t block_size=0;
    size_t padded_len=0;

    int status;

    byteBuffer ciphertext,padded_message;

    // Set cipher
    cc_ciphermode_descriptor_s encrypt_desc;
    cc_ciphermode_descriptor_s decrypt_desc;

    encrypt_desc.cipher = cryptor->cipher;
    encrypt_desc.mode = cryptor->mode;
    encrypt_desc.direction = cc_Encrypt;
    encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;

    decrypt_desc.cipher = cryptor->cipher;
    decrypt_desc.mode = cryptor->mode;
    decrypt_desc.direction = cc_Decrypt;
    decrypt_desc.ciphermode = cryptor->decrypt_ciphermode;

    block_size=cc_symmetric_bloc_size(&encrypt_desc);
    padded_len=(len+block_size) & (~(block_size-1)); // Assumes block size is a power of 2.

    key = mallocByteBuffer(block_size);
    status = ccrng_generate(global_test_rng, key->len, key->bytes);
    cc_assert(status == 0);
    (void)status;

    init_iv = mallocByteBuffer(block_size);
    status = ccrng_generate(global_test_rng, init_iv->len, init_iv->bytes);
    cc_assert(status == 0);
    (void)status;
    
    message = mallocByteBuffer(len);
    status = ccrng_generate(global_test_rng, message->len, message->bytes);
    cc_assert(status == 0);
    (void)status;
    
    MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
    MAKE_GENERIC_MODE_CONTEXT(decrypt_ctx, &decrypt_desc);
    ok_or_fail((cc_symmetric_setup(&encrypt_desc, key->bytes, key->len, init_iv->bytes, encrypt_ctx) == 0), "Encrypted cipher-mode is initted");
    ok_or_fail((cc_symmetric_setup(&decrypt_desc, key->bytes, key->len, init_iv->bytes, decrypt_ctx) == 0), "Decrypted cipher-mode is initted");

    // Temporary buffers
    ciphertext  = mallocByteBuffer(padded_len);
    padded_message = mallocByteBuffer(padded_len);

    //----------------------------------
    // Round Trip, out of place
    //----------------------------------

    // a. Encrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) encrypt_ctx,padding_mode, init_iv->bytes, message->bytes, ciphertext->bytes, len);
    ok_or_fail(result_len >= len, "Encryption with padding failed");

    // b. Decrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) decrypt_ctx,padding_mode, init_iv->bytes, ciphertext->bytes, padded_message->bytes, result_len);
    ok_or_fail(result_len <= len, "Decryption with padding failed");

    // c. Compare with original messsage
    ok_memcmp_or_fail(padded_message->bytes,
                      message->bytes, len, "Wrap/Unwrapped decrypted message");

    ok_or_fail(message->len == result_len, "Wrap/Unwrapped decrypted length");

    //----------------------------------
    // Round Trip, in place
    //----------------------------------

    // a. Encrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) encrypt_ctx,padding_mode, init_iv->bytes, padded_message->bytes, padded_message->bytes, len);
    ok_or_fail(result_len >= len, "Encryption in place failed");

    // Makes sure the plaintext has been encrypted
    ok_or_fail(memcmp(padded_message->bytes,message->bytes,len)!=0, "Encryption in place did nothing?");

    // b. Decrypt with padding
    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) decrypt_ctx,padding_mode, init_iv->bytes, padded_message->bytes, padded_message->bytes, result_len);
    ok_or_fail(result_len <= len, "Decryption in place failed");

    // c. Compare with original messsage
    ok_memcmp_or_fail(padded_message->bytes,
                      message->bytes, len, "Wrap/Unwrapped in place decrypted message");

    ok_or_fail(message->len == result_len, "Wrap/Unwrapped in place decrypted length");

    //----------------------------------
    free(ciphertext);
    free(padded_message);
    free(key);
    free(init_iv);
    free(message);
    return 1;
}



CC_UNUSED static int
ccsymmetric_crypt_pad_timing_tests(duplex_cryptor cryptor, ccpad_select padding_mode, const ccpad_test_vector_t *test) {
    // Retrieve test case info
    // Message is ignore, random messages are generated
    byteBuffer key =        hexStringToBytes(test->keyStr);
    byteBuffer init_iv =    hexStringToBytes(test->init_ivStr);
    byteBuffer plaintext,output,ciphertext_valid,ciphertext_random;
    size_t len = 0;
    size_t max_len = 0;
    size_t result_len = 0;
    size_t block_size=0;
    size_t padded_len=0;
    int failure_cnt=0;
    int early_abort=1;
    uint32_t j,sample_counter;
    bool retry=true;

    // Random for messages
    struct ccrng_state *rng = global_test_rng;

    // Set cipher
    cc_ciphermode_descriptor_s encrypt_desc;
    cc_ciphermode_descriptor_s decrypt_desc;

    encrypt_desc.cipher = cryptor->cipher;
    encrypt_desc.mode = cryptor->mode;
    encrypt_desc.direction = cc_Encrypt;
    encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;

    decrypt_desc.cipher = cryptor->cipher;
    decrypt_desc.mode = cryptor->mode;
    decrypt_desc.direction = cc_Decrypt;
    decrypt_desc.ciphermode = cryptor->decrypt_ciphermode;

    MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
    MAKE_GENERIC_MODE_CONTEXT(decrypt_ctx, &decrypt_desc);
    ok_or_fail((cc_symmetric_setup(&encrypt_desc, key->bytes, key->len, init_iv->bytes, encrypt_ctx) == 0), "Encrypted cipher-mode is initted");
    ok_or_fail((cc_symmetric_setup(&decrypt_desc, key->bytes, key->len, init_iv->bytes, decrypt_ctx) == 0), "Decrypted cipher-mode is initted");

    // Work on messages of size 0 < len <= blocksize
    block_size=cc_symmetric_bloc_size(&encrypt_desc);
    len=block_size;
    max_len=(len+block_size) & (~(block_size-1)); // Assumes block size is a power of 2.

    // Temporary buffers
    plaintext  = mallocByteBuffer(max_len);
    ciphertext_valid  = mallocByteBuffer(max_len);
    ciphertext_random  = mallocByteBuffer(max_len);
    output  = mallocByteBuffer(max_len);

    for (len=0; len<=block_size;len++)
    {
        j=0;
        while(retry)
        {
            sample_counter=0; // Index of current sample
            measurement_t timing_sample[2*CCPAD_TIMING_SAMPLES];

            for (size_t i=0;i<2*CCPAD_TIMING_SAMPLES+(CCPAD_WARMUP/CCPAD_TIMING_REPEAT);i++)
            {
                padded_len=(len+block_size) & (~(block_size-1)); // Assumes block size is a power of 2.
                volatile size_t decode_result;
                if ((len==0) || ((i&1) == 0))
                {
                    // -------------------------
                    //      Random
                    // -------------------------
                    ccrng_generate(rng,padded_len,plaintext->bytes); // Full length
                    cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, init_iv->bytes, plaintext->bytes, ciphertext_valid->bytes, padded_len);
                    result_len=padded_len;
                }
                else
                {
                    // -------------------------
                    //      Correct padding
                    // -------------------------
                    // Create message with good padding
                    ccrng_generate(rng,len,plaintext->bytes);         // Actual length
                    result_len=cc_symmetric_crypt_pad((cc_symmetric_context_p) encrypt_ctx,padding_mode, init_iv->bytes, plaintext->bytes, ciphertext_valid->bytes, len);
                    cc_assert(result_len == padded_len);
                }

                // Decrypt with padding decrypt function
                cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx,init_iv->bytes, ciphertext_valid->bytes, output->bytes,result_len);

                TIMING_WITH_QUANTILE(timing_sample[sample_counter].timing,
                                     CCPAD_TIMING_REPEAT,
                                     CCPAD_PERCENTILE,
                                     decode_result=ccpad_pkcs7_decode(block_size,output->bytes+result_len-block_size),errOut);

                timing_sample[sample_counter].group=sample_counter&1;
#if CCPAD_WARMUP
                if (i>=(CCPAD_WARMUP/CCPAD_TIMING_REPEAT))
#endif
                {
                    sample_counter++;
                }
            }
#if TARGET_OS_OSX
            if (verbose>1) {
                char file_name[64];
                snprintf(file_name,sizeof(file_name),"corecrypto_test_timings_%.2zu.csv",len);
                export_measurement_to_file(file_name,timing_sample,sample_counter);
            }
#endif
            // Process results
#if T_TEST
            // T test
            int status=T_test_isRejected(timing_sample,sample_counter);
#else
            // Wilcoxon Rank-Sum Test
            int status=WilcoxonRankSumTest(timing_sample,sample_counter);
#endif
            if (status!=0)
            {
                j++; // retry counter
                if (j>=CCPAD_TIMING_RETRIES)
                {
                    // If it fails for len==0 it's a test issue since it is all random
                    if (len==0) {
                        diag("Constant timing FAILED for all random, this is a test issue",len,j);
                    }
                    else
                    {
                        diag("Constant timing FAILED for len %d after %d attempts",len,j);
                        //ok_or_fail((status==0),"Decrypt+padding constant timing");
                        failure_cnt++;
                    }
                    break;
                }
            }
            else
            {
                if ((verbose>1) && (j>0)) diag("Constant timing ok for len %d after %d attempts (of %d)",len,j+1,CCPAD_TIMING_RETRIES);
                break;
            }
        } // retry
    }
    early_abort=0;
errOut:
    free(plaintext);
    free(ciphertext_valid);
    free(ciphertext_random);
    free(output);
    free(key);
    free(init_iv);
    if (failure_cnt || early_abort)
    {
        return 0;
    }
    return 1;
}

// For PKCS7 since it is special with regards to modes
static int test_pad_plaintext_pkcs7(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode,cc_cipher_select cipher,cc_mode_select mode) {
    duplex_cryptor_s cryptor;
    cryptor.cipher = cipher;
    cryptor.mode = mode;
    cryptor.encrypt_ciphermode = encrypt_ciphermode;
    cryptor.decrypt_ciphermode = decrypt_ciphermode;
    ccpad_select padding_mode=ccpad_pkcs7;

    const ccpad_test_vector_t *run_vector=NULL;

    if (cc_cipherAES==cryptor.cipher)
    {
        run_vector=aes_plaintext_vectors;
    }
    else if (cc_cipherDES==cryptor.cipher)
    {
        run_vector=des_plaintext_vectors;
    } else {
        fail("Test not implemented");
        return 0;
    }

    // Detect timing attacks on PKCS7 padding
    if (cc_ModeECB!=cryptor.mode && padding_mode==ccpad_pkcs7 && !cc_is_vmm_present())
    {   // Timing attack not relevant on ECB
        for (int i=0;i<CMP_TIMING_TEST_ITERATION;i++)
            ok_or_warning(ccsymmetric_crypt_pad_timing_tests(&cryptor,padding_mode,&run_vector[0]), "Constant Time test");
    }

    // Plaintext tests
    for(int i=0; run_vector[i].keyStr != NULL; i++) {
        const ccpad_test_vector_t *test = &run_vector[i];
        ok_or_fail(ccsymmetric_pad_plaintext_tests(&cryptor,padding_mode,test), "Test Vector Passed");
    }
    return 1;
}

// Generic test framework that checks input/output
static int test_pad_roundtrip(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode,cc_cipher_select cipher,cc_mode_select mode) {
    duplex_cryptor_s cryptor;
    cryptor.cipher = cipher;
    cryptor.mode = mode;
    cryptor.encrypt_ciphermode = encrypt_ciphermode;
    cryptor.decrypt_ciphermode = decrypt_ciphermode;

    ok_or_fail(cc_cipherAES==cryptor.cipher, "Test not implemented");

    for(ccpad_select padding_mode=0; padding_mode<ccpad_cnt; padding_mode++) {
        if  ((cc_ModeCBC==cryptor.mode && cbc_pad_crypt_funcs[padding_mode][cc_Encrypt]!=NULL)
        ||   (cc_ModeECB==cryptor.mode && ecb_pad_crypt_funcs[padding_mode][cc_Encrypt]!=NULL))
        {
            // AES CBC
            ok_or_fail(ccsymmetric_pad_roundtrip_tests(&cryptor,padding_mode,47), "Random roundtrip 47 bytes Passed");
            ok_or_fail(ccsymmetric_pad_roundtrip_tests(&cryptor,padding_mode,48), "Random roundtrip 48 bytes Passed");
            ok_or_fail(ccsymmetric_pad_roundtrip_tests(&cryptor,padding_mode,40), "Random roundtrip 40 bytes Passed");
        }
    }
    return 1;
}

// Generic test framework that checks input/output
static int test_pad_ciphertext(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode,cc_cipher_select cipher,cc_mode_select mode) {
    duplex_cryptor_s cryptor;
    cryptor.cipher = cipher;
    cryptor.mode = mode;
    cryptor.encrypt_ciphermode = encrypt_ciphermode;
    cryptor.decrypt_ciphermode = decrypt_ciphermode;

    const ccpad_test_vector_t *run_vector=NULL;

    if (cc_cipherAES==cryptor.cipher && cc_ModeCBC==cryptor.mode)
    {
        run_vector=aes_cbc_ciphertext_vectors;
    }
    else
    {
        fail("Test not implemented");
        return 0;
    }

    // Plaintext tests
    for(int i=0; run_vector[i].keyStr != NULL; i++) {
        ok_or_fail(ccsymmetric_pad_ciphertext_tests(&cryptor,&run_vector[i]), "Encryption/Decryption KAT passed");
    }
    return 1;
}

// Main of the test
int ccpad_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
	plan_tests(kTestTestCount);

    if (verbose) diag("Generic AES KAT padding tests");
    ok(test_pad_ciphertext((ciphermode_t) ccaes_cbc_encrypt_mode(), (ciphermode_t) ccaes_cbc_decrypt_mode(),cc_cipherAES,cc_ModeCBC) == 1, "Generic KAT padding tests");

    if (verbose) diag("Generic AES roundtrip padding tests");
    ok(test_pad_roundtrip((ciphermode_t) ccaes_ecb_encrypt_mode(), (ciphermode_t) ccaes_ecb_decrypt_mode(),cc_cipherAES,cc_ModeECB) == 1, "Generic AES ECB roundtrip padding tests");
    ok(test_pad_roundtrip((ciphermode_t) ccaes_cbc_encrypt_mode(), (ciphermode_t) ccaes_cbc_decrypt_mode(),cc_cipherAES,cc_ModeCBC) == 1, "Generic AES CBC roundtrip padding tests");

    if (verbose) diag("PKCS7 Padding - Default AES-ECB");
    ok(test_pad_plaintext_pkcs7((ciphermode_t) ccaes_ecb_encrypt_mode(), (ciphermode_t) ccaes_ecb_decrypt_mode(),cc_cipherAES,cc_ModeECB) == 1, "PKCS7 Padding - Default AES-ECB");
    if (verbose) diag("PKCS7 Padding - Default AES-CBC");
    ok(test_pad_plaintext_pkcs7((ciphermode_t) ccaes_cbc_encrypt_mode(), (ciphermode_t) ccaes_cbc_decrypt_mode(),cc_cipherAES,cc_ModeCBC) == 1, "PKCS7 Padding - Default AES-CBC");
    if (verbose) diag("PKCS7 Padding - Default DES-ECB");
    ok(test_pad_plaintext_pkcs7((ciphermode_t) ccdes_ecb_encrypt_mode(), (ciphermode_t) ccdes_ecb_decrypt_mode(),cc_cipherDES,cc_ModeECB) == 1, "PKCS7 Padding - Default DES-ECB");
    if (verbose) diag("PKCS7 Padding - Default DES-CBC");
    ok(test_pad_plaintext_pkcs7((ciphermode_t) ccdes_cbc_encrypt_mode(), (ciphermode_t) ccdes_cbc_decrypt_mode(),cc_cipherDES,cc_ModeCBC) == 1, "PKCS7 Padding - Default DES-CBC");

    return 0;
}
#endif

