/* Copyright (c) (2012-2022) Apple Inc. All rights reserved.
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

#if (CCEC == 0)
entryPoint(ccec_tests, "ccec")
#else

#include <inttypes.h>
#include "cc_runtime_config.h"
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng_pbkdf2_prng.h>
#include <corecrypto/ccrng_sequence.h>
#include "crypto_test_ec.h"
#include <corecrypto/ccder.h>
#include <corecrypto/ccn.h>

static int verbose = 1;

#define MAXKEYSPACE 8192

struct ccec_pbkdf2_keygen_vector {
    ccec_const_cp_t (*cp)(void);
    char *password;
    size_t iterations;
    char *str_salt;
    char *str_legacy_x963_full_key;
    char *str_fips_x963_full_key;
    char *str_compact_x963_full_key;
};

const struct ccec_pbkdf2_keygen_vector ccec_pbkdf2_keygen_vectors[] = {
    {
        .cp = &ccec_cp_192,
        .password = "foofoofoo",
        .iterations = 1024,
        .str_salt = "4141414141414141",
        .str_legacy_x963_full_key = "04b2c06c91874594ac7a9a11e015021dbfce8be82937c44ee8f49736d538ed23af7d57b64ef11aed308b405deb6a"
                                    "6712f54cd97af15879dc056f76061796f8f71efafdf368622fddab",
        .str_fips_x963_full_key = "044ea8feee26902c7df26d4fec83592c6a1fba2c2ee5463ee0467ff1c12001aa7f00ffff2e9eacad923336ded5d9b1"
                                  "fdd3d020c30e2d7767d712049879327387988f2c5ee37b1cd2ba",
        .str_compact_x963_full_key = "044ea8feee26902c7df26d4fec83592c6a1fba2c2ee5463ee0467ff1c12001aa7f00ffff2e9eacad923336ded5d"
                                     "9b1fdd3d020c30e2d7767d712049879327387988f2c5ee37b1cd2ba",
    },
    {
        .cp = &ccec_cp_224,
        .password = "foofoofoo",
        .iterations = 1024,
        .str_salt = "4141414141414141",
        .str_legacy_x963_full_key = "048ff2fc917799d97633df4a431cb1a2b02418a2a40c3b8153533a48d6a9f93112ff6bce3c3c9852e32a62ea7b98"
                                    "9801f1ced7d6212b9e67ae7b1cd2b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
#if CCN_UNIT_SIZE == 8
        .str_fips_x963_full_key = "04c3312a8817ea34d7eb72a5af0bbd9804558904e7ea070835545f60d875e09171c9d992c3440d14d2f3587bd33594"
                                  "83968ec6683d0b38a0bc00e5745c885181d60a580111d020c30e2d7767d71204987932738799",
#elif CCN_UNIT_SIZE == 4
        .str_fips_x963_full_key = "043b468f17be760e163c76eaf61468a8fede4e57032b5747301241be09aa70886d8d9e79fe2ee49c49c98fc62dae64"
                                  "ceec37cf30647acfd9b9885181d60a580111d020c30e2d7767d712049879327387988f2c5ee4",
#endif
    },
    {
        .cp = &ccec_cp_256,
        .password = "foofoofoo",
        .iterations = 1024,
        .str_salt = "4141414141414141",
        .str_legacy_x963_full_key =
            "044c20da234c2cd2d674c42cd322de2f6c4b51ad3f9b3915342dba188a85fe48b9e4103add4611308a3b951e894dbaddb8593a520c89f39cc0a5"
            "b546518ebaf38f8f2c5ee37b1cd2b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
        .str_fips_x963_full_key =
            "049767be9128a7f6d0ac245931cf17b84846c4120bf95e5cc276a8f43d670f9d1a8d74ad12d38c776eb0baaab07301a5636b6de55aaae5c996b0"
            "a5cea771f632d9f383216100e5745c885181d60a580111d020c30e2d7767d71204987932738799",
        .str_compact_x963_full_key =
            "049767be9128a7f6d0ac245931cf17b84846c4120bf95e5cc276a8f43d670f9d1a728b52ec2c7388924f45554f8cfe5a9c94921aa6551a36694f"
            "5a31588e09cd260c7cde9dff1a8ba477ae7e29f5a7feedecc6379f79a036ade1b53249c9ef9db8",
    },
    {
        .cp = &ccec_cp_384,
        .password = "foofoofoo",
        .iterations = 1024,
        .str_salt = "4141414141414141",
        .str_legacy_x963_full_key =
            "04954955319fa1e463a7bef143e8231f347ef6fa36c25e935d00008cb7837f427207a5a93eb9dcd04a9c8b7d6501050f0982d185e05e5a632869"
            "608ad7621b3a40558cd8608c1b5dd2f1705d286ca2e5f87d837cb9727df8949ed4b4fd4b6c98d1d020c30e2d7767d712049879327387988f2c5e"
            "e37b1cd2b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
        .str_fips_x963_full_key =
            "043546cb3667a75a375f7e1cddc5f133389d0fd4dcc759b8e74d80df4c4b94ece497bcd544d782f1ad84336c9decd525e4bc9f24c13826a467ba"
            "e79e404befa3bc76701b62f65138736fb025b7f335add145d0cffbe534bca6c3afc1ed99b12062835a04461534742d76701b8fd0959f90913923"
            "e79bbec5a393ddb9d7d69aabebf383216100e5745c885181d60a580112",
        .str_compact_x963_full_key =
            "043546cb3667a75a375f7e1cddc5f133389d0fd4dcc759b8e74d80df4c4b94ece497bcd544d782f1ad84336c9decd525e44360db3ec7d95b9845"
            "1861bfb4105c43898fe49d09aec78c904fda480cca522dba2f30031acb43593c503e13664edf9d7ca5fbb9eacb8bd2898fe4702f6a606f6ec6dc"
            "1864413a5c338593aa1d9c81f36496ec5147cb331e649a9794c26d2861",
    },
    {
        .cp = &ccec_cp_521,
        .password = "foofoofoo",
        .iterations = 1024,
        .str_salt = "4141414141414141",
        .str_legacy_x963_full_key =
            "0400c968e680dc020dea239817ba7ac407b14fc92059f3757f63d037869cd262fadbcae8ca005cc9a86f3dbcd15328084667cff94e1a4fd3b8d1"
            "d529a29955c92a620f012c5aa28b4aab652b2654d5e19da7f90ce4f6be300e09072d0cc676814043aeb564c38f7f74db3fb27cfe7bd19322a2f7"
            "727f26989a49c97cd135cfe986472e024a01ebf383216100e5745c885181d60a580111d020c30e2d7767d712049879327387988f2c5ee37b1cd2"
            "b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
#if CCN_UNIT_SIZE == 8
        .str_fips_x963_full_key =
            "040122a5b2a09234374c143614d4ee897c6aba09a674cf748de994ca2c2e2debc4b198b2259b780ccf71204492b38595b9efc6a0e8f3a5f83ebb"
            "6a28b20f79a4d223a8014a9575f2cde7bae68f502ccfe39a04db658eff2714b3e6c19b3d634dfbd6c36c6a6f201e5f483f3e942310bedebf1e50"
            "ad7600c32d9f795496d12bee9f6036236001129e9e8ecba2f709fb2a1a8969ec192a0e93a43b6963d38ee902929da64df51c7317ad70ff94e3e6"
            "f1835a04461534742d76701b8fd0959f90913923e79bbec5a4",
#elif CCN_UNIT_SIZE == 4
        .str_fips_x963_full_key =
            "0401edd47f457e722edd62a432f2eb90ccc2dfa8c018c3ca2c3cd2afeadceec71801fd98ee99e555ffb67229d4d0f0e0d7c8cbb7a754e05191e6"
            "1d4aa09e356c08e9f70186b37bcb63bb89a3d543d6049077c22ffc4a39f6935c422e20ba15946ba77b9918fdad631677c6df396202ac785bfa04"
            "9415da185908231af7ec6810500fb715c300cba2f709fb2a1a8969ec192a0e93a43b6963d38ee902929da64df51c7317ad70ff94e3e6f1835a04"
            "461534742d76701b8fd0959f90913923e79bbec5a393ddb9d8",
#endif
#if CCN_UNIT_SIZE == 8
        .str_compact_x963_full_key =
            "040122a5b2a09234374c143614d4ee897c6aba09a674cf748de994ca2c2e2debc4b198b2259b780ccf71204492b38595b9efc6a0e8f3a5f83ebb"
            "6a28b20f79a4d223a800b56a8a0d3218451970afd3301c65fb249a7100d8eb4c193e64c29cb204293c939590dfe1a0b7c0c16bdcef412140e1af"
            "5289ff3cd26086ab692ed411609fc9dc9f00ed616171345d08f604d5e5769613e6d5f16c5bc4969c2c7116fd6d6259b20ae38739d916842a4baf"
            "79fc71fd02e1d531a2c545ae28b906a81e2a369336f5799e65",
#elif CCN_UNIT_SIZE == 4
        .str_compact_x963_full_key =
            "0401edd47f457e722edd62a432f2eb90ccc2dfa8c018c3ca2c3cd2afeadceec71801fd98ee99e555ffb67229d4d0f0e0d7c8cbb7a754e05191e6"
            "1d4aa09e356c08e9f700794c84349c44765c2abc29fb6f883dd003b5c6096ca3bdd1df45ea6b94588466e702529ce9883920c69dfd5387a405fb"
            "6bea25e7a6f7dce5081397efaff048ea3c01345d08f604d5e5769613e6d5f16c5bc4969c2c7116fd6d6259b20ae38ce8528efabca2a0923bd592"
            "256a978d1b80998a406b202a27f86323c71fb0f17afd5aaa31",
#endif
    },
};

static int ccec_keys_are_equal(ccec_full_ctx_t full_key, byteBuffer x963_ec_full_key, size_t test_nb)
{
    int status = 1;
    // Export key
    size_t bufsiz = ccec_x963_export_size(1, ccec_ctx_pub(full_key));
    uint8_t buf[bufsiz];
    status &= is(ccec_x963_export(1, buf, full_key), CCERR_OK, "Key export failed");

    // Compare with expect value
    status &= is(x963_ec_full_key->len, bufsiz, "Key size mismatch for test");
    status &=
        ok_memcmp(buf, x963_ec_full_key->bytes, bufsiz, "%d bit EC Key mismatch for test %d", ccec_ctx_bitlen(full_key), test_nb);
    return status;
}

static int ECStaticGenTest(void)
{
    for (size_t i = 0; i < CC_ARRAY_LEN(ccec_pbkdf2_keygen_vectors); i++) {
        const struct ccec_pbkdf2_keygen_vector *test_vector = &ccec_pbkdf2_keygen_vectors[i];
        ccec_const_cp_t cp = test_vector->cp();
        struct ccrng_pbkdf2_prng_state pbkdf2_prng;
        ccec_full_ctx_decl_cp(cp, full_key);

        size_t iterations = 1024;

        struct ccrng_state *rng2 = (struct ccrng_state *)&pbkdf2_prng;
        byteBuffer x963_ec_full_key_legacy = hexStringToBytes(test_vector->str_legacy_x963_full_key);
        byteBuffer x963_ec_full_key_fips = hexStringToBytes(test_vector->str_fips_x963_full_key);
        byteBuffer x963_ec_full_key_compact = hexStringToBytes(test_vector->str_compact_x963_full_key);
        byteBuffer x963_ec_full_key_default = hexStringToBytes(test_vector->str_fips_x963_full_key); // Default is FIPS
        byteBuffer salt = hexStringToBytes(test_vector->str_salt);

        // Legacy
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng,
                                          2 * ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password),
                                          test_vector->password,
                                          salt->len,
                                          salt->bytes,
                                          iterations) == 0,
                   "pbkdf2 init");
        if (x963_ec_full_key_legacy->len && (is(ccec_generate_key_legacy(cp, rng2, full_key), 0, "Generate Legacy"))) {
            ok(ccec_keys_are_equal(full_key, x963_ec_full_key_legacy, i), "Check legacy key");
        }

        // FIPS
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng,
                                          8 * ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password),
                                          test_vector->password,
                                          salt->len,
                                          salt->bytes,
                                          iterations) == 0,
                   "pbkdf2 init");
        if (x963_ec_full_key_fips->len && (is(ccec_generate_key_fips(cp, rng2, full_key), 0, "Generate FIPS"))) {
            ok(ccec_keys_are_equal(full_key, x963_ec_full_key_fips, i), "Check FIPS key");
        }

        // Compact
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng,
                                          8 * ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password),
                                          test_vector->password,
                                          salt->len,
                                          salt->bytes,
                                          iterations) == 0,
                   "pbkdf2 init");
        if (x963_ec_full_key_compact->len && (is(ccec_compact_generate_key(cp, rng2, full_key), 0, "Generate compact"))) {
            ok(ccec_keys_are_equal(full_key, x963_ec_full_key_compact, i), "Check compact key");
        }

        // Default
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng,
                                          8 * ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password),
                                          test_vector->password,
                                          salt->len,
                                          salt->bytes,
                                          iterations) == 0,
                   "pbkdf2 init");
        if (x963_ec_full_key_default->len && (is(ccec_generate_key(cp, rng2, full_key), 0, "Generate default"))) {
            ok(ccec_keys_are_equal(full_key, x963_ec_full_key_default, i), "Check default key");
        }

        is(ccecdh_pairwise_consistency_check(full_key, NULL, global_test_rng), CCERR_OK, "Key is good");

        free(x963_ec_full_key_legacy);
        free(x963_ec_full_key_fips);
        free(x963_ec_full_key_compact);
        free(x963_ec_full_key_default);
        free(salt);
    }
    return 1;
}

static void fill(int *guard)
{
    guard[0] = -1;
    guard[1] = -1;
    guard[2] = -1;
    guard[3] = -1;
}

static int chkit(int *guard)
{
    return guard[0] == -1 && guard[1] == -1 && guard[2] == -1 && guard[3] == -1;
}

static int ccec_diversify_pub_twin_tests(void)
{
    ccec_const_cp_t cp = ccec_cp_256();

    ccec_pub_ctx_decl_cp(cp, pub_in);
    ccec_pub_ctx_decl_cp(cp, pub_out);
    ccec_ctx_init(cp, pub_in);
    ccec_ctx_init(cp, pub_out);

    ccec_full_ctx_decl_cp(cp, full_in);
    ccec_full_ctx_decl_cp(cp, full_out);
    ccec_ctx_init(cp, full_in);
    ccec_ctx_init(cp, full_out);

    // Test vectors created/checked with SageMath.
    // clang-format off
    const cc_unit d[CCN256_N] = {
        CCN256_C(00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f)
    };
    const cc_unit x[CCN256_N] = {
        CCN256_C(b9,c6,a6,d7,9a,5f,60,ce,9c,3a,0a,f3,8c,80,74,dd,4f,57,8e,ca,ce,6d,d7,c5,ff,92,13,b8,35,34,6a,73)
    };
    const cc_unit y[CCN256_N] = {
        CCN256_C(a3,a5,17,b2,11,de,0b,75,65,a4,cd,ac,c2,b1,65,1a,b9,9f,bc,e4,8b,82,4c,71,5b,9d,34,76,58,d9,9b,4d)
    };
    // clang-format on

    // Some entropy with different values for each scalar.
    const uint8_t entropy[80] = {
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
        0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
        0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
        0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1
    };

    int rv = ccec_make_pub_from_priv(cp, global_test_rng, d, NULL, pub_in);
    is(rv, 0, "Make public key");

    cc_assert(sizeof(entropy) == 2 * ccec_diversify_min_entropy_len(cp));
    rv = ccec_diversify_pub_twin(cp, pub_in, sizeof(entropy), entropy, global_test_rng, pub_out);
    is(rv, 0, "ccec_diversify_pub_twin failed");

    ok_ccn_cmp(CCN256_N, ccec_ctx_x(pub_out), x, "Unexpected x-coordinate");
    ok_ccn_cmp(CCN256_N, ccec_ctx_y(pub_out), y, "Unexpected y-coordinate");

    // len(entropy) must be a multiple of two.
    rv = ccec_diversify_pub_twin(cp, pub_in, sizeof(entropy) - 1, entropy, global_test_rng, pub_out);
    is(rv, CCERR_PARAMETER, "ccec_diversify_pub_twin should fail");

    // len(entropy) must be >= 2 * ccec_diversify_min_entropy_len(cp).
    rv = ccec_diversify_pub_twin(cp, pub_in, sizeof(entropy) - 2, entropy, global_test_rng, pub_out);
    is(rv, CCERR_PARAMETER, "ccec_diversify_pub_twin should fail");

    // Test vectors created/checked with SageMath.
    // clang-format off
    const cc_unit x2[CCN256_N] = {
        CCN256_C(0d,0a,69,9e,d7,99,e1,25,96,ad,af,8d,04,79,28,36,02,af,ce,ad,cf,97,d1,3b,44,ec,15,a9,39,58,89,ff)
    };
    const cc_unit y2[CCN256_N] = {
        CCN256_C(b1,e1,96,9a,42,5d,6d,be,4f,ce,32,63,a3,67,e3,0f,a6,aa,96,2f,1d,c8,dd,97,e7,fd,43,c2,de,b0,b4,e8)
    };
    // clang-format on

    // More entropy with different values for each scalar.
    const uint8_t entropy_long[96] = { 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
                                       0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
                                       0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
                                       0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
                                       0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
                                       0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
                                       0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1 };

    rv = ccec_diversify_pub_twin(cp, pub_in, sizeof(entropy_long), entropy_long, global_test_rng, pub_out);
    is(rv, 0, "ccec_diversify_pub_twin failed");

    ok_ccn_cmp(CCN256_N, ccec_ctx_x(pub_out), x2, "Unexpected x-coordinate");
    ok_ccn_cmp(CCN256_N, ccec_ctx_y(pub_out), y2, "Unexpected y-coordinate");

    // Point to diversify must be on the curve.
    (void)ccn_add1(CCN256_N, ccec_ctx_x(pub_in), ccec_ctx_x(pub_in), 1);
    rv = ccec_diversify_pub_twin(cp, pub_in, sizeof(entropy), entropy, global_test_rng, pub_out);
    isnt(rv, 0, "ccec_diversify_pub_twin should fail");

    // Construct a private key.
    ccn_set(CCN256_N, ccec_ctx_k(full_in), d);
    ccn_seti(CCN256_N, ccec_ctx_z(full_in), 1);
    rv = ccec_make_pub_from_priv(cp, global_test_rng, d, NULL, ccec_ctx_pub(full_in));
    is(rv, 0, "Make private key");

    // Compute a delegate.
    rv = ccec_diversify_priv_twin(cp, ccec_ctx_k(full_in), sizeof(entropy), entropy, global_test_rng, full_out);
    is(rv, 0, "ccec_diversify_priv_twin failed");

    ok_ccn_cmp(CCN256_N, ccec_ctx_x(full_out), x, "Unexpected x-coordinate");
    ok_ccn_cmp(CCN256_N, ccec_ctx_y(full_out), y, "Unexpected y-coordinate");
    ok(ccec_pairwise_consistency_check(full_out, global_test_rng), "Invalid private key");

    // len(entropy) must be a multiple of two.
    rv = ccec_diversify_priv_twin(cp, ccec_ctx_k(full_in), sizeof(entropy) - 1, entropy, global_test_rng, full_out);
    is(rv, CCERR_PARAMETER, "ccec_diversify_priv_twin should fail");

    // len(entropy) must be >= 2 * ccec_diversify_min_entropy_len(cp).
    rv = ccec_diversify_priv_twin(cp, ccec_ctx_k(full_in), sizeof(entropy) - 2, entropy, global_test_rng, full_out);
    is(rv, CCERR_PARAMETER, "ccec_diversify_priv_twin should fail");

    return 0;
}

static void ccec_cczp_mod_prime_tests(ccec_const_cp_t cp)
{
    cczp_const_t zp = (cczp_const_t)cp;
    cc_size n = cczp_n(zp);
    cc_unit a[n], b[n], r[n], s[n];

    cc_unit t[n * 2];
    ccn_clear(n * 2, t);

    // A few random tests.
    for (size_t i = 0; i < 1000; i++) {
        CC_DECL_WORKSPACE_TEST(ws);
        ccn_clear(n, a);
        ccn_clear(n, b);
        ccn_clear(n, r);
        ccn_clear(n, s);

        ccn_random_bits(cczp_bitlen(zp), a, global_test_rng);
        ccn_random_bits(cczp_bitlen(zp), b, global_test_rng);

        ccn_mul_ws(ws, n, t, a, b);
        cczp_modn_ws(ws, zp, s, n * 2, t);

        cczp_to_ws(ws, zp, a, a);
        cczp_to_ws(ws, zp, b, b);
        cczp_mul_ws(ws, zp, r, a, b);
        cczp_from_ws(ws, zp, r, r);

        ok_ccn_cmp(n, r, s, "Results don't match");

        // cczp_modn_ws() uses the Montgomery REDC algorithm.
        // Check that we get the same result when dividing on-the-fly.
        ccn_mod_ws(ws, n * 2, t, n, r, cczp_prime(zp));
        ok_ccn_cmp(n, r, s, "Results don't match");
        CC_FREE_WORKSPACE(ws);
    }
}

static void ccec_test_xcoord_internal(ccec_const_cp_t cp, size_t y_length, uint8_t *y)
{
    int rc;
    uint8_t x[1] = { 0 };
    uint8_t *shared_secret = malloc(y_length);
    size_t shared_secret_len = y_length;

    ccec_pub_ctx_decl_cp(cp, public_key);
    ccec_full_ctx_decl_cp(cp, private_key);

    rc = ccec_make_pub(ccec_cp_prime_bitlen(cp), sizeof(x), x, y_length, y, public_key);
    is(rc, CCERR_OK, "Couldn't make public key with xcoord 0");

    rc = ccecdh_generate_key(cp, global_test_rng, private_key);
    is(rc, CCERR_OK, "Couldn't generate a full key");

    rc = ccecdh_compute_shared_secret(private_key, public_key, &shared_secret_len, shared_secret, global_test_rng);
    is(rc, CCERR_OK, "Shared secret computation failed");
    free(shared_secret);
}

static void ccec_test_xcoord_zero(void)
{
    uint8_t y192a[24] = { 0x84, 0x97, 0xa9, 0xfa, 0x11, 0x9f, 0xf3, 0x4c, 0x9c, 0x24, 0xa1, 0x56, 0xed, 0x0d, 0x44, 0xa0,
                          0xc5, 0xf5, 0xd1, 0xf1, 0x9f, 0xc9, 0xf0, 0xed };

    uint8_t y192b[24] = { 0x7b, 0x68, 0x56, 0x05, 0xee, 0x60, 0x0c, 0xb3, 0x63, 0xdb, 0x5e, 0xa9, 0x12, 0xf2, 0xbb, 0x5e,
                          0x3a, 0x0a, 0x2e, 0x0e, 0x60, 0x36, 0x0f, 0x12 };

    uint8_t y256a[32] = { 0x99, 0xb7, 0xa3, 0x86, 0xf1, 0xd0, 0x7c, 0x29, 0xdb, 0xcc, 0x42, 0xa2, 0x7b, 0x5f, 0x94, 0x49,
                          0xab, 0xe3, 0xd5, 0x0d, 0xe2, 0x51, 0x78, 0xe8, 0xd7, 0x40, 0x7a, 0x95, 0xe8, 0xb0, 0x6c, 0x0b };

    uint8_t y256b[32] = { 0x66, 0x48, 0x5c, 0x78, 0x0e, 0x2f, 0x83, 0xd7, 0x24, 0x33, 0xbd, 0x5d, 0x84, 0xa0, 0x6b, 0xb6,
                          0x54, 0x1c, 0x2a, 0xf3, 0x1d, 0xae, 0x87, 0x17, 0x28, 0xbf, 0x85, 0x6a, 0x17, 0x4f, 0x93, 0xf4 };

    uint8_t y384a[48] = { 0x3c, 0xf9, 0x9e, 0xf0, 0x4f, 0x51, 0xa5, 0xea, 0x63, 0x0b, 0xa3, 0xf9, 0xf9, 0x60, 0xdd, 0x59,
                          0x3a, 0x14, 0xc9, 0xbe, 0x39, 0xfd, 0x2b, 0xd2, 0x15, 0xd3, 0xb4, 0xb0, 0x8a, 0xaa, 0xf8, 0x6b,
                          0xbf, 0x92, 0x7f, 0x2c, 0x46, 0xe5, 0x2a, 0xb0, 0x6f, 0xb7, 0x42, 0xb8, 0x85, 0x0e, 0x52, 0x1e };

    uint8_t y384b[48] = { 0xc3, 0x06, 0x61, 0x0f, 0xb0, 0xae, 0x5a, 0x15, 0x9c, 0xf4, 0x5c, 0x06, 0x06, 0x9f, 0x22, 0xa6,
                          0xc5, 0xeb, 0x36, 0x41, 0xc6, 0x02, 0xd4, 0x2d, 0xea, 0x2c, 0x4b, 0x4f, 0x75, 0x55, 0x07, 0x93,
                          0x40, 0x6d, 0x80, 0xd2, 0xb9, 0x1a, 0xd5, 0x4f, 0x90, 0x48, 0xbd, 0x48, 0x7a, 0xf1, 0xad, 0xe1 };

    uint8_t y521a[66] = { 0x01, 0x2d, 0xf1, 0x36, 0x01, 0x59, 0x4a, 0x88, 0x3e, 0xf2, 0xd9, 0x35, 0xe4, 0x4b, 0xb9, 0x0b,
                          0xf4, 0xd6, 0x61, 0x9b, 0x74, 0xe5, 0x2a, 0xf7, 0x55, 0x2f, 0x97, 0x76, 0x90, 0x11, 0xc0, 0x71,
                          0x9e, 0xb4, 0x39, 0xcf, 0xab, 0x2a, 0x88, 0xd4, 0x0f, 0xe5, 0x9a, 0x2b, 0xed, 0x1f, 0x43, 0x55,
                          0x71, 0x69, 0xa2, 0xd0, 0xa2, 0xcc, 0xd2, 0x80, 0xc6, 0x07, 0xb9, 0x2b, 0xbf, 0x51, 0xff, 0xe0,
                          0xb0, 0x78 };

    uint8_t y521b[66] = { 0x00, 0xd2, 0x0e, 0xc9, 0xfe, 0xa6, 0xb5, 0x77, 0xc1, 0x0d, 0x26, 0xca, 0x1b, 0xb4, 0x46, 0xf4,
                          0x0b, 0x29, 0x9e, 0x64, 0x8b, 0x1a, 0xd5, 0x08, 0xaa, 0xd0, 0x68, 0x89, 0x6f, 0xee, 0x3f, 0x8e,
                          0x61, 0x4b, 0xc6, 0x30, 0x54, 0xd5, 0x77, 0x2b, 0xf0, 0x1a, 0x65, 0xd4, 0x12, 0xe0, 0xbc, 0xaa,
                          0x8e, 0x96, 0x5d, 0x2f, 0x5d, 0x33, 0x2d, 0x7f, 0x39, 0xf8, 0x46, 0xd4, 0x40, 0xae, 0x00, 0x1f,
                          0x4f, 0x87 };

    ccec_test_xcoord_internal(ccec_cp_192(), sizeof(y192a), y192a);
    ccec_test_xcoord_internal(ccec_cp_192(), sizeof(y192b), y192b);
    ccec_test_xcoord_internal(ccec_cp_256(), sizeof(y256a), y256a);
    ccec_test_xcoord_internal(ccec_cp_256(), sizeof(y256b), y256b);
    ccec_test_xcoord_internal(ccec_cp_384(), sizeof(y384a), y384a);
    ccec_test_xcoord_internal(ccec_cp_384(), sizeof(y384b), y384b);
    ccec_test_xcoord_internal(ccec_cp_521(), sizeof(y521a), y521a);
    ccec_test_xcoord_internal(ccec_cp_521(), sizeof(y521b), y521b);
}

static void ccec_generate_rng_edgecases(ccec_const_cp_t cp)
{
    int top[4];
    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);
    int bot[4];
    fill(top);
    fill(bot);

    struct ccrng_sequence_state sequence_prng;
    struct ccrng_state *fake_rng = (struct ccrng_state *)&sequence_prng;
    uint8_t fake_rng_buf[MAXKEYSPACE];

    // Rng always return 0
    memset(fake_rng_buf, 0, sizeof(fake_rng_buf));
    ccrng_sequence_init(&sequence_prng, sizeof(fake_rng_buf), fake_rng_buf);
    ok(ccec_generate_key_fips(cp, fake_rng, key) == 0, "ccec_generate_key_fips failure (should succeed)");

    ok(ccec_generate_key_legacy(cp, fake_rng, key) != 0, "Don't create EC key with 0 for K");

    // Rng always returns order, needs to fail.
    memcpy(fake_rng_buf, (const uint8_t *)cczp_prime(ccec_cp_zq(cp)), ccec_cp_order_size(cp));
    ccrng_sequence_init(&sequence_prng, sizeof(fake_rng_buf), fake_rng_buf);
    ok(ccec_generate_key_fips(cp, fake_rng, key) != 0, "EC key gen fips with q (should fail)");

    // Rng always returns order - 1, needs to fail.
    memset(fake_rng_buf, 0xff, sizeof(fake_rng_buf));
    memcpy(fake_rng_buf, (const uint8_t *)cczp_prime(ccec_cp_zq(cp)), ccec_cp_order_size(cp));
    ccn_sub1(ccec_cp_n(cp), (cc_unit *)fake_rng_buf, (cc_unit *)fake_rng_buf, 1);
    ccrng_sequence_init(&sequence_prng, sizeof(fake_rng_buf), fake_rng_buf);
    ok(ccec_generate_key_fips(cp, fake_rng, key) != 0, "EC key gen fips with q - 1 (should fail)");

    // Rng always returns order - 2, needs to fail.
    memset(fake_rng_buf, 0xff, sizeof(fake_rng_buf));
    memcpy(fake_rng_buf, (const uint8_t *)cczp_prime(ccec_cp_zq(cp)), ccec_cp_order_size(cp));
    ccn_sub1(ccec_cp_n(cp), (cc_unit *)fake_rng_buf, (cc_unit *)fake_rng_buf, 2);
    ccrng_sequence_init(&sequence_prng, sizeof(fake_rng_buf), fake_rng_buf);
    ok(ccec_generate_key_fips(cp, fake_rng, key) == 0, "EC key gen fips with q - 2 (should succeed)");

    // Rng always returns ff: we will never get a scalar is in the appropriate range
    memset(fake_rng_buf, 0xff, sizeof(fake_rng_buf));
    ccrng_sequence_init(&sequence_prng, sizeof(fake_rng_buf), fake_rng_buf);
    ok(ccec_generate_key_fips(cp, fake_rng, key) != 0, "Can't pickup scalar in range (should fail)");
    ok(chkit(top), "Generate fips wrote memory of `top`");
    ok(chkit(bot), "Generate fips wrote memory of `bot`");
}

static int key_exchange(ccec_const_cp_t cp, ccec_full_ctx_t key1, ccec_full_ctx_t key2)
{
    size_t p_len = ccn_write_uint_size(ccec_cp_n(cp), ccec_cp_p(cp));
    size_t ss1_len = p_len;
    size_t ss2_len = p_len;
    uint8_t ss1[ss1_len];
    uint8_t ss2[ss2_len];

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    assert(ccec_ctx_cp(key1) == ccec_ctx_cp(key2));
    is(ccec_compute_key(key1, ccec_ctx_pub(key2), &ss1_len, ss1), CCERR_OK, "ccec_compute_key 1");
    is(ccec_compute_key(key2, ccec_ctx_pub(key1), &ss2_len, ss2), CCERR_OK, "ccec_compute_key 2");
#pragma clang diagnostic pop
    ok_or_fail(ss1_len == ss2_len, "ccec_compute_key length's not equal");
    ok_memcmp_or_fail(ss1, ss2, ss1_len, "ccec_compute_key shared secret's differ");

    ss1_len = p_len;
    ss2_len = p_len;
    ok_or_fail(ccecdh_compute_shared_secret(key1, ccec_ctx_pub(key2), &ss1_len, ss1, global_test_rng) == 0,
               "ccecdh_compute_shared_secret 1");
    ok_or_fail(ccecdh_compute_shared_secret(key2, ccec_ctx_pub(key1), &ss2_len, ss2, global_test_rng) == 0,
               "ccecdh_compute_shared_secret 2");

    ok_or_fail(ss1_len == ss2_len, "ccecdh_compute_shared_secret length's not equal");
    ok_memcmp_or_fail(ss1, ss2, ss1_len, "ccecdh_compute_shared_secret shared secret's differ");
    return 1;
}

static int verify_msg_digest(ccec_pub_ctx_t pub,
                             const struct ccdigest_info *di,
                             size_t msg_len,
                             uint8_t *msg,
                             size_t digest_len,
                             uint8_t *digest,
                             size_t sig_len,
                             uint8_t *signature,
                             char *label)
{
    uint8_t r_buffer[ccec_signature_r_s_size(pub)]; // Buffer to hold r from signature
    uint8_t rdigest[di->output_size];               // Digest we compute from r (r_buffer)
    cc_fault_canary_t ecc_canary;
    bool valid = false;

    ok_status_or_goto(ccec_extract_rs(pub, sig_len, signature, r_buffer, NULL), "extract_rs failure", err);
    ccdigest(di, ccec_signature_r_s_size(pub), r_buffer, rdigest);

    // ccec_verify
    ok_status_or_goto(ccec_verify(pub, digest_len, digest, sig_len, signature, &valid), "ccec_verify failure", err);
    is_or_goto(valid, true, "ccec_verify failure bool", err);

    // ccec_verify_strict
    ok_status_or_goto(ccec_verify_strict(pub, digest_len, digest, sig_len, signature, &valid), "ccec_verify_strict failure", err);
    is_or_goto(valid, true, "ccec_verify_strict failure bool", err);

    // ccec_verify_msg(NULL)
    ok_status_or_goto(ccec_verify_msg(pub, di, msg_len, msg, sig_len, signature, NULL), "ccec_verify_msg(NULL) failure", err);

    // ccec_verify_msg(!NULL)
    ok_status_or_goto(
        ccec_verify_msg(pub, di, msg_len, msg, sig_len, signature, ecc_canary), "ccec_verify_msg(!NULL) failure", err);
    bool canary_equal = CC_FAULT_CANARY_EQUAL(CCEC_FAULT_CANARY, ecc_canary);
    is_or_goto(canary_equal, true, "ccec_verify_msg(!NULL) canary not equal", err);


    // ccec_verify_digest(NULL)
    ok_status_or_goto(
        ccec_verify_digest(pub, digest_len, digest, sig_len, signature, NULL), "ccec_verify_digest(NULL) failure", err);

    // ccec_verify_digest(!NULL)
    ok_status_or_goto(ccec_verify_digest(pub, digest_len, digest, sig_len, signature, ecc_canary),
                      "ccec_verify_digest(!NULL) failure",
                      err);
    canary_equal = CC_FAULT_CANARY_EQUAL(CCEC_FAULT_CANARY, ecc_canary);
    is_or_goto(canary_equal, true, "ccec_verify_msg(!NULL) canary not equal", err);

    return 0;
err:
    diag("Verification failures: %s", label);
    return 1;
}

static int verify_composite_msg_digest(ccec_pub_ctx_t pub,
                                       const struct ccdigest_info *di,
                                       size_t msg_len,
                                       uint8_t *msg,
                                       size_t digest_len,
                                       uint8_t *digest,
                                       uint8_t *sig_r,
                                       uint8_t *sig_s,
                                       char *label)
{
    uint8_t rdigest[di->output_size];    // Digest we compute from r (r_buffer)
    cc_fault_canary_t fault_canary;
    bool valid = false;

    ccdigest(di, ccec_signature_r_s_size(pub), sig_r, rdigest);

    // ccec_verify_composite
    ok_status_or_goto(ccec_verify_composite(pub, digest_len, digest, sig_r, sig_s, &valid), "ccec_verify_composite failure", err);
    is_or_goto(valid, true, "ccec_verify_composite failure bool", err);

    // ccec_verify_composite_msg(NULL)
    ok_status_or_goto(
        ccec_verify_composite_msg(pub, di, msg_len, msg, sig_r, sig_s, NULL), "cec_verify_composite_msg(NULL) failure", err);

    // ccec_verify_composite_msg(!NULL)
    ok_status_or_goto(ccec_verify_composite_msg(pub, di, msg_len, msg, sig_r, sig_s, fault_canary),
                      "ccec_verify_composite_msg(!NULL) failure",
                      err);
    bool canary_equal = CC_FAULT_CANARY_EQUAL(CCEC_FAULT_CANARY, fault_canary);
    is_or_goto(canary_equal, true, "ccec_verify_composite_msg canary not equal", err);

    // ccec_verify_composite_digest(NULL)
    ok_status_or_goto(ccec_verify_composite_digest(pub, digest_len, digest, sig_r, sig_s, NULL),
                      "cec_verify_composite_digest(NULL) failure",
                      err);

    // ccec_verify_composite_digest(!NULL)
    ok_status_or_goto(ccec_verify_composite_digest(pub, digest_len, digest, sig_r, sig_s, fault_canary),
                      "cec_verify_composite_digest(!NULL) failure",
                      err);
    canary_equal = CC_FAULT_CANARY_EQUAL(CCEC_FAULT_CANARY, fault_canary);
    is_or_goto(canary_equal, true, "ccec_verify_composite_msg canary not equal", err);

    return 0;
err:
    diag("Verification failures: %s", label);
    return 1;
}

static int sign_verify(ccec_const_cp_t cp,
                       ccec_full_ctx_t sk,
                       ccec_full_ctx_t vk,
                       const struct ccdigest_info *di,
                       size_t msg_len,
                       uint8_t *msg)
{
    uint8_t digest[di->output_size];
    ccdigest(di, msg_len, msg, digest);

    size_t sig_len = ccec_sign_max_size(cp);
    uint8_t signature[sig_len];
    uint8_t *sig_r = signature;
    uint8_t *sig_s = signature + ccec_signature_r_s_size(ccec_ctx_pub(sk));

    /*
        ccec_sign
    */
    ok_status_or_goto(
        ccec_sign(sk, di->output_size, digest, &sig_len, signature, global_test_rng), "ccec_sign: Signing failure", err);

    ok_status_or_goto(
        verify_msg_digest(ccec_ctx_pub(vk), di, msg_len, msg, di->output_size, digest, sig_len, signature, "ccec_sign"),
        "ccec_sign: verify_msg_digest failure",
        err);

    /*
       ccec_sign_msg
    */
    cc_clear(sig_len, signature);
    sig_len = ccec_sign_max_size(cp);
    ok_status_or_goto(
        ccec_sign_msg(sk, di, msg_len, msg, &sig_len, signature, global_test_rng), "ccec_sign_msg: Signing failure", err);

    ok_status_or_goto(
        verify_msg_digest(ccec_ctx_pub(vk), di, msg_len, msg, di->output_size, digest, sig_len, signature, "ccec_sign_msg"),
        "ccec_sign_msg: verify_msg_digest failure",
        err);

    /*
       ccec_sign_composite
    */
    cc_clear(sig_len, signature);
    sig_len = ccec_sign_max_size(cp);
    ok_status_or_goto(ccec_sign_composite(sk, di->output_size, digest, sig_r, sig_s, global_test_rng),
                      "ccec_sign_composite: Signing failure",
                      err);
    ok_status_or_goto(verify_composite_msg_digest(
                          ccec_ctx_pub(vk), di, msg_len, msg, di->output_size, digest, sig_r, sig_s, "ccec_sign_composite"),
                      "ccec_sign_composite: verify_composite_msg_digest failure",
                      err);

    /*
       ccec_sign_composite_msg
    */
    cc_clear(sig_len, signature);
    sig_len = ccec_sign_max_size(cp);
    ok_status_or_goto(ccec_sign_composite_msg(sk, di, msg_len, msg, sig_r, sig_s, global_test_rng),
                      "ccec_sign_composite_msg: Signing failure",
                      err);
    ok_status_or_goto(verify_composite_msg_digest(
                          ccec_ctx_pub(vk), di, msg_len, msg, di->output_size, digest, sig_r, sig_s, "ccec_sign_composite_msg"),
                      "ccec_sign_composite_msg: verify_composite_msg_digest failure",
                      err);

    return 1;
err:
    return 0;
}

static int ie_copy(ccec_full_ctx_t fk, ccec_full_ctx_t ipub, ccec_full_ctx_t ipriv)
{
    memcpy(ipub, fk, ccec_full_ctx_size(ccec_ccn_size(ccec_ctx_cp(fk))));
    memcpy(ipriv, fk, ccec_full_ctx_size(ccec_ccn_size(ccec_ctx_cp(fk))));
    return 1;
}

static int ie_x963(ccec_full_ctx_t fk, ccec_full_ctx_t ipub, ccec_full_ctx_t ipriv)
{
    ccec_const_cp_t cp = ccec_ctx_cp(fk);
    size_t cz = ccec_cp_prime_bitlen(cp);

    size_t export_pubsize = ccec_x963_export_size(0, ccec_ctx_pub(fk));
    is(export_pubsize, ccec_x963_export_size_cp(0, cp), "x963: Export size incorrect (pubkey)[cp%zu]", cz);
    size_t export_privsize = ccec_x963_export_size(1, ccec_ctx_pub(fk));
    is(export_privsize, ccec_x963_export_size_cp(1, cp), "x963: Export size incorrect (pubkey+privkey)[cp%zu]", cz);

    uint8_t exported_pubkey[export_pubsize];
    uint8_t exported_privkey[export_privsize];
    is(ccec_x963_export(0, exported_pubkey, fk), CCERR_OK, "Public key export failed");
    is(ccec_x963_export(1, exported_privkey, fk), CCERR_OK, "Private key export failed");

    // Now we'll import the key using x963
    // -----------------------------------
    size_t import_pubsize = ccec_x963_import_pub_size(export_pubsize);
    size_t import_privsize = ccec_x963_import_priv_size(export_privsize);

    is(import_pubsize, ccec_ctx_bitlen(fk), "x963: Import size incorrect (pubkey)[cp%zu]", cz);
    is(import_privsize, ccec_ctx_bitlen(fk), "x963: Import size incorrect (pubkey+privkey)[cp%zu]", cz);
    ok_status_or_goto(
        ccec_x963_import_pub(cp, export_pubsize, exported_pubkey, ccec_ctx_pub(ipub)), "ccec_x963_import_pub failure", err);
    is_or_goto(ccec_ctx_bitlen(ipub), ccec_ctx_bitlen(fk), "x963: Incorrect imported public key size", err);
    ok_status_or_goto(ccec_x963_import_priv(cp, export_privsize, exported_privkey, ipriv), "ccec_x963_import_priv failure", err);
    ok_status_or_goto(
        ccec_x963_import_pub(cp, export_pubsize, exported_pubkey, ccec_ctx_pub(ipriv)), "ccec_x963_import_pub failure", err);
    is_or_goto(ccec_ctx_bitlen(ipriv), ccec_ctx_bitlen(fk), "x963: Incorrect imported private key size", err);

    return 1;
err:
    diag("x963 import / export error cp%zu", cz);
    return 0;
}

static int ie_raw(ccec_full_ctx_t fk, ccec_full_ctx_t ipub, ccec_full_ctx_t ipriv)
{
    ccec_const_cp_t cp = ccec_ctx_cp(fk);
    size_t cz = ccec_cp_prime_bitlen(cp);

    size_t export_pubsize = ccec_x963_export_size(0, ccec_ctx_pub(fk));
    is(export_pubsize, ccec_x963_export_size_cp(0, cp), "x963: Export size incorrect (pubkey)[cp%zu]", cz);
    size_t export_privsize = ccec_x963_export_size(1, ccec_ctx_pub(fk));
    is(export_privsize, ccec_x963_export_size_cp(1, cp), "x963: Export size incorrect (pubkey+privkey)[cp%zu]", cz);
    size_t es = (export_privsize - 1) / 3;

    uint8_t exported_pubkey[export_pubsize];
    uint8_t exported_privkey[export_privsize];
    is(ccec_x963_export(0, exported_pubkey, fk), CCERR_OK, "Public key export failed");
    is(ccec_x963_export(1, exported_privkey, fk), CCERR_OK, "Private key export failed");

    ok_status_or_goto(
        ccec_raw_import_pub(cp, export_pubsize - 1, exported_pubkey + 1, ccec_ctx_pub(ipub)), "ccec_raw_import_pub failure", err);
    is_or_goto(ccec_ctx_bitlen(ipub), ccec_ctx_bitlen(fk), "raw: Incorrect imported public key size", err);
    ok_status_or_goto(
        ccec_raw_import_priv_only(cp, es, exported_privkey + 2 * es + 1, ipriv), "ccec_raw_import_priv_only failure", err);
    ok_status_or_goto(ccec_raw_import_pub(cp, export_pubsize - 1, exported_pubkey + 1, ccec_ctx_pub(ipriv)),
                      "ccec_raw_import_pub failure (private key)",
                      err);
    is_or_goto(ccec_ctx_bitlen(ipriv), ccec_ctx_bitlen(fk), "raw: Incorrect imported private key size", err);

    return 1;
err:
    diag("raw import / export error cp%zu", cz);
    return 0;
}

static int ie_components(ccec_full_ctx_t fk, ccec_full_ctx_t ipub, ccec_full_ctx_t ipriv)
{
    ccec_const_cp_t cp = ccec_ctx_cp(fk);
    size_t cz = ccec_cp_prime_bitlen(cp);

    cc_size n = ccec_cp_n(cp);
    size_t xsize, ysize, dsize, nbits, xy_excessize_size;
    xsize = ysize = dsize = nbits = ccn_sizeof_n(n);
    xy_excessize_size = 2 * ccn_sizeof_n(n);

    uint8_t x[xsize], y[ysize], d[dsize];
    uint8_t xy_excessive[xy_excessize_size];
    memset(xy_excessive, 0, xy_excessize_size);

    ok_status_or_goto(
        ccec_get_fullkey_components(fk, &nbits, x, &xsize, y, &ysize, d, &dsize), "ccec_get_fullkey_components failure", err);

    // Negative testing
    xy_excessive[0] |= 0x80; // Set the MSB so the parser thinks the entire key is valid
    ok_or_goto(0 != ccec_make_pub(nbits, xsize, x, xy_excessize_size, xy_excessive, ccec_ctx_pub(ipub)),
               "ccec_make_pub excessive y should fail",
               err);
    ok_or_goto(0 != ccec_make_pub(nbits, xy_excessize_size, xy_excessive, ysize, y, ccec_ctx_pub(ipub)),
               "ccec_make_pub excessive x should fail",
               err);
    ok_or_goto(0 != ccec_make_priv(nbits, xsize, x, xy_excessize_size, xy_excessive, dsize, d, ipriv),
               "ccec_make_priv excessive y should fail",
               err);
    ok_or_goto(0 != ccec_make_priv(nbits, xy_excessize_size, xy_excessive, ysize, y, dsize, d, ipriv),
               "ccec_make_priv excessive x should fail",
               err);
    ok_or_goto(0 != ccec_make_priv(nbits, xsize, x, ysize, y, xy_excessize_size, xy_excessive, ipriv),
               "ccec_make_priv excessive d should fail",
               err);

    // Now actually import it
    ok_status_or_goto(ccec_make_pub(nbits, xsize, x, ysize, y, ccec_ctx_pub(ipub)), "ccec_make_pub failure", err);
    ok_status_or_goto(ccec_make_priv(nbits, xsize, x, ysize, y, dsize, d, ipriv), "ccec_make_priv failure", err);

    // ccec_make_pub() and ccec_make_priv() don't properly support multiple
    // curves with the same bit lengths. Restore the original `cp`.
    ipriv->cp = cp;

    return 1;
err:
    diag("components import / export error cp%zu", cz);
    return 0;
}

static int ie_compact(ccec_full_ctx_t fk, ccec_full_ctx_t ipub, ccec_full_ctx_t ipriv)
{
    ccec_const_cp_t cp = ccec_ctx_cp(fk);
    size_t cz = ccec_cp_prime_bitlen(cp);
    cc_size n = ccec_cp_n(cp);

    size_t export_pubsize = ccec_compact_export_size(0, ccec_ctx_pub(fk));
    is(export_pubsize, ccec_compact_export_size_cp(0, cp), "Export compact size incorrect (pubkey)[%zu]", cz);
    size_t export_privsize = ccec_compact_export_size(1, ccec_ctx_pub(fk));
    is(export_privsize, ccec_compact_export_size_cp(1, cp), "Export compact size incorrect (pubkey+privkey)[%zu]", cz);

    uint8_t exported_pubkey[export_pubsize];
    uint8_t exported_pubkey2[export_pubsize];
    uint8_t exported_privkey[export_privsize];
    is(ccec_compact_export(0, exported_pubkey, fk), CCERR_OK, "Public key compact export failed");
    is(ccec_compact_export_pub(exported_pubkey2, ccec_ctx_pub(fk)), CCERR_OK, "Public key compact export failed");
    is(ccec_compact_export(1, exported_privkey, fk), CCERR_OK, "Private key compact export failed");
    ok_memcmp_or_goto(exported_pubkey, exported_pubkey2, export_pubsize, err, "Exported public keys neq");

    ok_status_or_goto(
        ccec_compact_import_pub(cp, export_pubsize, exported_pubkey, ccec_ctx_pub(ipub)), "ccec_compact_import_pub failure", err);
    is_or_goto(ccec_ctx_bitlen(ipub), ccec_ctx_bitlen(fk), "compact: Incorrect imported public key size", err);
    ok_status_or_goto(
        ccec_compact_import_priv(cp, export_privsize, exported_privkey, ipriv), "ccec_compact_import_priv failure", err);
    is_or_goto(ccec_ctx_bitlen(ipriv), ccec_ctx_bitlen(fk), "compact: Incorrect imported private key size", err);
    
    // Check the y coordinate
    if (ccec_is_compactable_pub(ccec_ctx_pub(fk))) {
        ok_memcmp(ccec_ctx_y(fk), ccec_ctx_y(ipub), n, "compact: import failed since y != y' for a compactable key");
        ok_memcmp(ccec_ctx_y(fk), ccec_ctx_y(ipriv), n, "compact: import failed since y != y' for a compactable key");
    } else {
        cc_unit t[n];
        ccn_sub(n, t, cczp_prime(ccec_cp_zp(cp)), ccec_ctx_y(ipub));
        ok_memcmp(ccec_ctx_y(fk), t, n, "compact: import failed since y == y' for a non-compactable key");
        ccn_sub(n, t, cczp_prime(ccec_cp_zp(cp)), ccec_ctx_y(ipriv));
        ok_memcmp(ccec_ctx_y(fk), t, n, "compact: import failed since y == y' for a non-compactable key");
    }

    return 1;
err:
    diag("compact import / export error cp%zu", cz);
    return 0;
}

static const struct ccdigest_info *get_digest(int n)
{
    switch (n) {
    case 1:
        return ccsha1_di();
    case 224:
        return ccsha224_di();
    case 256:
        return ccsha256_di();
    case 384:
        return ccsha384_di();
    case 512:
        return ccsha512_di();
    case 512256:
        return ccsha512_256_di();
    default:
        return NULL;
    }
}

struct ccec_test_import_export_func {
    int (*func)(ccec_full_ctx_t fk, ccec_full_ctx_t imported_pub_x963, ccec_full_ctx_t imported_priv_x963);
    char *name;
    bool compact;
};

static int blind_unblind(ccec_const_cp_t cp, ccec_pub_ctx_t pub)
{
    // Initialized by ccec_generate_blinding_keys
    ccec_full_ctx_decl_cp(cp, blinding_key);
    ccec_full_ctx_decl_cp(cp, unblinding_key);
    
    ccec_pub_ctx_decl_cp(cp, pub_blinded);
    ccec_ctx_init(cp, pub_blinded);
    ccec_pub_ctx_decl_cp(cp, pub_unblinded);
    ccec_ctx_init(cp, pub_unblinded);

    size_t pub_export_sz = ccec_export_pub_size(pub);
    uint8_t pub_input[pub_export_sz];
    uint8_t pub_calced[pub_export_sz];
    
    is_or_goto(ccec_generate_blinding_keys(cp, global_test_rng, blinding_key, unblinding_key), CCERR_OK, "Generate twin keys error", err);
    is_or_goto(ccec_blind(global_test_rng, blinding_key, pub, pub_blinded), CCERR_OK, "Twin keys blind error", err);
    is_or_goto(ccec_unblind(global_test_rng, unblinding_key, pub_blinded, pub_unblinded), CCERR_OK, "Twin keys unblind error", err);
    
    is(ccec_export_pub(pub, pub_input), CCERR_OK, "Public key export failed");
    is(ccec_export_pub(pub_unblinded, pub_calced), CCERR_OK, "Unblinded public key export failed");
    
    ok_memcmp_or_goto(pub_input, pub_calced, pub_export_sz, err, "Unblinded pubkey isn't equal to input key!");
    
    return 1;
err:
    return 0;
}

static int individual_key_tests(ccec_const_cp_t cp, ccec_full_ctx_t fk, bool compact_enabled)
{
    static struct ccec_test_import_export_func ccec_test_import_export_funcs[] = {
        { .func = ie_copy, .name = "Copy", .compact = false },
        { .func = ie_x963, .name = "x963", .compact = false },
        { .func = ie_raw, .name = "raw", .compact = false },
        { .func = ie_components, .name = "components", .compact = false },
        { .func = ie_compact, .name = "compact", .compact = true },
    };
    const size_t ccec_test_import_export_funcs_len = CC_ARRAY_LEN(ccec_test_import_export_funcs);
    const int ccec_test_valid_digests[] = { 1, 224, 256, 384, 512, 512256 };
    const size_t ccec_test_valid_digests_len = CC_ARRAY_LEN(ccec_test_valid_digests);
    uint8_t msg[74] = "We are good testers and will check all of the curve / digest combinations!";

    size_t cz = ccec_cp_prime_bitlen(cp);
    ccec_full_ctx_decl_cp(cp, ie_pub);
    ccec_full_ctx_decl_cp(cp, ie_priv);

    for (size_t j = 0; j < ccec_test_import_export_funcs_len; j++) {
        ccec_full_ctx_clear_cp(cp, ie_pub);
        ccec_full_ctx_clear_cp(cp, ie_priv);

        struct ccec_test_import_export_func ief = ccec_test_import_export_funcs[j];
        int status = ief.func(fk, ie_pub, ie_priv);

        ok(status, "Import / Export failure - %s", ief.name);
        if (!status) {
            continue;
        }

        ok(key_exchange(cp, ie_priv, fk), "Key exchange error[cp%zu, %s]", cz, ief.name);
        ok(blind_unblind(cp, ccec_ctx_pub(fk)), "Blind Unblind error[cp%zu, %s]", cz, ief.name);
        if (!compact_enabled && ief.compact) {
            continue;
        }
        for (size_t i = 0; i < ccec_test_valid_digests_len; i++) {
            const struct ccdigest_info *di = get_digest(ccec_test_valid_digests[i]);
            ok(sign_verify(cp, ie_priv, ie_pub, di, sizeof(msg), msg),
               "Sign / Verify error [cp%zu, %s, sha%d]",
               cz,
               ief.name,
               ccec_test_valid_digests[i]);
        }
    }
    return 1;
}

struct ccec_test_key_generation_func {
    int (*func)(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key);
    char *name;
    bool compact_enabled;
};

static void ccec_cp_tests(ccec_const_cp_t cp)
{
    static struct ccec_test_key_generation_func ccec_test_key_generation_funcs[] = {
        { .func = ccec_generate_key_fips, .name = "FIPS", .compact_enabled = false },
        { .func = ccecdh_generate_key, .name = "Normal", .compact_enabled = false },
        { .func = ccec_compact_generate_key, .name = "Compact", .compact_enabled = true },
    };
    const size_t ccec_test_key_generation_funcs_len = CC_ARRAY_LEN(ccec_test_key_generation_funcs);

    struct ccrng_state *rng = global_test_rng;
    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);

    for (size_t i = 0; i < ccec_test_key_generation_funcs_len; i++) {
        struct ccec_test_key_generation_func kgf = ccec_test_key_generation_funcs[i];

        int status = kgf.func(cp, rng, key);
        is(status, CCERR_OK, "Generate key failure: %s", kgf.name);
        is(ccecdh_pairwise_consistency_check(key, NULL, rng), CCERR_OK, "Key doesn't pass consistency checks");
        ok(individual_key_tests(cp, key, kgf.compact_enabled), "Individual key tests failed");
    }
}

static void ccec_compact_tests(ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);
    cc_size n = ccec_cp_n(cp);
    
    for (size_t i = 0; i < 10; i++) {
        // Compactable
        is(ccec_compact_generate_key(cp, global_test_rng, key), CCERR_OK, "Generate compact key failed");
        ok(ccec_is_compactable_pub(ccec_ctx_pub(key)), "Public key should be compactable");

        // Replace y by (p-y)
        ccn_sub(n, ccec_ctx_y(key), cczp_prime(ccec_cp_zp(cp)), ccec_ctx_y(key));
        ok(ccec_validate_pub(ccec_ctx_pub(key)), "Public key should remain valid");
        ok(!ccec_is_compactable_pub(ccec_ctx_pub(key)), "Public key should not be compactable");
    }
}

static void ccec_generate_key_ctx_tests(ccec_const_cp_t cp)
{
    ccec_generate_key_ctx_decl_cp(cp, key);
    ccec_full_ctx_t fk = NULL;
    cc_size n = ccec_cp_n(cp);
    
    for (size_t i = 0; i < 10; i++)
    {
        fk = NULL;
        is(ccec_compact_generate_key_init(cp, global_test_rng, key), CCERR_OK, "ccec_compact_generate_key_init failure");
        
        int rv = CCERR_OK;
        do {
            rv = ccec_compact_generate_key_step(global_test_rng, key, &fk);
            is(rv, CCERR_OK, "ccec_compact_generate_key_step failure");
        } while (rv == CCERR_OK && fk == NULL);
        
        isnt(fk, NULL, "ccec_compact_generate_key_step full key is not valid");
        
        if (fk != NULL) {
            ok(ccec_is_compactable_pub(ccec_ctx_pub(fk)), "Public key should be compactable");
            // Replace y by (p-y)
            ccn_sub(n, ccec_ctx_y(fk), cczp_prime(ccec_cp_zp(cp)), ccec_ctx_y(fk));
            ok(ccec_validate_pub(ccec_ctx_pub(fk)), "Public key should remain valid");
            ok(!ccec_is_compactable_pub(ccec_ctx_pub(fk)), "Public key should not be compactable");
        }
    }
}

static void ccec_affinify_points_tests(ccec_const_cp_t cp)
{
    cc_size n = ccec_cp_n(cp);
    cc_size npoints = 30;
    ccec_projective_point_t input[npoints];
    ccec_affine_point_t reference[npoints];
    ccec_affine_point_t output[npoints];
    ccec_full_ctx_t keys[npoints];

    CC_DECL_WORKSPACE_TEST(ws);
    // Allocate
    for(size_t i = 0; i < npoints; i++) {
        keys[i] = (ccec_full_ctx_t) CC_ALLOC_WS(ws, ccec_full_ctx_size(n));
        input[i] = CCEC_ALLOC_POINT_WS(ws, n);
        output[i] = (ccec_affine_point_t)CCEC_ALLOC_POINT_WS(ws, n);
        reference[i] = (ccec_affine_point_t)CCEC_ALLOC_POINT_WS(ws, n);
    }
    // Generate input and reference
    for(size_t i = 0; i < npoints; i++) {
        is(ccec_generate_key_internal_fips_ws(ws, cp, global_test_rng, keys[i]), CCERR_OK, "Key generation failed");
        is(ccec_projectify_ws(ws, cp, input[i], (ccec_affine_point_t)ccec_ctx_point(keys[i]), global_test_rng), CCERR_OK, "Projectify failed");
        is(ccec_affinify_ws(ws, cp, reference[i], input[i]), CCERR_OK, "Affinify failed");
    }
    // Affinify input points into output
    is(ccec_affinify_points_ws(ws, cp, npoints, output, input), CCERR_OK, "affinify_points failed");
    // Compare output and reference
    for(size_t i = 0; i < npoints; i++) {
        ok_ccn_cmp(n, ccec_point_x(output[i], cp), ccec_point_x(reference[i], cp), "x coordinates don't match");
        ok_ccn_cmp(n, ccec_point_y(output[i], cp), ccec_point_y(reference[i], cp), "y coordinates don't match");
    }
    // Affinify input points in place
    is(ccec_affinify_points_ws(ws, cp, npoints, (ccec_affine_point_t*)input, input), CCERR_OK, "affinify_points failed");
    // Compare input and reference
    for(size_t i = 0; i < npoints; i++) {
        ok_ccn_cmp(n, ccec_point_x(input[i], cp), ccec_point_x(reference[i], cp), "x coordinates don't match");
        ok_ccn_cmp(n, ccec_point_y(input[i], cp), ccec_point_y(reference[i], cp), "y coordinates don't match");
    }
    // Generate new inputs, with one point at infinity
    for(size_t i = 0; i < npoints; i++) {
        is(ccec_generate_key_internal_fips_ws(ws, cp, global_test_rng, keys[i]), CCERR_OK, "Key generation failed");
        is(ccec_projectify_ws(ws, cp, input[i], (ccec_affine_point_t)ccec_ctx_point(keys[i]), global_test_rng), CCERR_OK, "Projectify failed");
        if (i == npoints - 1) {
            // Make the last point the point at infinity
            ccn_clear(n, ccec_point_z(input[i], cp));
        }
    }
    // Attempt to affinity input points
    is(ccec_affinify_points_ws(ws, cp, npoints, output, input), CCERR_PARAMETER, "affinify_points should have failed");
    CC_FREE_WORKSPACE(ws);
}

#if CCN_MULMOD_256_ASM
// Wrapper to implement runtime checks for Intel extensions.
static ccec_const_cp_t ccec_cp_256_asm_if_available(void)
{
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
    return ccec_cp_256_asm();

#if defined(__x86_64__)
    return NULL;
#endif
}
#endif

#if CCN_MULMOD_384_ASM
// Wrapper to implement runtime checks for Intel extensions.
static ccec_const_cp_t ccec_cp_384_asm_if_available(void)
{
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
    return ccec_cp_384_asm();

#if defined(__x86_64__)
    return NULL;
#endif
}
#endif

static void ccec_random_tests(void)
{
    ccec_const_cp_t curves[] = {
        ccec_cp_192(),
        ccec_cp_224(), ccec_cp_224_c(),
#if CCN_MULMOD_224_ASM
        ccec_cp_224_asm(), ccec_cp_224_small_asm(),
#endif
        ccec_cp_256(), ccec_cp_256_c(), ccec_cp_256_small(),
#if CCN_MULMOD_256_ASM
        ccec_cp_256_asm_if_available(),
#endif
        ccec_cp_384(), ccec_cp_384_c(), ccec_cp_384_small(),
#if CCN_MULMOD_384_ASM
        ccec_cp_384_asm_if_available(),
#endif
        ccec_cp_521()
    };
    
    for (size_t i = 0; i < CC_ARRAY_LEN(curves); i++) {
        ccec_const_cp_t cp = curves[i];
        if (curves[i]) {
            ccec_generate_rng_edgecases(cp);
            ccec_cczp_mod_prime_tests(cp);
            ccec_cp_tests(cp);
            ccec_compact_tests(cp);
            ccec_affinify_points_tests(cp);
            ccec_generate_key_ctx_tests(cp);
        }
    }
}

static void ccec_key_sizes_tests(void)
{
    static const size_t ccec_test_valid_key_sizes[] = { 192, 224, 256, 384, 521 };
    static const size_t ccec_test_valid_key_sizes_len = CC_ARRAY_LEN(ccec_test_valid_key_sizes);
    const size_t invalid_key_sizes[] = { 100, 200, 300, 400, 500, 600 };
    const size_t invalid_key_sizes_len = CC_ARRAY_LEN(invalid_key_sizes);

    for (size_t i = 0; i < ccec_test_valid_key_sizes_len; i++) {
        size_t key_size = ccec_test_valid_key_sizes[i];
        ok(ccec_keysize_is_supported(key_size), "Key size valid yet deemed invalid");
        isnt(ccec_get_cp(key_size), NULL, "ccec_get_cp failed for valid key size");
    }

    for (size_t i = 0; i < invalid_key_sizes_len; i++) {
        size_t key_size = invalid_key_sizes[i];
        ok(!ccec_keysize_is_supported(key_size), "Invalid key size deemed valid");
        is(ccec_get_cp(key_size), NULL, "ccec_get_cp succeeded for invalid key size");
    }
}

static void ccec_scalar_tests(void)
{
    ccec_const_cp_t cp = ccec_cp_256();

    ccec_point_decl_cp(cp, G);
    ccec_point_decl_cp(cp, R);
    ccec_point_decl_cp(cp, S);

    CC_DECL_WORKSPACE_TEST(ws);

    int rv = ccec_projectify_ws(ws, cp, G, ccec_cp_g(cp), global_test_rng);
    is(rv, CCERR_OK, "ccec_projectify() failed");

    cc_size n = ccec_cp_n(cp);
    cc_unit s[n];

    /* Test small scalars with lots of leading zeros. */

    // 0 * G
    ccn_clear(n, s);
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    // R == O ?
    ok(ccec_is_point_at_infinity(cp, R), "R = 0 * G = O");

    // 7 * O
    ccn_seti(n, s, 7);
    rv = ccec_mult_blinded_ws(ws, cp, S, s, R, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    // R == O ?
    ok(ccec_is_point_at_infinity(cp, S), "R = 7 * O = O");

    // 1 * G
    ccn_seti(n, s, 1);
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)S, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    // x(R) == x(G) ?
    ok_ccn_cmp(n, ccec_point_x(ccec_cp_g(cp), cp), ccec_point_x(S, cp), "R = 1 * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)S, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    // x(R) == x(G) ?
    ok_ccn_cmp(n, ccec_point_x(ccec_cp_g(cp), cp), ccec_point_x(S, cp), "R = 1 * G");

    // 2 * G
    ccec_full_add_ws(ws, cp, S, G, G);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)S, S);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    ccn_seti(n, s, 2);
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    // x(R) == x(S) ?
    ok_ccn_cmp(n, ccec_point_x(R, cp), ccec_point_x(S, cp), "R = 2 * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    // x(R) == x(S) ?
    ok_ccn_cmp(n, ccec_point_x(R, cp), ccec_point_x(S, cp), "R = 2 * G");

    // 5 * G
    ccec_full_add_ws(ws, cp, S, G, G);
    ccec_full_add_ws(ws, cp, R, S, S);
    ccec_full_add_ws(ws, cp, S, R, G);

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)S, S);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    ccn_seti(n, s, 5);
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    // x(R) == x(S) ?
    ok_ccn_cmp(n, ccec_point_x(R, cp), ccec_point_x(S, cp), "R = 5 * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    // x(R) == x(S) ?
    ok_ccn_cmp(n, ccec_point_x(R, cp), ccec_point_x(S, cp), "R = 5 * G");

    /* Test scalar with no leading zeros. */

    // q * G
    ccn_set(n, s, cczp_prime(ccec_cp_zq(cp)));
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    ok(ccec_is_point_at_infinity(cp, R), "R is point at infinity");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");
    ok(ccec_is_point_at_infinity(cp, R), "R is point at infinity");

    // (q + 1) * G
    ccn_add1_ws(ws, n, s, cczp_prime(ccec_cp_zq(cp)), 1);
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    const cc_unit S1[] = {
        CCN256_C(6b,17,d1,f2,e1,2c,42,47,f8,bc,e6,e5,63,a4,40,f2,77,03,7d,81,2d,eb,33,a0,f4,a1,39,45,d8,98,c2,96)
    };
    ok_ccn_cmp(n, ccec_point_x(R, cp), S1, "R = (q-1) * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    ok_ccn_cmp(n, ccec_point_x(R, cp), S1, "R = (q-1) * G");

    // (q + 2) * G
    ccn_add1_ws(ws, n, s, cczp_prime(ccec_cp_zq(cp)), 2);
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    const cc_unit S2[] = {
        CCN256_C(7c,f2,7b,18,8d,03,4f,7e,8a,52,38,03,04,b5,1a,c3,c0,89,69,e2,77,f2,1b,35,a6,0b,48,fc,47,66,99,78)
    };
    ok_ccn_cmp(n, ccec_point_x(R, cp), S2, "R = (q-1) * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    ok_ccn_cmp(n, ccec_point_x(R, cp), S2, "R = (q-1) * G");

    // (q - 1) * G
    ccn_sub1(n, s, cczp_prime(ccec_cp_zq(cp)), 1);
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    const cc_unit S3[] = {
        CCN256_C(6b,17,d1,f2,e1,2c,42,47,f8,bc,e6,e5,63,a4,40,f2,77,03,7d,81,2d,eb,33,a0,f4,a1,39,45,d8,98,c2,96)
    };
    ok_ccn_cmp(n, ccec_point_x(R, cp), S3, "R = (q-1) * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    ok_ccn_cmp(n, ccec_point_x(R, cp), S3, "R = (q-1) * G");

    /* Test a scalar with one leading zeros. */

    // (q-1 mod 2^255) * G
    s[n - 1] &= CCN_UNIT_MASK >> 1;
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    const cc_unit S4[] = {
        CCN256_C(f8,08,03,3c,1c,06,0c,40,db,4b,76,f8,c6,2d,c8,f1,6a,a3,16,95,2d,a3,d5,4c,fa,c4,36,f9,f8,15,16,1a)
    };
    ok_ccn_cmp(n, ccec_point_x(R, cp), S4, "R = (q-1 mod 2^255) * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    ok_ccn_cmp(n, ccec_point_x(R, cp), S4, "R = (q-1 mod 2^255) * G");

    /* Test a scalar with two leading zeros. */

    // (q-1 mod 2^254) * G
    s[n - 1] &= CCN_UNIT_MASK >> 2;
    rv = ccec_mult_blinded_ws(ws, cp, R, s, G, global_test_rng);
    is(rv, CCERR_OK, "ccec_mult_blinded() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    const cc_unit S5[] = {
        CCN256_C(06,90,82,9e,c3,cf,98,0e,fd,6d,77,ab,44,15,c6,05,9b,9c,56,6a,8e,44,2a,27,cc,28,de,73,e9,2b,12,26)
    };
    ok_ccn_cmp(n, ccec_point_x(R, cp), S5, "R = (q-1 mod 2^254) * G");

    rv = ccec_mult_ws(ws, cp, R, s, ccn_bitsof_n(n), G);
    is(rv, CCERR_OK, "ccec_mult() failed");

    rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
    is(rv, CCERR_OK, "ccec_affinify() failed");

    ok_ccn_cmp(n, ccec_point_x(R, cp), S5, "R = (q-1 mod 2^254) * G");

    CC_FREE_WORKSPACE(ws);
}

const struct ccec_mult_edge_case_test_vector {
    cc_unit gx[32];  // x = x(G), the x-coordinate of the base point
    cc_unit rx[32];  // x = x(R), the x-coordinate of the resulting point
    cc_unit s[32];   // scalar s
    uint8_t mask[4]; // mask value returned by the RNG
} ccec_mult_edge_case_test_vectors[] = {
    {
        // Intermediate result Q, such that x(Q) = x(mask * S) = 0.
        .gx = { CCN256_C(15,59,0c,30,8b,73,02,b8,db,f9,2e,e2,39,4b,a4,89,6e,92,68,91,2b,cf,b2,6a,e1,d0,3e,2e,ef,56,d7,53) },
        .rx = { CCN256_C(86,df,92,96,8f,36,67,f8,8b,f2,ee,18,93,f5,0a,7f,29,db,3c,85,5f,fa,ae,69,a3,04,95,e7,bc,57,23,3c) },
        .s = { CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,4f) },
        .mask = { 0x00, 0x00, 0x00, 0x00 }
    },
    {
        // Intermediate result Q, such that x(Q) = x(b * S) = 0.
        .gx = { CCN256_C(27,24,ac,95,ba,46,72,14,3a,2a,4b,7a,06,14,da,9b,ff,54,fe,14,4e,7c,77,a4,a4,02,ee,ff,a6,3a,6b,ad) },
        .rx = { CCN256_C(7f,e5,ee,1f,e1,8b,a3,67,51,a7,78,29,d5,01,a7,37,c2,61,b7,0a,ee,15,c7,5f,36,f7,86,25,12,e0,03,67) },
        .s = { CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,4f) },
        .mask = { 0x00, 0x00, 0x00, 0x00 }
    },
    {
        // Intermediate result R, such that x(R) = x(mask * a * S) = 0.
        .gx = { CCN256_C(96,b2,f1,82,c1,16,f3,ea,eb,ef,38,f9,97,d8,a1,a8,5d,16,aa,6c,4e,6c,8b,7c,6d,e4,aa,fc,57,28,9f,f0) },
        .rx = { CCN256_C(02,bd,8e,bd,06,a3,14,d2,e7,59,d1,6b,34,72,44,9f,4d,5b,d0,b0,7d,26,2c,d6,76,19,74,a5,47,ce,ee,b1) },
        .s = { CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,4f) },
        .mask = { 0x00, 0x00, 0x00, 0x00 }
    },
    {
        // Compute R = s * G = (q - 5) * G. If s = 0 (mod mask) and b = 0,
        // one partial result of the blinded scalar multiplication will be
        // the point at infinity as we're multiplying by zero, Q = 0 * S.
        .gx = { CCN256_C(6b,17,d1,f2,e1,2c,42,47,f8,bc,e6,e5,63,a4,40,f2,77,03,7d,81,2d,eb,33,a0,f4,a1,39,45,d8,98,c2,96) },
        .rx = { CCN256_C(51,59,0b,7a,51,51,40,d2,d7,84,c8,56,08,66,8f,df,ef,8c,82,fd,1f,5b,e5,24,21,55,4a,0d,c3,d0,33,ed) },
        .s = { CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,4c) },
        .mask = { 0xe4, 0x82, 0xa3, 0x00 }
    },
    {
        // Compute R = s * S = (q - 2) * S, where x(S) = 0 and s odd.
        .gx = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00) },
        .rx = { CCN256_C(c2,24,2b,e3,59,87,9e,cf,8a,92,b8,d9,79,c6,dc,96,d9,00,5a,00,23,6b,a2,0e,7e,b2,46,5f,e7,68,29,b4) },
        .s = { CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,4f) },
        .mask = { 0x01, 0x02, 0x03, 0x04 }
    },
    {
        // Compute R = s * S = (q - 3) * S, where x(S) = 0 and s even.
        .gx = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00) },
        .rx = { CCN256_C(4e,db,2f,8a,9b,1b,9d,31,dc,70,4c,71,e1,7c,d2,d5,1e,13,38,62,00,20,b5,fe,bb,70,3b,78,a5,25,57,b1) },
        .s = { CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,4e) },
        .mask = { 0x01, 0x02, 0x03, 0x04 }
    },
    {
        // Compute R = 1 * S, where x(S) = 0. The small scalar also sets a = 0.
        .gx = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00) },
        .rx = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00) },
        .s = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01) },
        .mask = { 0x01, 0x02, 0x03, 0x04 }
    },
    {
        // Compute R = 2 * S, where x(S) = 0. The small scalar also sets a = 0.
        .gx = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00) },
        .rx = { CCN256_C(c2,24,2b,e3,59,87,9e,cf,8a,92,b8,d9,79,c6,dc,96,d9,00,5a,00,23,6b,a2,0e,7e,b2,46,5f,e7,68,29,b4) },
        .s = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02) },
        .mask = { 0x01, 0x02, 0x03, 0x04 }
    },
    {
        // Compute R = 3 * S, where x(S) = 0. The small scalar also sets a = 0.
        .gx = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00) },
        .rx = { CCN256_C(4e,db,2f,8a,9b,1b,9d,31,dc,70,4c,71,e1,7c,d2,d5,1e,13,38,62,00,20,b5,fe,bb,70,3b,78,a5,25,57,b1) },
        .s = { CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,03) },
        .mask = { 0x01, 0x02, 0x03, 0x04 }
    }
};

const size_t ccec_mult_edge_case_test_vectors_num =
    CC_ARRAY_LEN(ccec_mult_edge_case_test_vectors);

static int ccec_mult_edge_case_tests(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    cc_size n = ccec_cp_n(cp);

    ccec_point_decl_cp(cp, G);
    ccec_point_decl_cp(cp, R);

    struct ccrng_sequence_state seq_rng;
    struct ccrng_state *rng = (struct ccrng_state *)&seq_rng;

    for (size_t i = 0; i < ccec_mult_edge_case_test_vectors_num; i++) {
        const struct ccec_mult_edge_case_test_vector *tv =
            &ccec_mult_edge_case_test_vectors[i];

        CC_DECL_WORKSPACE_TEST(ws);

        int rv = ccec_affine_point_from_x_ws(ws, cp, (ccec_affine_point_t)R, tv->gx);
        is(rv, CCERR_OK, "ccec_affine_point_from_x() failed");

        rv = ccec_projectify_ws(ws, cp, G, (ccec_const_affine_point_t)R, global_test_rng);
        is(rv, CCERR_OK, "ccec_projectify() failed");

        ccrng_sequence_init(&seq_rng, 4, tv->mask);

        rv = ccec_mult_blinded_ws(ws, cp, R, tv->s, G, rng);
        is(rv, CCERR_OK, "ccec_mult_blinded_ws() failed");

        rv = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)R, R);
        is(rv, CCERR_OK, "ccec_affinify() failed");

        ok_ccn_cmp(n, ccec_point_x(R, cp), tv->rx, "R = s * G");

        CC_FREE_WORKSPACE(ws);
    }

    return 0;
}

static void ccec_sign_error_tests(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    const struct ccdigest_info *di = get_digest(256);

    // Initialize a buffer which is long enough to hold a signature.
    size_t max_sig_len = ccec_sign_max_size(cp);
    uint8_t signature[max_sig_len];

    // Generate a secret key
    ccec_full_ctx_decl_cp(cp, sk);
    ccec_ctx_init(cp, sk);
    is(ccec_generate_key_fips(cp, global_test_rng, sk), CCERR_OK, "Generate FIPS");

    // Attempt to sign with a sig_len equal to 0: it will fail but sig_len should be updated.
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE] = { 0 };
    size_t sig_len = 0;
    is(ccec_sign(sk, di->output_size, digest, &sig_len, signature, global_test_rng),
       CCERR_BUFFER_TOO_SMALL,
       "ccec_sign: Buffer too small");
    isnt(sig_len, 0, "ccec_sign: sig_len updated");

    // Attempt to sign with a sig_len which is equal to `max_sig_len`: it will succeed.
    sig_len = max_sig_len;
    is(ccec_sign(sk, di->output_size, digest, &sig_len, signature, global_test_rng), CCERR_OK, "ccec_sign: Buffer large enough");

    // Cleanup!
    ccec_full_ctx_clear_cp(cp, sk);
}

static void ccec_sign_edge_cases_tests(void)
{
    // H(msg) (mod q)
    const cc_unit e[] = {
        CCN192_C(5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a)
    };

    // Private signing key
    const cc_unit x[] = {
        CCN192_C(f1,f2,f3,f4,f5,f6,f7,f8,f9,fa,fb,fc,fd,fe,ff,e1,e2,e3,e4,e5,e6,e7,e8,e9)
    };

    // Ephemeral key
    const cc_unit k[] = {
        CCN192_C(01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,11,12,13,14,15,16,17,18,19)
    };

    // x(k * G) = 0
    const cc_unit gxy1[] = {
        CCN192_C(47,db,ca,aa,34,eb,8c,fe,a3,22,40,1b,d4,68,0a,49,ab,b4,d2,ab,38,0e,55,40),
        CCN192_C(29,5a,e5,df,2f,49,56,0e,25,70,a5,68,63,c0,cc,20,65,c7,3a,44,3e,98,81,d1)
    };

    // x(k * G) = q = 0 (mod q)
    const cc_unit gxy2[] = {
        CCN192_C(e0,61,cf,86,34,a0,84,38,a5,ea,0f,0a,e5,f6,b4,ac,1c,cf,7f,91,75,b2,4b,06),
        CCN192_C(82,92,10,a4,68,c2,fa,ae,ec,1f,1e,66,4a,31,8d,22,56,2e,1c,a8,98,6f,b9,b6)
    };

    // x(k * G) = (q - e) / x. And so s = e + xr = q = 0 (mod q).
    const cc_unit gxy3[] = {
        CCN192_C(c0,9c,1d,b8,e0,b5,15,26,d6,1e,c6,5d,1d,bb,b3,b9,f7,1b,41,cc,c5,11,54,c6),
        CCN192_C(7f,e2,3f,53,93,d0,53,6d,f4,9e,cc,fc,3b,1a,d1,97,6c,f5,40,8f,6c,5d,67,35)
    };

    ccec_const_cp_t cp = ccec_cp_192();
    cc_size n = ccec_cp_n(cp);

    CC_DECL_WORKSPACE_TEST(ws);

    ccec_point_decl_cp(cp, G);
    cc_unit r[CCN192_N], s[CCN192_N], m[CCN192_N];
    ccn_seti(n, m, 1);

    int rv = ccec_projectify_ws(ws, cp, G, (ccec_const_affine_point_t)gxy1, global_test_rng);
    is(rv, CCERR_OK, "ccec_projectify() failed");

    // Check that r = 0, because x(k * G) = 0, is rejected.
    rv = ccec_sign_internal_inner_ws(ws, cp, e, x, k, G, m, r, s, global_test_rng);
    is(rv, CCERR_RETRY, "ccec_sign_internal_inner_ws() should request retry");

    rv = ccec_projectify_ws(ws, cp, G, (ccec_const_affine_point_t)gxy2, global_test_rng);
    is(rv, CCERR_OK, "ccec_projectify() failed");

    // Check that r = 0, because x(k * G) = 0 (mod q), is rejected.
    rv = ccec_sign_internal_inner_ws(ws, cp, e, x, k, G, m, r, s, global_test_rng);
    is(rv, CCERR_RETRY, "ccec_sign_internal_inner_ws() should request retry");

    rv = ccec_projectify_ws(ws, cp, G, (ccec_const_affine_point_t)gxy3, global_test_rng);
    is(rv, CCERR_OK, "ccec_projectify() failed");

    // Check that s = 0, because e + xr = q, is rejected.
    rv = ccec_sign_internal_inner_ws(ws, cp, e, x, k, G, m, r, s, global_test_rng);
    is(rv, CCERR_RETRY, "ccec_sign_internal_inner_ws() should request retry");

    CC_FREE_WORKSPACE(ws);
}

static void ccec_verify_edge_cases_tests(void)
{
    // H(msg) (mod q)
    const cc_unit e[] = {
        CCN256_C(5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a,5a)
    };

    const uint8_t h[] = {
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
    };

    // Private signing key
    const cc_unit d[] = {
        CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,10,00,00,00)
    };

    // x(d * G) = 0
    const cc_unit gx[] = {
        CCN256_C(76,62,c3,fc,5e,50,95,aa,43,bf,87,53,cf,b8,c0,f0,03,c2,4c,61,3a,30,57,9a,6b,0e,a0,7d,df,08,82,71)
    };

    ccec_const_cp_t cp = ccec_cp_256();
    cc_size n = ccec_cp_n(cp);

    CC_DECL_WORKSPACE_TEST(ws);

    ccec_point_decl_cp(cp, G_aff);
    ccec_point_decl_cp(cp, G_prj);

    // Import the custom generator / base point.
    int rv = ccec_affine_point_from_x_ws(ws, cp, (ccec_affine_point_t)G_aff, gx);
    is(rv, CCERR_OK, "ccec_affine_point_from_x() failed");

    rv = ccec_projectify_ws(ws, cp, G_prj, (ccec_const_affine_point_t)G_aff, global_test_rng);
    is(rv, CCERR_OK, "ccec_projectify() failed");

    // Compute the public key (d * G).
    ccec_pub_ctx_decl_cp(cp, pub);
    ccec_ctx_init(cp, pub);

    rv = ccec_make_pub_from_priv_ws(ws, cp, global_test_rng, d, (ccec_const_affine_point_t)G_aff, pub);
    is(rv, CCERR_OK, "ccec_make_pub_from_priv() failed");
    ok(ccn_is_zero(n, ccec_ctx_x(pub)), "x(d * G) should be zero");

    // Sign and verify.
    cc_unit r[CCN256_N], s[CCN256_N], m[CCN256_N], k[CCN256_N];
    ccn_random(n, k, global_test_rng);
    ccn_seti(n, m, 1); // Set mask := 1.

    rv = ccec_sign_internal_inner_ws(ws, cp, e, d, k, G_prj, m, r, s, global_test_rng);
    is(rv, CCERR_OK, "ccec_sign_internal_inner() failed");

    cc_fault_canary_t unused_fault_canary;
    rv = ccec_verify_internal_with_base_ws(ws, pub, sizeof(h), h, r, s, (ccec_const_affine_point_t)G_aff, unused_fault_canary);
    is(rv, CCERR_OK, "ccec_verify_internal() failed");

    CC_FREE_WORKSPACE(ws);
}

static void ccec_pairwise_consistency_tests(void)
{
    ccec_const_cp_t cp = ccec_cp_256();

    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);

    // Generate a new key pair.
    is(ccec_generate_key(cp, global_test_rng, key), CCERR_OK,
        "ccec_generate_key failed()");

    CC_DECL_WORKSPACE_TEST(ws);

    // Corrupt the public key.
    ccec_ctx_x(ccec_ctx_pub(key))[0] ^= 0x5a;

    isnt(ccec_pairwise_consistency_check_ws(ws, key, global_test_rng), CCERR_OK,
        "ccec_pairwise_consistency_check_ws() should've failed");

    isnt(ccecdh_pairwise_consistency_check_ws(ws, key, NULL, global_test_rng), CCERR_OK,
        "ccecdh_pairwise_consistency_check_ws() should've failed");

    ccec_ctx_x(ccec_ctx_pub(key))[0] ^= 0x5a;

    // Corrupt the private key.
    ccec_ctx_k(key)[0] ^= 0x5a;

    isnt(ccec_pairwise_consistency_check_ws(ws, key, global_test_rng), CCERR_OK,
        "ccec_pairwise_consistency_check_ws() should've failed");

    isnt(ccecdh_pairwise_consistency_check_ws(ws, key, NULL, global_test_rng), CCERR_OK,
        "ccecdh_pairwise_consistency_check_ws() should've failed");

    // Clear the private key.
    cc_size n = ccec_cp_n(cp);
    ccn_clear(n, ccec_ctx_k(key));

    isnt(ccec_pairwise_consistency_check_ws(ws, key, global_test_rng), CCERR_OK,
        "ccec_pairwise_consistency_check_ws() should've failed");

    isnt(ccecdh_pairwise_consistency_check_ws(ws, key, NULL, global_test_rng), CCERR_OK,
        "ccecdh_pairwise_consistency_check_ws() should've failed");

    // Set q as the private key.
    ccn_set(n, ccec_ctx_k(key), cczp_prime(ccec_cp_zq(cp)));

    isnt(ccec_pairwise_consistency_check_ws(ws, key, global_test_rng), CCERR_OK,
        "ccec_pairwise_consistency_check_ws() should've failed");

    isnt(ccecdh_pairwise_consistency_check_ws(ws, key, NULL, global_test_rng), CCERR_OK,
        "ccecdh_pairwise_consistency_check_ws() should've failed");

    CC_FREE_WORKSPACE(ws);
}

int ccec_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int ntests = 0;
    ntests += 6451 * 10; // ccec_random_tests
#if CCN_MULMOD_224_ASM
    ntests += 6451 * 2;  // ccec_random_tests
#endif
#if CCN_MULMOD_256_ASM
    if (ccec_cp_256_asm_if_available()) {
        ntests += 6451;  // ccec_random_tests
    }
#endif
#if CCN_MULMOD_384_ASM
    if (ccec_cp_384_asm_if_available()) {
        ntests += 6451;  // ccec_random_tests
    }
#endif
    ntests += 22;    // ccec_key_sizes_tests
    ntests += 82;    // eckeygen_tests
    ntests += 180;   // ecdsa_known_answer_tests
    ntests += 294;   // ecdsa_negative_tests
    ntests += 55;    // ecdh_known_answer_tests
    ntests += 56;    // ecdh_negative_tests
    ntests += 121;   // ECStaticGenTest
    ntests += 1289;  // ecwrapping_tests
    ntests += 18;    // ccec_diversify_pub_twin_tests
    ntests += 20;    // keyroll_tests
    ntests += 8 * 3; // ccec_test_xcoord_zero
    ntests += 50;    // ccec_scalar_tests
    ntests += 4;     // ccec_sign_error_tests
    ntests += 6;     // ccec_sign_edge_cases_tests
    ntests += 6;     // ccec_verify_edge_cases_tests
    ntests += ccec_mult_edge_case_test_vectors_num * 5; // ccec_mult_edge_case_tests
    ntests += 9;     // ccec_pairwise_consistency_tests
    plan_tests(ntests);

    if (verbose)
        diag("Key sizes Tests");
    ccec_key_sizes_tests();

    if (verbose)
        diag("Random EC Tests");
    ccec_random_tests();

    if (verbose)
        diag("KeyGen KATs");
    ok(eckeygen_tests(), "KeyGen KATs");

    if (verbose)
        diag("ECDSA KATs");
    ok(ecdsa_known_answer_tests(), "ECDSA KATs");

    if (verbose)
        diag("ECDSA Negative tests");
    ok(ecdsa_negative_tests(), "ECDSA Negative tests");

    if (verbose)
        diag("ECDH KATs");
    ok(ecdh_known_answer_tests(), "ECDH KATs");

    if (verbose)
        diag("ECDH Negative tests");
    ok(ecdh_negative_tests(), "ECDH Negative tests");

    if (verbose)
        diag("Static Gen Tests");
    ok(ECStaticGenTest(), "Generate Static EC Key Pairs");

    if (verbose)
        diag("EC Wrapping Tests");
    ok(ecwrapping_tests(), "EC Wrapping tests");

    if (verbose)
        diag("Public key diversification tests");
    is(ccec_diversify_pub_twin_tests(), 0, "Public key diversification");

    if (verbose)
        diag("Keyroll tests");
    ok(keyroll_tests(), "Keyroll tests");

    if (verbose)
        diag("Pairwise consistency tests");
    ccec_pairwise_consistency_tests();

    ccec_test_xcoord_zero();
    ccec_scalar_tests();
    ccec_mult_edge_case_tests();
    ccec_sign_error_tests();
    ccec_sign_edge_cases_tests();
    ccec_verify_edge_cases_tests();

    return 0;
}

#endif
