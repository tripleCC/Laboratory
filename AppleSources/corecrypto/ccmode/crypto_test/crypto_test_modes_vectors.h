/* Copyright (c) (2012,2014-2017,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CRYPTO_TEST_MODES_VECTORS_H_
#define _CORECRYPTO_CRYPTO_TEST_MODES_VECTORS_H_

// These are stock keys/IVs/blocks to encode - don't change them - add if you
// need more.
#define keystr64     "0001020304050607"
#define keystr128    "000102030405060708090a0b0c0d0e0f"
#define keystr128_2  "2b7e151628aed2a6abf7158809cf4f3c"
#define keystr192    "000102030405060708090a0b0c0d0e0f1011121314151617"
#define keystr256    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define keystr256_2    "000102030405060708090a0b0c0d0e0ff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
#define twkstr128    "0f0e0d0c0b0a09080706050403020100"
#define ivstr64      "0f0e0d0c0b0a0908"
#define ivstr128     "0f0e0d0c0b0a09080706050403020100"
#define ivstr128_2   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
#define ivstrff64    "0000000000000000ffffffffffffffff"
#define ivstrff128   "ffffffffffffffffffffffffffffffff"
#define ivstrff128_1 "fffffffffffffffeffffffffffffffff"
#define ivstrff128_2 "fffffffffffffffdffffffffffffffff"
#define zeroX1       "00"
#define zeroX16      "00000000000000000000000000000000"
#define zeroX32      "0000000000000000000000000000000000000000000000000000000000000000"
#define zeroX33      "000000000000000000000000000000000000000000000000000000000000000000"
#define zeroX64      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
#define aX21         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define aDataTest    "TEST"
#define END_VECTOR   {.keyStr=NULL}

ccsymmetric_test_vector aes_ecb_vectors[] = {
    { .keyStr=keystr128, .ptStr=zeroX16, .ctStr="c6a13b37878f5b826f4f8162a1c8d879"},
    { .keyStr=keystr128, .ptStr=zeroX32, .ctStr="c6a13b37878f5b826f4f8162a1c8d879c6a13b37878f5b826f4f8162a1c8d879"},
    { .keyStr=keystr128, .ptStr=zeroX64,
        .ctStr="c6a13b37878f5b826f4f8162a1c8d879c6a13b37878f5b826f4f8162a1c8d879c6a13b37878f5b826f4f8162a1c8d879"},
    END_VECTOR
};

ccsymmetric_test_vector aes_cbc_vectors[] = {
    { .keyStr=keystr128, .block_ivStr=ivstr128, .ptStr=zeroX16,
        .ctStr="20a9f992b44c5be8041ffcdc6cae996a"},
    { .keyStr=keystr128, .block_ivStr=ivstr128, .ptStr=zeroX32,
        .ctStr="20a9f992b44c5be8041ffcdc6cae996ae40e2d6f4762a0c584042b8bd534704b"},
    { .keyStr=keystr128, .block_ivStr=ivstr128, .ptStr=zeroX64,
        .ctStr="20a9f992b44c5be8041ffcdc6cae996ae40e2d6f4762a0c584042b8bd534704b8b9c1f12376c87fdb08b354e40418f9d"},
    END_VECTOR
};

ccsymmetric_test_vector aes_cfb_vectors[] = {
    { .keyStr=keystr128, .init_ivStr=ivstr128, .ptStr=zeroX1,
        .ctStr="20"},
    { .keyStr=keystr128, .init_ivStr=ivstr128, .ptStr=zeroX16,
        .ctStr="20a9f992b44c5be8041ffcdc6cae996a"},
    { .keyStr=keystr128, .init_ivStr=ivstr128, .ptStr=zeroX33,
        .ctStr="20a9f992b44c5be8041ffcdc6cae996ae40e2d6f4762a0c584042b8bd534704b8b"},
    END_VECTOR
};

ccsymmetric_test_vector aes_ofb_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr128, .ptStr=zeroX1, "20", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr128, .ptStr=zeroX16, "20a9f992b44c5be8041ffcdc6cae996a", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr128, .ptStr=zeroX33, "20a9f992b44c5be8041ffcdc6cae996ae40e2d6f4762a0c584042b8bd534704b8b", NULL },
    END_VECTOR
};

ccsymmetric_test_vector aes_xts_vectors[] = {
    { .keyStr=keystr128, twkstr128, ivstr128, ivstr128, .ptStr=zeroX16, "d79b5174ba20ccb8f0b52290fb8045b8", NULL },
    { .keyStr=keystr128, twkstr128, ivstr128, ivstr128, .ptStr=zeroX32, "d79b5174ba20ccb8f0b52290fb8045b82d21fa05363fe5ff6483b7fa02ffdcfc", NULL },
    { .keyStr=keystr128, twkstr128, ivstr128, ivstr128, .ptStr=zeroX64, "d79b5174ba20ccb8f0b52290fb8045b82d21fa05363fe5ff6483b7fa02ffdcfc47d4f82717d128a5d6b0846f5472b982", NULL },
    END_VECTOR
};

ccsymmetric_test_vector aes_cfb8_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr128, .ptStr=zeroX1, "20", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr128, .ptStr=zeroX16, "20850f3e23fb3645d633538f3bedcecc", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr128, .ptStr=zeroX33, "20850f3e23fb3645d633538f3bedceccf85db3f7e68cb4b72bb029404c755a0399", NULL },
    END_VECTOR
};

ccsymmetric_test_vector aes_gcm_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr128, .aDataStr=aDataTest, .ptStr=zeroX1, "9e", "c0b7b834467c01300eb37a2d94593a48" },
    { .keyStr=keystr128,.init_ivStr=ivstr128, .aDataStr=aDataTest, .ptStr=zeroX16, "9ea5433afafdaca2ac376b736ae44152", "bdaa4f10af822c61178783033143eed1" },
    { .keyStr=keystr128,.init_ivStr=ivstr128, .aDataStr=aDataTest, .ptStr=zeroX33, "9ea5433afafdaca2ac376b736ae44152a3f8f8f5d378d1a378be3175d28162b686", "1b11adfcfbec6fd1300a0290c3784049" },
#include "../test_vectors/aes_gcm_test_vectors_ossl.inc"
#include "../test_vectors/aes_gcm_test_vectors.inc"
    END_VECTOR
};

ccsymmetric_test_vector aes_siv_hmac_vectors[] = {
    {
        .keyStr = "01020304050607080102030405060708f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8",
        .init_ivStr = "",
        .ptStr = "706c61696e74657874206f6e6c792074657374",
        .ctStr = "171843cb97aa22ba9b0696fcc4f2b1e6ca2e9558d5d14a4fc0916ecd93fc1a3402bd48fa3fb0a1",
        .tagStr = "171843cb97aa22ba9b0696fcc4f2b1e6ca2e9558",
    },
    {
        .keyStr = "01020304050607080102030405060708f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8",
        .init_ivStr = "a1a2a3a4",
        .ptStr = "706c61696e74657874206f6e6c792074657374",
        .ctStr = "029205cc1bfe1bd7ed774e93729ba6de4935140775d962684300d4f72fca81d7cf1ac5f2a40238",
        .tagStr = "029205cc1bfe1bd7ed774e93729ba6de49351407",
    },
    {
        .keyStr = "01020304050607080102030405060708f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8",
        .aDataStr="b1b2b3b4",
        .init_ivStr = "a1a2a3a4",
        .ptStr = "706c61696e74657874206f6e6c792074657374",
        .ctStr = "31c8ade8f1de9c5d4fd434937df466d5c5d964562b70419403f8beae7511482af8ed748b507560",
        .tagStr = "31c8ade8f1de9c5d4fd434937df466d5c5d96456",
    },
    {
        .keyStr = "01020304050607080102030405060708f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8",
        .aDataStr="1234",
        .aData2Str="ff00ff00",
        .init_ivStr = "a1a2a3a4a5a6a7a8a9",
        .ptStr = "7465787420746f20656e6372797074",
        .ctStr = "298d9bbc83526652a9f765c869f99594ab5922865219f36ad8c57a917069eacf1ce430",
        .tagStr = "298d9bbc83526652a9f765c869f99594ab592286",
    },
    {
        .keyStr = "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        .aDataStr="00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        .aData2Str="102030405060708090a0",
        .init_ivStr = "09f911029d74e35bd84156c5635688c0",
        .ptStr = "37343638363937333230363937333230373336663664363532303730366336313639366537343635373837343230373436663230363536653633373237393730373432303735373336393665363732303533343935363264343134353533",
        .ctStr = "5c697cc54be7f3667686dd93f09b9f518ef98e401798462e70ab90f09dc7061f636fc1485f3166bd9fd438135e9379b9a0b46e727345dd862835cdc2d4f4b2d88de13cd322113e827b5eee74accd208c954a113c6fa384eb44c8138f4971d42e59aac4191c5561124b22050d3c0308eac8eba571b1d754dc6b97dcea",
        .tagStr = "5c697cc54be7f3667686dd93f09b9f518ef98e401798462e70ab90f09dc7",
    },
    {
        .keyStr = "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        .aDataStr="abcdef",
        .init_ivStr = "",
        .ptStr = "5468697320206973206120706c61696e746578742074657374",
        .ctStr = "493707763d421c1d20e6335216cba76be7ea5d5df17d5fbc8eb8e3c01146092a0185f5e2d637595dfee993bb951b73f1e8f4cd066f4cbec562",
        .tagStr = "493707763d421c1d20e6335216cba76be7ea5d5df17d5fbc8eb8e3c01146092a",
    },
    {
        .keyStr = "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        .init_ivStr = "",
        .ptStr = "54687573206973206120706c61696e746578742074657374",
        .ctStr = "09884a14537b758e40fc069b41f70731b3de824cb720f586f22d757a4a07855495a9a5f217a7cb6a27bc2520b625d5e43c0967bf39626c90",
        .tagStr = "09884a14537b758e40fc069b41f70731b3de824cb720f586f22d757a4a078554",
    },
    {
        .keyStr = "01020304050607080102030405060708f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8",
        .init_ivStr = "",
        .ptStr = "",
        .ctStr = "0f747919e29dbad3477e3bbd1be46f98b06faa17",
        .tagStr = "0f747919e29dbad3477e3bbd1be46f98b06faa17",
    },
    END_VECTOR,
};

ccsymmetric_test_vector aes_siv_vectors[] = {
    { .keyStr="2b7e151628aed2a6abf7158809cf4f3c00000000000000000000000000000000",
        .aDataStr="",
        .ptStr="",
        .ctStr="d9fa25e90d2fa42543939a85b543e233"},
    { .keyStr="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .aDataStr="",
        .ptStr="00",
        .ctStr="467bcb1a213d98c0701e6462c5eb68a4b0"},
    { .keyStr="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .aDataStr="",
        .ptStr=zeroX16,
        .ctStr="564e1b92eae574669a6c6fdc40ea65dc0a9fcd7254de2203ea39f4bfcccb47a7"},
    { .keyStr="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .aDataStr="",
        .ptStr=zeroX32,
        .ctStr="5efa698979ea590979635b5b176f46a0a35969de8c38afc217dd6b0ddcb86b01f3855c1348ef0a8c13a55540b1b2a8e5"},
    { .keyStr="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .aDataStr="",
        .ptStr="112233445566778899aabbccddee",
        .ctStr="f1c5fdeac1f15a26779c1501f9fb758827e946c669088ab06da58c5c831c"},

    /* http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv-test-vectors.txt */
    /* Test case #1 */
    { .keyStr="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .aDataStr="101112131415161718191a1b1c1d1e1f2021222324252627",
        .ptStr="112233445566778899aabbccddee",
        .ctStr="85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"},
    { .keyStr="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a6968f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0001020304050607",
        .aDataStr="101112131415161718191a1b1c1d1e1f2021222324252627",
        .ptStr="112233445566778899aabbccddee",
        .ctStr="02347811daa8b27491f24448932775a62af34a06ac0016e8ac284a5514f6"},
    { .keyStr="fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
                "6f6e6d6c6b6a69686766656463626160"
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                "000102030405060708090a0b0c0d0e0f",
        .aDataStr="101112131415161718191a1b1c1d1e1f2021222324252627",
        .ptStr="112233445566778899aabbccddee",
        .ctStr="f125274c598065cfc26b0e71575029088b035217e380cac8919ee800c126"},
    /* Test case #2 */
    { .keyStr="7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        .aDataStr="00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        .aData2Str="102030405060708090a0",
        .init_ivStr="09f911029d74e35bd84156c5635688c0",
        .ptStr="7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        .ctStr="7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"},
    { .keyStr="7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a6968404142434445464748494a4b4c4d4e4f5051525354555657",
        .aDataStr="00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        .aData2Str="102030405060708090a0",
        .init_ivStr="09f911029d74e35bd84156c5635688c0",
        .ptStr="7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        .ctStr="de40aa1e7180d519cb14308ea7f77586da09877c510f29651f42311ab728e95609e7de2994bdf80bb99bfaace31c4ec0d15ba6509f53f36ad725dcabc9e2a7"},
    { .keyStr="7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160404142434445464748494a4b4c4d4e4f505152535455565758595a5b5b5d5e5f",
        .aDataStr="00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        .aData2Str="102030405060708090a0",
        .init_ivStr="09f911029d74e35bd84156c5635688c0",
        .ptStr="7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        .ctStr="85b8167310038db7dc4692c0281ca35868181b2762f3c24f2efa5fb80cb143516ce6c434b898a6fd8eb98a418842f51f66fc67de43ac185a66dd72475bbb08"},
    END_VECTOR
};

ccsymmetric_test_vector aes_ccm_vectors[] = {
    // From NIST CAV tests.
    // AES 128
    { .keyStr="4bb3c4a4f893ad8c9bdc833c325d62b3", .init_ivStr="5a8aa485c316e9403aff",
        .ptStr="00", .ctStr="a1", .tagStr="246d32b7" },
    { .keyStr="4bb3c4a4f893ad8c9bdc833c325d62b3", .init_ivStr="5a8aa485c316e9403aff85",
        .ptStr="00", .ctStr="89", .tagStr="086723fd" },
    { .keyStr="4ae701103c63deca5b5a3939d7d05992", .init_ivStr="5a8aa485c316e9", .ptStr="", "", "02209f55" },
    { .keyStr="4bb3c4a4f893ad8c9bdc833c325d62b3", .init_ivStr="5a8aa485c316e9", .ptStr="", "", "75d582db43ce9b13ab4b6f7f14341330" },
    { .keyStr="4bb3c4a4f893ad8c9bdc833c325d62b3", .init_ivStr="5a8aa485c316e9403aff859fbb", .ptStr="", "", "90156f3f" },
    { .keyStr="19ebfde2d5468ba0a3031bde629b11fd", .init_ivStr="5a8aa485c316e9403aff859fbb", .ptStr="", "", "fb04dc5a44c6bb000f2440f5154364b4" },
    { .keyStr="19ebfde2d5468ba0a3031bde629b11fd", .init_ivStr="5a8aa485c316e9",
        .ptStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22", "a90e8ea44085ced791b2fdb7fd44b5cf0bd7d27718029bb7", "03e1fa6b" },
    { .keyStr="197afb02ffbd8f699dacae87094d5243", .init_ivStr="5a8aa485c316e9",
        .ptStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22", "24ab9eeb0e5508cae80074f1070ee188a637171860881f1f", "2d9a3fbc210595b7b8b1b41523111a8e" },
    { .keyStr="197afb02ffbd8f699dacae87094d5243", .init_ivStr="5a8aa485c316e9403aff859fbb",
        .ptStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697", "4a550134f94455979ec4bf89ad2bd80d25a77ae94e456134", "a3e138b9" },
    { .keyStr="90929a4b0ac65b350ad1591611fe4829", .init_ivStr="5a8aa485c316e9403aff859fbb",
        .ptStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697", "4bfe4e35784f0a65b545477e5e2f4bae0e1e6fa717eaf2cb", "6a9a970b9beb2ac1bd4fd62168f8378a" },
    { .keyStr="90929a4b0ac65b350ad1591611fe4829", .init_ivStr="5a8aa485c316e9", .aDataStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c", .ptStr="", "", "782e4318" },
    { .keyStr="6a798d7c5e1a72b43e20ad5c7b08567b", .init_ivStr="5a8aa485c316e9", .aDataStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c", .ptStr="", "", "41b476013f45e4a781f253a6f3b1e530" },
    { .keyStr="6a798d7c5e1a72b43e20ad5c7b08567b", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="", "", "9f69f24f" },
    { .keyStr="f9fdca4ac64fe7f014de0f43039c7571", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="", "", "1859ac36a40a6b28b34266253627797a" },
    { .keyStr="f9fdca4ac64fe7f014de0f43039c7571", .init_ivStr="5a8aa485c316e9", .aDataStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c", .ptStr="a265480ca88d5f536db0dc6abc40faf0d05be7a966977768", "6be31860ca271ef448de8f8d8b39346daf4b81d7e92d65b3", "38f125fa" },
    { .keyStr="a7aa635ea51b0bb20a092bd5573e728c", .init_ivStr="5a8aa485c316e9", .aDataStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c", .ptStr="a265480ca88d5f536db0dc6abc40faf0d05be7a966977768", "b351ab96b2e45515254558d5212673ee6c776d42dbca3b51", "2cf3a20b7fd7c49e6e79bef475c2906f" },
    { .keyStr="a7aa635ea51b0bb20a092bd5573e728c", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="8739b4bea1a099fe547499cbc6d1b13d849b8084c9b6acc5",
        "934f893824e880f743d196b22d1f340a52608155087bd28a", "c25e5329" },
    { .keyStr="26511fb51fcfa75cb4b44da75a6e5a0e", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="8739b4bea1a099fe547499cbc6d1b13d849b8084c9b6acc5", "50038b5fdd364ee747b70d00bd36840ece4ea19998123375", "c0a458bfcafa3b2609afe0f825cbf503" },
    // AES 192
    { .keyStr="c98ad7f38b2c7e970c9b965ec87a08208384718f78206c6c", .init_ivStr="5a8aa485c316e9", .ptStr="", "", "9d4b7f3b" },
    { .keyStr="4bb3c4a4f893ad8c9bdc833c325d62b3d3ad1bccf9282a65", .init_ivStr="5a8aa485c316e9", .ptStr="", "", "17223038fa99d53681ca1beabe78d1b4" },
    { .keyStr="4bb3c4a4f893ad8c9bdc833c325d62b3d3ad1bccf9282a65", .init_ivStr="5a8aa485c316e9403aff859fbb", .ptStr="", "", "fe69ed84" },
    { .keyStr="19ebfde2d5468ba0a3031bde629b11fd4094afcb205393fa", .init_ivStr="5a8aa485c316e9403aff859fbb", .ptStr="", "", "0c66a8e547ed4f8c2c9a9a1eb5d455b9" },
    { .keyStr="19ebfde2d5468ba0a3031bde629b11fd4094afcb205393fa", .init_ivStr="5a8aa485c316e9", .ptStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22", "411986d04d6463100bff03f7d0bde7ea2c3488784378138c", "ddc93a54" },
    { .keyStr="197afb02ffbd8f699dacae87094d524324576b99844f75e1", .init_ivStr="5a8aa485c316e9", .ptStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22", "cba4b4aeb85f0492fd8d905c4a6d8233139833373ef188a8", "c5a5ebecf7ac8607fe412189e83d9d20" },
    { .keyStr="197afb02ffbd8f699dacae87094d524324576b99844f75e1", .init_ivStr="5a8aa485c316e9403aff859fbb", .ptStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697",
        "042653c674ef2a90f7fb11d30848e530ae59478f1051633a", "34fad277" },
    { .keyStr="90929a4b0ac65b350ad1591611fe48297e03956f6083e451", .init_ivStr="5a8aa485c316e9403aff859fbb", .ptStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697",
        "a5b7d8cca2069908d1ed88e6a9fe2c9bede3131dad54671e", "a7ade30a07d185692ab0ebdf4c78cf7a" },
    { .keyStr="90929a4b0ac65b350ad1591611fe48297e03956f6083e451", .init_ivStr="5a8aa485c316e9", .aDataStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c", .ptStr="", "", "1d089a5f" },
    { .keyStr="6a798d7c5e1a72b43e20ad5c7b08567b12ab744b61c070e2", .init_ivStr="5a8aa485c316e9", .aDataStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c", .ptStr="", "", "5280a2137fee3deefcfe9b63a1199fb3" },
    { .keyStr="6a798d7c5e1a72b43e20ad5c7b08567b12ab744b61c070e2", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="", "", "5e0eaebd" },
    { .keyStr="f9fdca4ac64fe7f014de0f43039c757194d544ce5d15eed4", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="", "", "d07ccf9fdc3d33aa94cda3d230da707c" },
    { .keyStr="f9fdca4ac64fe7f014de0f43039c757194d544ce5d15eed4", .init_ivStr="5a8aa485c316e9", .aDataStr="3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c", .ptStr="a265480ca88d5f536db0dc6abc40faf0d05be7a966977768", "9f6ca4af9b159148c889a6584d1183ea26e2614874b05045", "75dea8d1" },
    { .keyStr="a7aa635ea51b0bb20a092bd5573e728ccd4b3e8cdd2ab33d", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="8739b4bea1a099fe547499cbc6d1b13d849b8084c9b6acc5", "16e543d0e20615ff0df15acd9927ddfe40668a54bb854ccc", "c25e9fce" },
    { .keyStr="26511fb51fcfa75cb4b44da75a6e5a0eb8d9c8f3b906f886", .init_ivStr="5a8aa485c316e9403aff859fbb", .aDataStr="a16a2e741f1cd9717285b6d882c1fc53655e9773761ad697a7ee6410184c7982", .ptStr="8739b4bea1a099fe547499cbc6d1b13d849b8084c9b6acc5", "c5b0b2ef17498c5570eb335df4588032958ba3d69bf6f317", "8464a6f7fa2b76744e8e8d95691cecb8" },
    // AES 256
    { .keyStr="eda32f751456e33195f1f499cf2dc7c97ea127b6d488f211ccc5126fbb24afa6", .init_ivStr="a544218dadd3c1", .ptStr="", "", "469c90bb" },
    { .keyStr="e1b8a927a95efe94656677b692662000278b441c79e879dd5c0ddc758bdc9ee8", .init_ivStr="a544218dadd3c1", .ptStr="", "", "8207eb14d33855a52acceed17dbcbf6e" },
    { .keyStr="e1b8a927a95efe94656677b692662000278b441c79e879dd5c0ddc758bdc9ee8", .init_ivStr="a544218dadd3c10583db49cf39", .ptStr="", "", "8a19a133" },
    { .keyStr="af063639e66c284083c5cf72b70d8bc277f5978e80d9322d99f2fdc718cda569", .init_ivStr="a544218dadd3c10583db49cf39", .ptStr="", "", "97e1a8dd4259ccd2e431e057b0397fcf" },
    { .keyStr="af063639e66c284083c5cf72b70d8bc277f5978e80d9322d99f2fdc718cda569", .init_ivStr="a544218dadd3c1", .ptStr="d3d5424e20fbec43ae495353ed830271515ab104f8860c98", "64a1341679972dc5869fcf69b19d5c5ea50aa0b5e985f5b7", "22aa8d59" },
    { .keyStr="f7079dfa3b5c7b056347d7e437bcded683abd6e2c9e069d333284082cbb5d453", .init_ivStr="a544218dadd3c1", .ptStr="d3d5424e20fbec43ae495353ed830271515ab104f8860c98", "bc51c3925a960e7732533e4ef3a4f69ee6826de952bcb0fd", "374f3bb6db8377ebfc79674858c4f305" },
    { .keyStr="f7079dfa3b5c7b056347d7e437bcded683abd6e2c9e069d333284082cbb5d453", .init_ivStr="a544218dadd3c10583db49cf39", .ptStr="3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e",
        "63e00d30e4b08fd2a1cc8d70fab327b2368e77a93be4f412", "3d14fb3f" },
    { .keyStr="1b0e8df63c57f05d9ac457575ea764524b8610ae5164e6215f426f5a7ae6ede4", .init_ivStr="a544218dadd3c10583db49cf39", .ptStr="3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e",
        "f0050ad16392021a3f40207bed3521fb1e9f808f49830c42", "3a578d179902f912f9ea1afbce1120b3" },
    { .keyStr="1b0e8df63c57f05d9ac457575ea764524b8610ae5164e6215f426f5a7ae6ede4", .init_ivStr="a544218dadd3c1", .aDataStr="d3d5424e20fbec43ae495353ed830271515ab104f8860c988d15b6d36c038eab", .ptStr="", "", "92d00fbe" },
    { .keyStr="a4bc10b1a62c96d459fbaf3a5aa3face7313bb9e1253e696f96a7a8e36801088", .init_ivStr="a544218dadd3c1", .aDataStr="d3d5424e20fbec43ae495353ed830271515ab104f8860c988d15b6d36c038eab", .ptStr="", "", "93af11a08379eb37a16aa2837f09d69d" },
    { .keyStr="a4bc10b1a62c96d459fbaf3a5aa3face7313bb9e1253e696f96a7a8e36801088", .init_ivStr="a544218dadd3c10583db49cf39", .aDataStr="3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e09a1005e024f6907", .ptStr="", "", "866d4227" },
    { .keyStr="8c5cf3457ff22228c39c051c4e05ed4093657eb303f859a9d4b0f8be0127d88a", .init_ivStr="a544218dadd3c10583db49cf39", .aDataStr="3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e09a1005e024f6907", .ptStr="", "", "867b0d87cf6e0f718200a97b4f6d5ad5" },
    { .keyStr="8c5cf3457ff22228c39c051c4e05ed4093657eb303f859a9d4b0f8be0127d88a", .init_ivStr="a544218dadd3c1", .aDataStr="d3d5424e20fbec43ae495353ed830271515ab104f8860c988d15b6d36c038eab", .ptStr="78c46e3249ca28e1ef0531d80fd37c124d9aecb7be6668e3", "c2fe12658139f5d0dd22cadf2e901695b579302a72fc5608", "3ebc7720" },
    { .keyStr="705334e30f53dd2f92d190d2c1437c8772f940c55aa35e562214ed45bd458ffe", .init_ivStr="a544218dadd3c1", .aDataStr="d3d5424e20fbec43ae495353ed830271515ab104f8860c988d15b6d36c038eab", .ptStr="78c46e3249ca28e1ef0531d80fd37c124d9aecb7be6668e3", "3341168eb8c48468c414347fb08f71d2086f7c2d1bd581ce", "1ac68bd42f5ec7fa7e068cc0ecd79c2a" },
    { .keyStr="705334e30f53dd2f92d190d2c1437c8772f940c55aa35e562214ed45bd458ffe", .init_ivStr="a544218dadd3c10583db49cf39", .aDataStr="3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e09a1005e024f6907", .ptStr="e8de970f6ee8e80ede933581b5bcf4d837e2b72baa8b00c3", "c0ea400b599561e7905b99262b4565d5c3dc49fad84d7c69", "ef891339" },
    { .keyStr="314a202f836f9f257e22d8c11757832ae5131d357a72df88f3eff0ffcee0da4e", .init_ivStr="a544218dadd3c10583db49cf39", .aDataStr="3c0e2815d37d844f7ac240ba9d6e3a0b2a86f706e885959e09a1005e024f6907", .ptStr="e8de970f6ee8e80ede933581b5bcf4d837e2b72baa8b00c3", "8d34cdca37ce77be68f65baf3382e31efa693e63f914a781", "367f30f2eaad8c063ca50795acd90203" },
    END_VECTOR
};

ccsymmetric_test_vector des_ecb_vectors[] = {
    #include  "../../ccmode/test_vectors/des_ecb_crypto_test_vectors.inc"
    #include  "../../ccmode/test_vectors/des_ecb_xcunit_tests.inc"
    END_VECTOR
};

ccsymmetric_test_vector des_cbc_vectors[] = {
    { .keyStr=keystr64,.block_ivStr=ivstr64, .ptStr=zeroX16, "af342d1acd53c72120a127bead351d12", NULL },
    { .keyStr=keystr64,.block_ivStr=ivstr64, .ptStr=zeroX32, "af342d1acd53c72120a127bead351d125afe64feb410e48667671ed946a622a6", NULL },
    { .keyStr=keystr64,.block_ivStr=ivstr64, .ptStr=zeroX64, "af342d1acd53c72120a127bead351d125afe64feb410e48667671ed946a622a619e7c39e2e725fd9338b3d69b8ddd450", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des_cfb_vectors[] = {
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX1, "af", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX16, "af342d1acd53c72120a127bead351d12", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX33, "af342d1acd53c72120a127bead351d125afe64feb410e48667671ed946a622a619", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des_ctr_vectors[] = {
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX1, "af", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX16, "af342d1acd53c72146f42ae448a624b6", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX33, "af342d1acd53c72146f42ae448a624b68e03b9d1e04cff967a4261be15103f910a", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des_ofb_vectors[] = {
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX1, "af", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX16, "af342d1acd53c72120a127bead351d12", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX33, "af342d1acd53c72120a127bead351d125afe64feb410e48667671ed946a622a619", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des_cfb8_vectors[] = {
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX1, "af", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX16, "af445cfa60ae8dc4545ac82c1cf7015e", NULL },
    { .keyStr=keystr64,.init_ivStr=ivstr64, .ptStr=zeroX33, "af445cfa60ae8dc4545ac82c1cf7015e53b2c0ccbcbd94da460087a074525d6e3d", NULL },
    END_VECTOR
};


ccsymmetric_test_vector des3_ecb_vectors[] = {
    { .keyStr=keystr192,.ptStr=zeroX16, "894bc3085426a441894bc3085426a441", NULL },
    { .keyStr=keystr192,.ptStr=zeroX32, "894bc3085426a441894bc3085426a441894bc3085426a441894bc3085426a441", NULL },
    { .keyStr=keystr192,.ptStr=zeroX64, "894bc3085426a441894bc3085426a441894bc3085426a441894bc3085426a441894bc3085426a441894bc3085426a441", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des3_cbc_vectors[] = {
    #include "../../ccmode/test_vectors/3des_cbc_vectors_crypto_test_vectors.inc"
    // Tests below have been ported form old XCunit tests
    #include "../../ccmode/test_vectors/TCBCMMT1.inc"
    #include "../../ccmode/test_vectors/TCBCMMT2.inc"
    #include "../../ccmode/test_vectors/TCBCMMT3.inc"
    #include "../../ccmode/test_vectors/TCBCinvperm.inc"
    #include "../../ccmode/test_vectors/TCBCpermop.inc"
    #include "../../ccmode/test_vectors/TCBCsubtab.inc"
    #include "../../ccmode/test_vectors/TCBCvarkey.inc"
    #include "../../ccmode/test_vectors/TCBCvartext.inc"
    END_VECTOR
};

ccsymmetric_test_vector des3_cfb_vectors[] = {
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX1, "a3", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX16, "a38feed967ba6cfe6f2417e54f7b5260", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX33, "a38feed967ba6cfe6f2417e54f7b5260ed6430b817a27ce3746407017aa59d776a", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des3_ctr_vectors[] = {
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX1, "a3", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX16, "a38feed967ba6cfe6488374dff61b9fd", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX33, "a38feed967ba6cfe6488374dff61b9fd4362abfc77bb2e0c8c5592fedbbd5b5930", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des3_ofb_vectors[] = {
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX1, "a3", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX16, "a38feed967ba6cfe6f2417e54f7b5260", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX33, "a38feed967ba6cfe6f2417e54f7b5260ed6430b817a27ce3746407017aa59d776a", NULL },
    END_VECTOR
};

ccsymmetric_test_vector des3_cfb8_vectors[] = {
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX1, "a3", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX16, "a3d313e297cd33235df0692276ec1aeb", NULL },
    { .keyStr=keystr192,.init_ivStr=ivstr64, .ptStr=zeroX33, "a3d313e297cd33235df0692276ec1aeb578b180d77557126d9beb8eb5bacba56de", NULL },
    END_VECTOR
};



ccsymmetric_test_vector cast_ecb_vectors[] = {
    { .keyStr=keystr128, .ptStr=zeroX16, "98ed0a15f0337b1b98ed0a15f0337b1b", NULL },
    { .keyStr=keystr128, .ptStr=zeroX32, "98ed0a15f0337b1b98ed0a15f0337b1b98ed0a15f0337b1b98ed0a15f0337b1b", NULL },
    { .keyStr=keystr128, .ptStr=zeroX64, "98ed0a15f0337b1b98ed0a15f0337b1b98ed0a15f0337b1b98ed0a15f0337b1b98ed0a15f0337b1b98ed0a15f0337b1b", NULL },
    // The next three vectors are from RFC2144
    { .keyStr="0123456712345678234567893456789A", .ptStr="0123456789ABCDEF", "238B4FE5847E44B2", NULL },
    { .keyStr="01234567123456782345", .ptStr="0123456789ABCDEF", "EB6A711A2C02271B", NULL },
    { .keyStr="0123456712", .ptStr="0123456789ABCDEF", "7AC816D16E9B302E", NULL },
    END_VECTOR
};

ccsymmetric_test_vector cast_cbc_vectors[] = {
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX16, "c5546bdc50a400f7722c685d84ec285f", NULL },
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX32, "c5546bdc50a400f7722c685d84ec285fe6bab3d5f479bd6312dae235be573946", NULL },
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX64, "c5546bdc50a400f7722c685d84ec285fe6bab3d5f479bd6312dae235be57394603d3e828a3e1e54785e3e594c0649fb5", NULL },
    END_VECTOR
};

ccsymmetric_test_vector cast_cfb_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "c5", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "c5546bdc50a400f7722c685d84ec285f", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "c5546bdc50a400f7722c685d84ec285fe6bab3d5f479bd6312dae235be57394603", NULL },
    END_VECTOR
};

ccsymmetric_test_vector cast_ctr_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "c5", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "c5546bdc50a400f798ab6de151e19203", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "c5546bdc50a400f798ab6de151e19203d74a3e9a0d82be553dbe9089fcf2a94b61", NULL },
    END_VECTOR
};

ccsymmetric_test_vector cast_ofb_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "c5", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "c5546bdc50a400f7722c685d84ec285f", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "c5546bdc50a400f7722c685d84ec285fe6bab3d5f479bd6312dae235be57394603", NULL },
    END_VECTOR
};

ccsymmetric_test_vector cast_cfb8_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "c5", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "c5f272819cbc9557d5921753269e5020", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "c5f272819cbc9557d5921753269e50205a6d7ff7b07737391493963e5b10bf78b8", NULL },
    END_VECTOR
};



ccsymmetric_test_vector rc2_ecb_vectors[] = {
    { .keyStr=keystr128, .ptStr=zeroX16, "9c4bfe6dfe739c2b9c4bfe6dfe739c2b", NULL },
    { .keyStr=keystr128, .ptStr=zeroX32, "9c4bfe6dfe739c2b9c4bfe6dfe739c2b9c4bfe6dfe739c2b9c4bfe6dfe739c2b", NULL },
    { .keyStr=keystr128, .ptStr=zeroX64, "9c4bfe6dfe739c2b9c4bfe6dfe739c2b9c4bfe6dfe739c2b9c4bfe6dfe739c2b9c4bfe6dfe739c2b9c4bfe6dfe739c2b", NULL },
    END_VECTOR
};

ccsymmetric_test_vector rc2_cbc_vectors[] = {
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX16, "b2df22134258d3566c964020e5918809", NULL },
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX32, "b2df22134258d3566c964020e59188099e072f766fcf49e63eddcd81de64da42", NULL },
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX64, "b2df22134258d3566c964020e59188099e072f766fcf49e63eddcd81de64da42b5f45750d48f3d191a2e806ba027d624", NULL },
    END_VECTOR
};

ccsymmetric_test_vector rc2_cfb_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "b2", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "b2df22134258d3566c964020e5918809", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "b2df22134258d3566c964020e59188099e072f766fcf49e63eddcd81de64da42b5", NULL },
    END_VECTOR
};

ccsymmetric_test_vector rc2_ctr_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "b2", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "b2df22134258d35691a96187855ad58d", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "b2df22134258d35691a96187855ad58d2d28e7df3551b65866ff40405cdc572b92", NULL },
    END_VECTOR
};

ccsymmetric_test_vector rc2_ofb_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "b2", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "b2df22134258d3566c964020e5918809", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "b2df22134258d3566c964020e59188099e072f766fcf49e63eddcd81de64da42b5", NULL },
    END_VECTOR
};

ccsymmetric_test_vector rc2_cfb8_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "b2", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "b211de15aecd4e5331065b799f763d09", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "b211de15aecd4e5331065b799f763d098d3d8beefa35fc83cc6a4ed9ad1a08a7ac", NULL },
    END_VECTOR
};



ccsymmetric_test_vector blowfish_ecb_vectors[] = {
    { .keyStr=keystr128,.ptStr=zeroX16, "b995f24ddfe87bf0b995f24ddfe87bf0", NULL },
    { .keyStr=keystr128,.ptStr=zeroX32, "b995f24ddfe87bf0b995f24ddfe87bf0b995f24ddfe87bf0b995f24ddfe87bf0", NULL },
    { .keyStr=keystr128,.ptStr=zeroX64, "b995f24ddfe87bf0b995f24ddfe87bf0b995f24ddfe87bf0b995f24ddfe87bf0b995f24ddfe87bf0b995f24ddfe87bf0", NULL },
    { .keyStr="0000000000000000", .ptStr="0000000000000000", "4EF997456198DD78", NULL},
    { .keyStr="FFFFFFFFFFFFFFFF", .ptStr="FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A", NULL},
    { .keyStr="3000000000000000", .ptStr="1000000000000001", "7D856F9A613063F2", NULL},
    END_VECTOR
};

ccsymmetric_test_vector blowfish_cbc_vectors[] = {
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX16, "16c5049f3e3ad3562cac4e5b98dbed08", NULL },
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX32, "16c5049f3e3ad3562cac4e5b98dbed08e901bc04d1b2d84f00e215b262c917dd", NULL },
    { .keyStr=keystr128,.block_ivStr=ivstr64, .ptStr=zeroX64, "16c5049f3e3ad3562cac4e5b98dbed08e901bc04d1b2d84f00e215b262c917ddfbf81ba83106bb09f2ae30aeffa6a91f", NULL },
    END_VECTOR
};

ccsymmetric_test_vector blowfish_cfb_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "16", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "16c5049f3e3ad3562cac4e5b98dbed08", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "16c5049f3e3ad3562cac4e5b98dbed08e901bc04d1b2d84f00e215b262c917ddfb", NULL },
    END_VECTOR
};

ccsymmetric_test_vector blowfish_ctr_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "16", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "16c5049f3e3ad356a3ed4d1f897c44f5", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "16c5049f3e3ad356a3ed4d1f897c44f5189eef6feafcd0c959f52c8eaa2a7c7fa8", NULL },
    END_VECTOR
};

ccsymmetric_test_vector blowfish_ofb_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "16", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "16c5049f3e3ad3562cac4e5b98dbed08", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "16c5049f3e3ad3562cac4e5b98dbed08e901bc04d1b2d84f00e215b262c917ddfb", NULL },
    END_VECTOR
};

ccsymmetric_test_vector blowfish_cfb8_vectors[] = {
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX1, "16", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX16, "16ac9f958a247fb9aa5058b45b86eb80", NULL },
    { .keyStr=keystr128,.init_ivStr=ivstr64, .ptStr=zeroX33, "16ac9f958a247fb9aa5058b45b86eb80013303a7eb91747a3387b9dbc18787b497", NULL },
    END_VECTOR
};

#endif /* _CORECRYPTO_CRYPTO_TEST_MODES_VECTORS_H_ */
