/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#define STANDALONE 0

#if (STANDALONE == 0)
#include "crypto_test_ec.h"
#include "testmore.h"
#endif

#include <corecrypto/ccansikdf.h>
#include <corecrypto/ccec.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccsha2.h>

#if (STANDALONE == 1)
#include <stdio.h>

static int ok(bool cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAILURE: %s\n", msg);
    }

    return (int)cond;
}

#define is(a, b, msg) ok(a == b, msg)
#define isnt(a, b, msg) ok(a != b, msg)
#define ok_memcmp(a, b, len, msg) ok(memcmp(a, b, len) == 0, msg)

int keyroll_tests(void);

int main(int argc, const char *const *argv)
{
    fprintf(stderr, "Running keyroll tests...\n");
    int rv = keyroll_tests();
    fprintf(stderr, "\nDone! (Successful if no errors reported.)\n");
    return rv ? 0 : 1;
}
#endif

const uint8_t KDF_LABEL_UPDATE[] = "update";
const uint8_t KDF_LABEL_DIVERSIFY[] = "diversify";
const uint8_t KDF_LABEL_INTERMEDIATE[] = "intermediate";
const uint8_t KDF_LABEL_COMMAND[] = "command";
const uint8_t KDF_LABEL_STATUS[] = "status";

const uint8_t MAC_LABEL_NEAROWNER[] = "NearOwnerAuthToken";

/*
 * [SageMath]
 *  p224 = 2^224 - 2^96 + 1
 *  b224 = 18958286285566608000408668544493926415504680968679321075787234672564
 *  gx = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21
 *  gy = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34
 *  d = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b
 *
 *  FF = GF(p224)
 *  EC = EllipticCurve([FF(p224 - 3), FF(b224)])
 *  G = EC(FF(gx), FF(gy))
 *  P = d*G
 */
const uint8_t P[85] = {
    0x04,
    0x0b, 0x75, 0x43, 0x51, 0x20, 0xc3, 0x61, 0x42,
    0x8b, 0xa8, 0xb6, 0xfa, 0x21, 0x9d, 0x65, 0xb7,
    0xdc, 0xd9, 0xb5, 0x13, 0x02, 0xd4, 0x00, 0x09,
    0xca, 0x7c, 0x6b, 0xba,
    0x15, 0x24, 0x09, 0x0e, 0xc8, 0x34, 0x48, 0xb4,
    0x1a, 0x21, 0x3e, 0x93, 0xd0, 0xee, 0x7b, 0x94,
    0xba, 0x15, 0xfa, 0x49, 0xaf, 0xf3, 0xf6, 0x88,
    0x63, 0xb1, 0xff, 0x4b,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b
};

const uint8_t SK_0[32] = {
    0xb9, 0xc6, 0xa6, 0xd7, 0x9a, 0x5f, 0x60, 0xce,
    0x9c, 0x3a, 0x0a, 0xf3, 0x8c, 0x80, 0x74, 0xdd,
    0x4f, 0x57, 0x8e, 0xca, 0xce, 0x6d, 0xd7, 0xc5,
    0xff, 0x92, 0x13, 0xb8, 0x35, 0x34, 0x6a, 0x73
};

/*
 * [Python]
 * >>> import hashlib
 * >>> m = hashlib.sha256()
 * >>> m.update("b9c6a6d79a5f60ce9c3a0af38c8074dd4f578ecace6dd7c5ff9213b835346a73".decode("hex"))
 * >>> m.update("00000001".decode("hex"))
 * >>> m.update(b"update")
 * >>> m.hexdigest()
 * '41c86f894c53a546d0f8f7f31bb4f91968f5102b6d8e74994fca9e042744bc3b'
 */
const uint8_t SK_1[32] = {
    0x41, 0xc8, 0x6f, 0x89, 0x4c, 0x53, 0xa5, 0x46,
    0xd0, 0xf8, 0xf7, 0xf3, 0x1b, 0xb4, 0xf9, 0x19,
    0x68, 0xf5, 0x10, 0x2b, 0x6d, 0x8e, 0x74, 0x99,
    0x4f, 0xca, 0x9e, 0x04, 0x27, 0x44, 0xbc, 0x3b
};

/*
 * [Python]
 * >>> import hashlib
 * >>> m = hashlib.sha256()
 * >>> m.update("41c86f894c53a546d0f8f7f31bb4f91968f5102b6d8e74994fca9e042744bc3b".decode("hex"))
 * >>> m.update("00000001".decode("hex"))
 * >>> m.update(b"diversify")
 * >>> m.hexdigest()
 * '37c61399ea18a8bb2a34e290a8c1967d4e1e8f002eb87fbdac30dbeba86990fd'
 *
 * >>> m = hashlib.sha256()
 * >>> m.update("41c86f894c53a546d0f8f7f31bb4f91968f5102b6d8e74994fca9e042744bc3b".decode("hex"))
 * >>> m.update("00000002".decode("hex"))
 * >>> m.update(b"diversify")
 * >>> m.hexdigest()
 * 'dca287c86bb6026aca217c4e1712dffe4fd9a38ccbb7081ad5c2a5f9ce3e4d09'
 *
 * >>> m = hashlib.sha256()
 * >>> m.update("41c86f894c53a546d0f8f7f31bb4f91968f5102b6d8e74994fca9e042744bc3b".decode("hex"))
 * >>> m.update("00000003".decode("hex"))
 * >>> m.update(b"diversify")
 * >>> m.hexdigest()
 * '6023fa3a731960dacfa1a3e33bbd48077b72a1e76fb802b88e82ce2dfc9a18de'
 */
const uint8_t AT_1[72] = {
    0x37, 0xc6, 0x13, 0x99, 0xea, 0x18, 0xa8, 0xbb,
    0x2a, 0x34, 0xe2, 0x90, 0xa8, 0xc1, 0x96, 0x7d,
    0x4e, 0x1e, 0x8f, 0x00, 0x2e, 0xb8, 0x7f, 0xbd,
    0xac, 0x30, 0xdb, 0xeb, 0xa8, 0x69, 0x90, 0xfd,
    0xdc, 0xa2, 0x87, 0xc8, 0x6b, 0xb6, 0x02, 0x6a,
    0xca, 0x21, 0x7c, 0x4e, 0x17, 0x12, 0xdf, 0xfe,
    0x4f, 0xd9, 0xa3, 0x8c, 0xcb, 0xb7, 0x08, 0x1a,
    0xd5, 0xc2, 0xa5, 0xf9, 0xce, 0x3e, 0x4d, 0x09,
    0x60, 0x23, 0xfa, 0x3a, 0x73, 0x19, 0x60, 0xda
};

/*
 * [SageMath]
 *  n = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d
 *  u = (0x37c61399ea18a8bb2a34e290a8c1967d4e1e8f002eb87fbdac30dbeba86990fddca287c8 % (n - 1)) + 1
 *  v = (0x6bb6026aca217c4e1712dffe4fd9a38ccbb7081ad5c2a5f9ce3e4d096023fa3a731960da % (n - 1)) + 1
 *
 *  u*P + v*G
 */
const uint8_t x_P_1[28] = {
    0x3a, 0xcd, 0x35, 0x31, 0x34, 0x74, 0xf5, 0xbc,
    0x85, 0x17, 0x6e, 0x38, 0x52, 0x03, 0x30, 0x13,
    0xe1, 0x4c, 0x88, 0xc8, 0x8c, 0xe7, 0x3d, 0xcb,
    0xc9, 0xfb, 0x98, 0xf0
};

/*
 * [Python]
 * >>> import hashlib
 * >>> m = hashlib.sha256()
 * >>> m.update("41c86f894c53a546d0f8f7f31bb4f91968f5102b6d8e74994fca9e042744bc3b".decode("hex"))
 * >>> m.update("00000001".decode("hex"))
 * >>> m.update(b"intermediate")
 * >>> m.hexdigest()
 * '2c555e615836daa92b22b83f1874924d511f67b6886cd0c7d8f92ebf3b1ab4fe'
 */
const uint8_t IK_1[32] = {
    0x2c, 0x55, 0x5e, 0x61, 0x58, 0x36, 0xda, 0xa9,
    0x2b, 0x22, 0xb8, 0x3f, 0x18, 0x74, 0x92, 0x4d,
    0x51, 0x1f, 0x67, 0xb6, 0x88, 0x6c, 0xd0, 0xc7,
    0xd8, 0xf9, 0x2e, 0xbf, 0x3b, 0x1a, 0xb4, 0xfe
};

/*
 * [Python]
 * >>> import hashlib
 * >>> m = hashlib.sha256()
 * >>> m.update("2c555e615836daa92b22b83f1874924d511f67b6886cd0c7d8f92ebf3b1ab4fe".decode("hex"))
 * >>> m.update("00000001".decode("hex"))
 * >>> m.update(b"command")
 * >>> m.hexdigest()
 * 'a0fe5d2a5472c2f79195ee6ec36cf394355ae7899e7b28d128939a765fda0929'
 */
const uint8_t CK_1[32] = {
    0xa0, 0xfe, 0x5d, 0x2a, 0x54, 0x72, 0xc2, 0xf7,
    0x91, 0x95, 0xee, 0x6e, 0xc3, 0x6c, 0xf3, 0x94,
    0x35, 0x5a, 0xe7, 0x89, 0x9e, 0x7b, 0x28, 0xd1,
    0x28, 0x93, 0x9a, 0x76, 0x5f, 0xda, 0x09, 0x29
};

/*
 * [Python]
 * >>> import hmac
 * >>> ck = "a0fe5d2a5472c2f79195ee6ec36cf394355ae7899e7b28d128939a765fda0929".decode("hex")
 * >>> xp = "3acd35313474f5bc85176e3852033013e14c88c88ce73dcbc9fb98f0".decode("hex")
 * >>> h = hmac.new(ck, xp + b"NearOwnerAuthToken", digestmod=hashlib.sha256)
 * 'b8db0e1034189f49f8e2887ef73759ae176dfefaa5f82474d5a3e64c4a38284b'
 */
const uint8_t NOAT_1[6] = {
    0xb8, 0xdb, 0x0e, 0x10, 0x34, 0x18
};

/*
 * [Python]
 * >>> import hashlib
 * >>> m = hashlib.sha256()
 * >>> m.update("2c555e615836daa92b22b83f1874924d511f67b6886cd0c7d8f92ebf3b1ab4fe".decode("hex"))
 * >>> m.update("00000001".decode("hex"))
 * >>> m.update(b"status")
 * >>> m.hexdigest()
 * '870acb83d9d509de95cb0747b122a7e524d4232a56cddf793d41a21c5010fd60'
 *
 * >>> m = hashlib.sha256()
 * >>> m.update("2c555e615836daa92b22b83f1874924d511f67b6886cd0c7d8f92ebf3b1ab4fe".decode("hex"))
 * >>> m.update("00000002".decode("hex"))
 * >>> m.update(b"status")
 * >>> m.hexdigest()
 * '39695ca87b6856a12a1c619e902903642338f3389a75262005a03fc141be0966'
 */
const uint8_t BK_BIV_1[48] = {
    0x87, 0x0a, 0xcb, 0x83, 0xd9, 0xd5, 0x09, 0xde,
    0x95, 0xcb, 0x07, 0x47, 0xb1, 0x22, 0xa7, 0xe5,
    0x24, 0xd4, 0x23, 0x2a, 0x56, 0xcd, 0xdf, 0x79,
    0x3d, 0x41, 0xa2, 0x1c, 0x50, 0x10, 0xfd, 0x60,
    0x39, 0x69, 0x5c, 0xa8, 0x7b, 0x68, 0x56, 0xa1,
    0x2a, 0x1c, 0x61, 0x9e, 0x90, 0x29, 0x03, 0x64
};

/*
 * [OpenSSL]
 * echo -ne '\xaa' \
 *  | openssl enc -aes-256-ctr \
 *      -K "870acb83d9d509de95cb0747b122a7e524d4232a56cddf793d41a21c5010fd60" \
 *      -iv "39695ca87b6856a12a1c619e90290364" \
 *  | hexdump
 * '0000000 18'
 */
const uint8_t SB_1[1] = {
    0x18
};

int keyroll_tests(void)
{
    int rv;
    int passed = 1;

    ccec_const_cp_t cp = ccec_cp_224();
    ccec_full_ctx_decl_cp(cp, full);
    ccec_pub_ctx_decl_cp(cp, p_1);
    ccec_ctx_init(cp, full);
    ccec_ctx_init(cp, p_1);

    // Get the RNG instance.
    struct ccrng_state *rng = ccrng(NULL);
    passed &= isnt(rng, NULL, "RNG Init failed");

    // Import and check P.
    rv = ccec_x963_import_priv(cp, sizeof(P), P, full);
    passed &= is(rv, CCERR_OK, "Importing P failed");

    passed &= ok(ccec_pairwise_consistency_check(full, rng), "Invalid P");

    // Derive SK_1 from SK_0.
    uint8_t sk_1[32];
    rv = ccansikdf_x963(ccsha256_di(), sizeof(SK_0), SK_0,
                        sizeof(KDF_LABEL_UPDATE) - 1, KDF_LABEL_UPDATE,
                        sizeof(sk_1), sk_1);
    passed &= is(rv, CCERR_OK, "Deriving SK_1 failed");
    passed &= ok_memcmp(sk_1, SK_1, sizeof(SK_1), "Deriving SK_1 failed");

    // Derive AT_1 from SK_1.
    uint8_t at_1[72];
    rv = ccansikdf_x963(ccsha256_di(), sizeof(sk_1), sk_1,
                        sizeof(KDF_LABEL_DIVERSIFY) - 1, KDF_LABEL_DIVERSIFY,
                        sizeof(at_1), at_1);
    passed &= is(rv, CCERR_OK, "Deriving AT_1 failed");
    passed &= ok_memcmp(at_1, AT_1, sizeof(AT_1), "Deriving AT_1 failed");

    // Derive P_1 from P and AT_1.
    rv = ccec_diversify_pub_twin(cp, ccec_ctx_pub(full), sizeof(at_1), at_1, rng, p_1);
    passed &= is(rv, CCERR_OK, "Deriving P_1 failed");

    // Export x(P_1).
    uint8_t x_p_1[28];
    rv = ccec_compact_export_pub(x_p_1, p_1);
    passed &= is(rv, CCERR_OK, "Exporting P_1 failed");
    passed &= ok_memcmp(x_p_1, x_P_1, sizeof(x_P_1), "Deriving x(P_1) failed");

    // Derive IK_1 from SK_1.
    uint8_t ik_1[32];
    rv = ccansikdf_x963(ccsha256_di(), sizeof(sk_1), sk_1,
                        sizeof(KDF_LABEL_INTERMEDIATE) - 1, KDF_LABEL_INTERMEDIATE,
                        sizeof(ik_1), ik_1);
    passed &= is(rv, CCERR_OK, "Deriving IK_1 failed");
    passed &= ok_memcmp(ik_1, IK_1, sizeof(IK_1), "Deriving IK_1 failed");

    // Derive CK_i from IK_i.
    uint8_t ck_1[32];
    rv = ccansikdf_x963(ccsha256_di(), sizeof(ik_1), ik_1,
                        sizeof(KDF_LABEL_COMMAND) - 1, KDF_LABEL_COMMAND,
                        sizeof(ck_1), ck_1);
    passed &= is(rv, CCERR_OK, "Deriving CK_1 failed");
    passed &= ok_memcmp(ck_1, CK_1, sizeof(CK_1), "Deriving CK_1 failed");

    // Compute NearOwnerAuthToken_1.
    uint8_t noat_1[32];
    uint8_t noat_info[28 + sizeof(MAC_LABEL_NEAROWNER) - 1];
    memcpy(noat_info, x_p_1, 28);
    memcpy(noat_info + 28, MAC_LABEL_NEAROWNER, sizeof(MAC_LABEL_NEAROWNER) - 1);
    cchmac(ccsha256_di(), sizeof(ck_1), ck_1, sizeof(noat_info), noat_info, noat_1);
    passed &= ok_memcmp(noat_1, NOAT_1, sizeof(NOAT_1), "Computing NearOwnerAuthToken_1 failed");

    // Derive BK_1,BIV_1 from IK_1.
    uint8_t bk_biv_1[48];
    rv = ccansikdf_x963(ccsha256_di(), sizeof(ik_1), ik_1,
                        sizeof(KDF_LABEL_STATUS) - 1, KDF_LABEL_STATUS,
                        sizeof(bk_biv_1), bk_biv_1);
    passed &= is(rv, CCERR_OK, "Deriving BK_1,BIV_1 failed");
    passed &= ok_memcmp(bk_biv_1, BK_BIV_1, sizeof(BK_BIV_1), "Deriving BK_1,BIV_1 failed");

    // Encrypt Status Byte.
    uint8_t sb_1[1] = { 0xaa };
    rv = ccctr_one_shot(ccaes_ctr_crypt_mode(), 32, bk_biv_1, bk_biv_1 + 32, 1, sb_1, sb_1);
    passed &= is(rv, CCERR_OK, "Encrypting Status Byte failed");
    passed &= ok_memcmp(sb_1, SB_1, sizeof(SB_1), "Encrypting Status Byte failed");

    return passed;
}
