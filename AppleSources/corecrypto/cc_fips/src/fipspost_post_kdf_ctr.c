/* Copyright (c) (2020,2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_error.h"
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>
#include <corecrypto/ccnistkdf.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_kdf_ctr.h"

int fipspost_post_kdf_ctr(uint32_t fips_mode)
{
    /*
    [PRF=HMAC_SHA1]
    [CTRLOCATION=BEFORE_FIXED]
    [RLEN=32_BITS]

    COUNT=0
    L = 128
    KI = f7591733c856593565130975351954d0155abf3c
    FixedInputDataByteLen = 60
    FixedInputData = 8e347ef55d5f5e99eab6de706b51de7ce004f3882889e259ff4e5cff102167a5a4bd711578d4ce17dd9abe56e51c1f2df950e2fc812ec1b217ca08d6
        Binary rep of i = 00000001
        instring = 000000018e347ef55d5f5e99eab6de706b51de7ce004f3882889e259ff4e5cff102167a5a4bd711578d4ce17dd9abe56e51c1f2df950e2fc812ec1b217ca08d6
    KO = 34fe44b0d8c41b93f5fa64fb96f00e5b
    */

    size_t hmacSha1KeyLength = 20;
    unsigned char* hmacSha1Key = (unsigned char*)
        "\xf7\x59\x17\x33\xc8\x56\x59\x35\x65\x13\x09\x75\x35\x19\x54\xd0"
        "\x15\x5a\xbf\x3c";

    size_t hmacSha1FixedInputDataLength = 60;
    unsigned char* hmacSha1FixedInputData = (unsigned char*)
        "\x8e\x34\x7e\xf5\x5d\x5f\x5e\x99\xea\xb6\xde\x70\x6b\x51\xde\x7c"
        "\xe0\x04\xf3\x88\x28\x89\xe2\x59\xff\x4e\x5c\xff\x10\x21\x67\xa5"
        "\xa4\xbd\x71\x15\x78\xd4\xce\x17\xdd\x9a\xbe\x56\xe5\x1c\x1f\x2d"
        "\xf9\x50\xe2\xfc\x81\x2e\xc1\xb2\x17\xca\x08\xd6";

    unsigned char* hmacSha1KeyOut = POST_FIPS_RESULT_STR(
        "\x34\xfe\x44\xb0\xd8\xc4\x1b\x93\xf5\xfa\x64\xfb\x96\xf0\x0e\x5b");

    unsigned char dk1[16];
    memset(dk1, 0, sizeof(dk1));

    int ret = ccnistkdf_ctr_hmac_fixed(ccsha1_di(),
                                       hmacSha1KeyLength, hmacSha1Key,
                                       hmacSha1FixedInputDataLength,
                                       hmacSha1FixedInputData,
                                       sizeof(dk1), dk1);

    int status = CCERR_OK;
    if (ret != 0) {
        failf("failed ccnistkdf_ctr_hmac_fixed (SHA-1): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(hmacSha1KeyOut, dk1, sizeof(dk1))) {
        failf("failed HMAC_SHA1 KAT");
        status = CCPOST_KAT_FAILURE;
    }

    /*
    [PRF=HMAC_SHA256]
    [CTRLOCATION=BEFORE_FIXED]
    [RLEN=32_BITS]

    COUNT=30
    L = 320
    KI = c4bedbddb66493e7c7259a3bbbc25f8c7e0ca7fe284d92d431d9cd99a0d214ac
    FixedInputDataByteLen = 60
    FixedInputData = 1c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220eacace6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b
        Binary rep of i = 00000001
        instring = 000000011c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220eacace6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b
        Binary rep of i = 00000002
        instring = 000000021c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220eacace6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b
    KO = 1da47638d6c9c4d04d74d4640bbd42ab814d9e8cc22f4326695239f96b0693f12d0dd1152cf44430
    */

    size_t hmacSha256KeyLength = 32;
    unsigned char* hmacSha256Key = (unsigned char*)
        "\xc4\xbe\xdb\xdd\xb6\x64\x93\xe7\xc7\x25\x9a\x3b\xbb\xc2\x5f\x8c"
        "\x7e\x0c\xa7\xfe\x28\x4d\x92\xd4\x31\xd9\xcd\x99\xa0\xd2\x14\xac";

    size_t hmacSha256FixedInputDataLength = 60;
    unsigned char* hmacSha256FixedInputData = (unsigned char*)
        "\x1c\x69\xc5\x47\x66\x79\x1e\x31\x5c\x2c\xc5\xc4\x7e\xcd\x3f\xfa"
        "\xb8\x7d\x0d\x27\x3d\xd9\x20\xe7\x09\x55\x81\x4c\x22\x0e\xac\xac"
        "\xe6\xa5\x94\x65\x42\xda\x3d\xfe\x24\xff\x62\x6b\x48\x97\x89\x8c"
        "\xaf\xb7\xdb\x83\xbd\xff\x3c\x14\xfa\x46\xfd\x4b";

    unsigned char* hmacSha256KeyOut = POST_FIPS_RESULT_STR(
        "\x1d\xa4\x76\x38\xd6\xc9\xc4\xd0\x4d\x74\xd4\x64\x0b\xbd\x42\xab"
        "\x81\x4d\x9e\x8c\xc2\x2f\x43\x26\x69\x52\x39\xf9\x6b\x06\x93\xf1"
        "\x2d\x0d\xd1\x15\x2c\xf4\x44\x30");

    unsigned char dk2[40];
    memset(dk2, 0, sizeof(dk2));

    ret = ccnistkdf_ctr_hmac_fixed(ccsha256_di(),
                                   hmacSha256KeyLength, hmacSha256Key,
                                   hmacSha256FixedInputDataLength,
                                   hmacSha256FixedInputData,
                                   sizeof(dk2), dk2);

    if (ret != 0) {
        failf("failed ccnistkdf_ctr_hmac_fixed (SHA-256): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(hmacSha256KeyOut, dk2, sizeof(dk2))) {
        failf("failed HMAC_SHA256 KAT");
        status = CCPOST_KAT_FAILURE;
    }

    /*
    [PRF=HMAC_SHA512]
    [CTRLOCATION=BEFORE_FIXED]
    [RLEN=32_BITS]

    COUNT=0
    L = 128
    KI = dd5dbd45593ee2ac139748e7645b450f223d2ff297b73fd71cbcebe71d41653c950b88500de5322d99ef18dfdd30428294c4b3094f4c954334e593bd982ec614
    FixedInputDataByteLen = 60
    FixedInputData = b50b0c963c6b3034b8cf19cd3f5c4ebe4f4985af0c03e575db62e6fdf1ecfe4f28b95d7ce16df85843246e1557ce95bb26cc9a21974bbd2eb69e8355
        Binary rep of i = 00000001
        instring = 00000001b50b0c963c6b3034b8cf19cd3f5c4ebe4f4985af0c03e575db62e6fdf1ecfe4f28b95d7ce16df85843246e1557ce95bb26cc9a21974bbd2eb69e8355
    KO = e5993bf9bd2aa1c45746042e12598155
    */

    size_t hmacSha512KeyLength = 64;
    unsigned char* hmacSha512Key = (unsigned char*)
        "\xdd\x5d\xbd\x45\x59\x3e\xe2\xac\x13\x97\x48\xe7\x64\x5b\x45\x0f"
        "\x22\x3d\x2f\xf2\x97\xb7\x3f\xd7\x1c\xbc\xeb\xe7\x1d\x41\x65\x3c"
        "\x95\x0b\x88\x50\x0d\xe5\x32\x2d\x99\xef\x18\xdf\xdd\x30\x42\x82"
        "\x94\xc4\xb3\x09\x4f\x4c\x95\x43\x34\xe5\x93\xbd\x98\x2e\xc6\x14";

    size_t hmacSha512FixedInputDataLength = 60;
    unsigned char* hmacSha512FixedInputData = (unsigned char*)
        "\xb5\x0b\x0c\x96\x3c\x6b\x30\x34\xb8\xcf\x19\xcd\x3f\x5c\x4e\xbe"
        "\x4f\x49\x85\xaf\x0c\x03\xe5\x75\xdb\x62\xe6\xfd\xf1\xec\xfe\x4f"
        "\x28\xb9\x5d\x7c\xe1\x6d\xf8\x58\x43\x24\x6e\x15\x57\xce\x95\xbb"
        "\x26\xcc\x9a\x21\x97\x4b\xbd\x2e\xb6\x9e\x83\x55";

    unsigned char* hmacSha512KeyOut = POST_FIPS_RESULT_STR(
        "\xe5\x99\x3b\xf9\xbd\x2a\xa1\xc4\x57\x46\x04\x2e\x12\x59\x81\x55");

    unsigned char dk3[16];
    memset(dk3, 0, sizeof(dk3));

    ret = ccnistkdf_ctr_hmac_fixed(ccsha512_di(),
                                   hmacSha512KeyLength, hmacSha512Key,
                                   hmacSha512FixedInputDataLength,
                                   hmacSha512FixedInputData,
                                   sizeof(dk3), dk3);

    if (ret != 0) {
        failf("failed ccnistkdf_ctr_hmac_fixed (SHA-512): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(hmacSha512KeyOut, dk3, sizeof(dk3))) {
        failf("failed HMAC_SHA512 KAT");
        status = CCPOST_KAT_FAILURE;
    }

#if !CC_KERNEL
    // SHA3. We reuse the fixed input data from SHA1, and the input key from SHA1.
/*
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import (CounterLocation, KBKDFHMAC, Mode)
fixed = bytes.fromhex("8e347ef55d5f5e99eab6de706b51de7ce004f3882889e259ff4e5cff102167a5a4bd711578d4ce17dd9abe56e51c1f2df950e2fc812ec1b217ca08d6")
key = bytes.fromhex("f7591733c856593565130975351954d0155abf3c")
s224=KBKDFHMAC(algorithm=hashes.SHA3_224(),mode=Mode.CounterMode,length=16,llen=4,rlen=4,location=CounterLocation.BeforeFixed,fixed=fixed,label=None,context=None).derive(key).hex()
s256=KBKDFHMAC(algorithm=hashes.SHA3_256(),mode=Mode.CounterMode,length=16,llen=4,rlen=4,location=CounterLocation.BeforeFixed,fixed=fixed,label=None,context=None).derive(key).hex()
s384=KBKDFHMAC(algorithm=hashes.SHA3_384(),mode=Mode.CounterMode,length=16,llen=4,rlen=4,location=CounterLocation.BeforeFixed,fixed=fixed,label=None,context=None).derive(key).hex()
s512=KBKDFHMAC(algorithm=hashes.SHA3_512(),mode=Mode.CounterMode,length=16,llen=4,rlen=4,location=CounterLocation.BeforeFixed,fixed=fixed,label=None,context=None).derive(key).hex()
printdigest = lambda s: print("\\x" + "\\x".join(s[i:i+2] for i in range(0, len(s), 2)))
printdigest(s224)
printdigest(s256)
printdigest(s384)
printdigest(s512)
*/
    unsigned char dk_sha3[16];
    memset(dk_sha3, 0, sizeof(dk_sha3));

    unsigned char* hmac_sha3_224_key_out = POST_FIPS_RESULT_STR("\xbd\xd9\x5c\x39\xbd\x85\x6e\x25\xfe\xbd\x03\xf8\x89\xa0\xf7\x00");
    unsigned char* hmac_sha3_256_key_out = POST_FIPS_RESULT_STR("\x5a\xc9\xf7\xec\x38\xf6\x8b\x76\x23\x94\xd3\xca\xec\xeb\xa5\xbb");
    unsigned char* hmac_sha3_384_key_out = POST_FIPS_RESULT_STR("\x68\x8b\x9e\x28\x23\x2b\x76\x54\xf9\x35\x93\xa5\xc3\xf0\x38\x35");
    unsigned char* hmac_sha3_512_key_out = POST_FIPS_RESULT_STR("\xfe\xa9\x6a\xf5\x19\x2a\xd4\x27\x1d\x79\xb9\x80\x80\x3b\x57\x11");
    
    ret = ccnistkdf_ctr_hmac_fixed(ccsha3_224_di(),
                                   hmacSha1KeyLength, hmacSha1Key,
                                   hmacSha1FixedInputDataLength,
                                   hmacSha1FixedInputData,
                                   sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccnistkdf_ctr_hmac_fixed (SHA3-224): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(hmac_sha3_224_key_out, dk_sha3, sizeof(dk_sha3))) {
        failf("failed HMAC_SHA3_224 KAT");
        status = CCPOST_KAT_FAILURE;
    }
    
    ret = ccnistkdf_ctr_hmac_fixed(ccsha3_256_di(),
                                   hmacSha1KeyLength, hmacSha1Key,
                                   hmacSha1FixedInputDataLength,
                                   hmacSha1FixedInputData,
                                   sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccnistkdf_ctr_hmac_fixed (SHA3-256): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(hmac_sha3_256_key_out, dk_sha3, sizeof(dk_sha3))) {
        failf("failed HMAC_SHA3_256 KAT");
        status = CCPOST_KAT_FAILURE;
    }
    
    ret = ccnistkdf_ctr_hmac_fixed(ccsha3_384_di(),
                                   hmacSha1KeyLength, hmacSha1Key,
                                   hmacSha1FixedInputDataLength,
                                   hmacSha1FixedInputData,
                                   sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccnistkdf_ctr_hmac_fixed (SHA3-384): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(hmac_sha3_384_key_out, dk_sha3, sizeof(dk_sha3))) {
        failf("failed HMAC_SHA3_384 KAT");
        status = CCPOST_KAT_FAILURE;
    }
    
    ret = ccnistkdf_ctr_hmac_fixed(ccsha3_512_di(),
                                   hmacSha1KeyLength, hmacSha1Key,
                                   hmacSha1FixedInputDataLength,
                                   hmacSha1FixedInputData,
                                   sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccnistkdf_ctr_hmac_fixed (SHA3-512): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(hmac_sha3_512_key_out, dk_sha3, sizeof(dk_sha3))) {
        failf("failed HMAC_SHA3_512 KAT");
        status = CCPOST_KAT_FAILURE;
    }
#endif

    return status;
}
