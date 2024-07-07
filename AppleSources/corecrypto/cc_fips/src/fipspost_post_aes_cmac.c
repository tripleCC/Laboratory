/* Copyright (c) (2020,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccaes.h>
#include <corecrypto/cccmac.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_aes_cmac.h"

int fipspost_post_aes_cmac(uint32_t fips_mode)
{
    const struct ccmode_cbc *cbc = ccaes_cbc_encrypt_mode();

    /*
    Count = 0
    Klen = 16
    Mlen = 0
    Tlen = 4
    Key = e4b7645b2f7d63b4674cd01970c9d1ec
    Msg = 00
    Mac = f266a187
    */

    const size_t aesCmacGen1KeyLength = 16;
    unsigned char* aesCmacGen1Key = (unsigned char*)
        "\xe4\xb7\x64\x5b\x2f\x7d\x63\xb4\x67\x4c\xd0\x19\x70\xc9\xd1\xec";

    const size_t aesCmacGen1MessageLength = 0;
    unsigned char* aesCmacGen1Message = (unsigned char*)"";

    unsigned char* aesCmacGen1Mac = POST_FIPS_RESULT_STR(
        "\xf2\x66\xa1\x87");

    unsigned char mac1[4 /* Length of aesCmacGen1Mac */];
    memset(mac1, 0, sizeof(mac1));

    int ret = cccmac_one_shot_generate(cbc, aesCmacGen1KeyLength, aesCmacGen1Key,
                                            aesCmacGen1MessageLength, aesCmacGen1Message,
                                            sizeof(mac1), mac1);

    if (ret != 0) {
        failf("failed cccmac_one_shot_generate COUNT #0: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(aesCmacGen1Mac, mac1, sizeof(mac1))) {
        failf("failed AES-CMAC KAT");
        return CCPOST_KAT_FAILURE;
    }

    /*
    Count = 32
    Klen = 16
    Mlen = 32
    Tlen = 4
    Key = 77a77faf290c1fa30c683df16ba7a77b
    Msg = 020683e1f0392f4cac54318b6029259e9c553dbc4b6ad998e64d58e4e7dc2e13
    Mac = fbfea41b
    */

    const size_t aesCmacGen2KeyLength = 16;
    unsigned char* aesCmacGen2Key = (unsigned char*)
        "\x77\xa7\x7f\xaf\x29\x0c\x1f\xa3\x0c\x68\x3d\xf1\x6b\xa7\xa7\x7b";

    const size_t aesCmacGen2MessageLength = 32;
    unsigned char* aesCmacGen2Message = (unsigned char*)
        "\x02\x06\x83\xe1\xf0\x39\x2f\x4c\xac\x54\x31\x8b\x60\x29\x25\x9e"
        "\x9c\x55\x3d\xbc\x4b\x6a\xd9\x98\xe6\x4d\x58\xe4\xe7\xdc\x2e\x13";

    unsigned char* aesCmacGen2Mac = POST_FIPS_RESULT_STR(
        "\xfb\xfe\xa4\x1b");

    unsigned char mac2[4 /* Length of aesCmacGen2Mac */];
    memset(mac2, 0, sizeof(mac2));

    ret = cccmac_one_shot_generate(cbc, aesCmacGen2KeyLength, aesCmacGen2Key,
                                        aesCmacGen2MessageLength, aesCmacGen2Message,
                                        sizeof(mac2), mac2);

    if (ret != 0) {
        failf("failed cccmac_one_shot_generate COUNT #32: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(aesCmacGen2Mac, mac2, sizeof(mac2))) {
        failf("failed AES-CMAC KAT");
        return CCPOST_KAT_FAILURE;
    }

    /*
    Count = 79
    Klen = 16
    Mlen = 37
    Tlen = 15
    Key = 1874596cddbdf18a10bc71d60c6bb93d
    Msg = 12a340ef015dc0a38625a4847eb6cac9cab9450548e9f96402756531a6a5bf9c37c146bb01
    Mac = 26a5fd25805129756b5b1ac33d8774
    */

    const size_t aesCmacGen3KeyLength = 16;
    unsigned char* aesCmacGen3Key = (unsigned char*)
        "\x18\x74\x59\x6c\xdd\xbd\xf1\x8a\x10\xbc\x71\xd6\x0c\x6b\xb9\x3d";

    const size_t aesCmacGen3MessageLength = 37;
    unsigned char* aesCmacGen3Message = (unsigned char*)
        "\x12\xa3\x40\xef\x01\x5d\xc0\xa3\x86\x25\xa4\x84\x7e\xb6\xca\xc9"
        "\xca\xb9\x45\x05\x48\xe9\xf9\x64\x02\x75\x65\x31\xa6\xa5\xbf\x9c\x37\xc1\x46\xbb\x01";

    unsigned char* aesCmacGen3Mac = POST_FIPS_RESULT_STR(
        "\x26\xa5\xfd\x25\x80\x51\x29\x75\x6b\x5b\x1a\xc3\x3d\x87\x74");

    unsigned char mac3[15 /* Length of aesCmacGen3Mac */];
    memset(mac3, 0, sizeof(mac3));

    ret = cccmac_one_shot_generate(cbc, aesCmacGen3KeyLength, aesCmacGen3Key,
                                        aesCmacGen3MessageLength, aesCmacGen3Message,
                                        sizeof(mac3), mac3);

    if (ret != 0) {
        failf("failed cccmac_one_shot_generate COUNT #79: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(aesCmacGen3Mac, mac3, sizeof(mac3))) {
        failf("failed AES-CMAC KAT");
        return CCPOST_KAT_FAILURE;
    }

    /*
    Count = 2
    Klen = 16
    Mlen = 0
    Tlen = 8
    Key = 7256e344f68b3e7f9dd6e04c5c65135c
    Msg = 00
    Mac = d4d7fcc5f979230f
    Result = P
    */

    const size_t aesCmacVer1KeyLength = 16;
    unsigned char* aesCmacVer1Key = (unsigned char*)
        "\x72\x56\xe3\x44\xf6\x8b\x3e\x7f\x9d\xd6\xe0\x4c\x5c\x65\x13\x5c";

    const size_t aesCmacVer1MessageLength = 0;
    unsigned char* aesCmacVer1Message = (unsigned char*)"";

    const size_t aesCmacVer1MacLength = 8;
    unsigned char* aesCmacVer1Mac = POST_FIPS_RESULT_STR(
        "\xd4\xd7\xfc\xc5\xf9\x79\x23\x0f");

    ret = cccmac_one_shot_verify(cbc, aesCmacVer1KeyLength, aesCmacVer1Key,
                                      aesCmacVer1MessageLength, aesCmacVer1Message,
                                      aesCmacVer1MacLength, aesCmacVer1Mac);

    if (ret != 0) {
        failf("failed cccmac_one_shot_verify COUNT #2: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    /*
    Count = 47
    Klen = 16
    Mlen = 32
    Tlen = 8
    Key = 6583a4ff27b6e109046d11b977c8293d
    Msg = b63be320f92e01260fba37312224494a2764dfc928287c75dc1cafee7b698d48
    Mac = fa0cced22e896b40
    Result = F (1 - Message changed)
    */

    const size_t aesCmacVer2KeyLength = 16;
    unsigned char* aesCmacVer2Key = (unsigned char*)
        "\x65\x83\xa4\xff\x27\xb6\xe1\x09\x04\x6d\x11\xb9\x77\xc8\x29\x3d";

    const size_t aesCmacVer2MessageLength = 32;
    unsigned char* aesCmacVer2Message = (unsigned char*)
        "\xb6\x3b\xe3\x20\xf9\x2e\x01\x26\x0f\xba\x37\x31\x22\x24\x49\x4a"
        "\x27\x64\xdf\xc9\x28\x28\x7c\x75\xdc\x1c\xaf\xee\x7b\x69\x8d\x48";

    const size_t aesCmacVer2MacLength = 8;
    unsigned char* aesCmacVer2Mac = (unsigned char*)
        "\xfa\x0c\xce\xd2\x2e\x89\x6b\x40";

    ret = cccmac_one_shot_verify(cbc, aesCmacVer2KeyLength, aesCmacVer2Key,
                                      aesCmacVer2MessageLength, aesCmacVer2Message,
                                      aesCmacVer2MacLength, aesCmacVer2Mac);

    if (ret == 0) {
        failf("failed cccmac_one_shot_verify COUNT #47: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    /*
    Count = 89
    Klen = 16
    Mlen = 64
    Tlen = 8
    Key = edfe2e15edf0b0c28875651d4becfca5
    Msg = 70b1e2e4cf260b108f5a52d0d8234838ffd6ffe7b4acd78d7d6b95aa6342b598eaf402cb47396358ce61f8b4aa3a65bed0346e0036c3c5323f051f007aa58d0e
    Mac = 7b70730219907d18
    Result = F (4 - Key or Key1 changed)
    */

    const size_t aesCmacVer3KeyLength = 16;
    unsigned char* aesCmacVer3Key = (unsigned char*)
        "\xed\xfe\x2e\x15\xed\xf0\xb0\xc2\x88\x75\x65\x1d\x4b\xec\xfc\xa5";

    const size_t aesCmacVer3MessageLength = 64;
    unsigned char* aesCmacVer3Message = (unsigned char*)
        "\x70\xb1\xe2\xe4\xcf\x26\x0b\x10\x8f\x5a\x52\xd0\xd8\x23\x48\x38"
        "\xff\xd6\xff\xe7\xb4\xac\xd7\x8d\x7d\x6b\x95\xaa\x63\x42\xb5\x98"
        "\xea\xf4\x02\xcb\x47\x39\x63\x58\xce\x61\xf8\xb4\xaa\x3a\x65\xbe"
        "\xd0\x34\x6e\x00\x36\xc3\xc5\x32\x3f\x05\x1f\x00\x7a\xa5\x8d\x0e";

    const size_t aesCmacVer3MacLength = 8;
    unsigned char* aesCmacVer3Mac = (unsigned char*)
        "\x7b\x70\x73\x02\x19\x90\x7d\x18";

    ret = cccmac_one_shot_verify(cbc, aesCmacVer3KeyLength, aesCmacVer3Key,
                                      aesCmacVer3MessageLength, aesCmacVer3Message,
                                      aesCmacVer3MacLength, aesCmacVer3Mac);

    if (ret == 0) {
        failf("failed cccmac_one_shot_verify COUNT #89: %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    return 0; // passed
}
