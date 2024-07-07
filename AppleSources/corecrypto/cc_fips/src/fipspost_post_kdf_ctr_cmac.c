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
#include <corecrypto/ccnistkdf.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_kdf_ctr_cmac.h"

int fipspost_post_kdf_ctr_cmac(uint32_t fips_mode)
{
    /*
    From published NIST KAT for CMAC_AES128, R=32
    [PRF=CMAC_AES128]
    [CTRLOCATION=BEFORE_FIXED]
    [RLEN=32_BITS]

    COUNT=1
    L = 128
    KI = c10b152e8c97b77e18704e0f0bd38305
    FixedInputDataByteLen = 60
    FixedInputData =
        98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ffdba89d03e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4
        Binary rep of i = 00000000000000000000000000000001
        instring = 0000000000000000000000000000000198cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ffdba89d03e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4
    KO = 26faf61908ad9ee881b8305c221db53f
    */
    
    uint8_t r_len = 32;
    size_t cmacAes128KeyLength = 16;
    unsigned char* cmacAes128Key = (unsigned char*)
        "\xc1\x0b\x15\x2e\x8c\x97\xb7\x7e\x18\x70\x4e\x0f\x0b\xd3\x83\x05";

    size_t cmacAes128FixedInputDataLength = 60;
    unsigned char* cmacAes128FixedInputData = (unsigned char*)
        "\x98\xcd\x4c\xbb\xbe\xbe\x15\xd1\x7d\xc8\x6e\x6d\xba\xd8\x00\xa2"\
        "\xdc\xbd\x64\xf7\xc7\xad\x0e\x78\xe9\xcf\x94\xff\xdb\xa8\x9d\x03"\
        "\xe9\x7e\xad\xf6\xc4\xf7\xb8\x06\xca\xf5\x2a\xa3\x8f\x09\xd0\xeb"\
        "\x71\xd7\x1f\x49\x7b\xcc\x69\x06\xb4\x8d\x36\xc4";

    unsigned char* cmacAes128KeyOut = POST_FIPS_RESULT_STR(
        "\x26\xfa\xf6\x19\x08\xad\x9e\xe8\x81\xb8\x30\x5c\x22\x1d\xb5\x3f");

    unsigned char dk1[16];
    memset(dk1, 0, sizeof(dk1));

    int ret1 = ccnistkdf_ctr_cmac_fixed(ccaes_cbc_encrypt_mode(), r_len,
                                       cmacAes128KeyLength, cmacAes128Key,
                                       cmacAes128FixedInputDataLength,
                                       cmacAes128FixedInputData,
                                       sizeof(dk1), dk1);

    int status = CCERR_OK;
    if (ret1 != 0) {
        failf("failed ccnistkdf_ctr_cmac_fixed (AES128): %d", ret1);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(cmacAes128KeyOut, dk1, sizeof(dk1))) {
        failf("failed CMAC_AES128 KAT");
        status = CCPOST_KAT_FAILURE;
    }
    
    /*
    From published NIST KAT for CMAC_AES256, R=24
    [PRF=CMAC_AES256]
    [CTRLOCATION=BEFORE_FIXED]
    [RLEN=24_BITS]

    COUNT=6
    L = 256
    KI = 4d71923280fb4a11b25f9d58d67704d8f8bb2d64d89edb9ee6f3de32e4601efc
    FixedInputDataByteLen = 60
    FixedInputData =
        e27b8f350bc1360ddc476cb0cae886f0161da22ee8159c330f545af1d782a0f0aacc3c3de6215807161df09336d470b5b4db1cc0ce73ed1d3ea24380
        Binary rep of i = 000000000000000000000001
        instring = 000000000000000000000001e27b8f350bc1360ddc476cb0cae886f0161da22ee8159c330f545af1d782a0f0aacc3c3de6215807161df09336d470b5b4db1cc0ce73ed1d3ea24380
    KO = b5b2bb675fe7b04a52340bd5cf248d5258a1f837dad747ee8a4e904608a8977d
    */
    
    r_len = 24;
    size_t cmacAes256KeyLength = 32;
    unsigned char* cmacAes256Key = (unsigned char*)
        "\x4d\x71\x92\x32\x80\xfb\x4a\x11\xb2\x5f\x9d\x58\xd6\x77\x04\xd8"\
        "\xf8\xbb\x2d\x64\xd8\x9e\xdb\x9e\xe6\xf3\xde\x32\xe4\x60\x1e\xfc";

    size_t cmacAes256FixedInputDataLength = 60;
    unsigned char* cmacAes256FixedInputData = (unsigned char*)
        "\xe2\x7b\x8f\x35\x0b\xc1\x36\x0d\xdc\x47\x6c\xb0\xca\xe8\x86\xf0"\
        "\x16\x1d\xa2\x2e\xe8\x15\x9c\x33\x0f\x54\x5a\xf1\xd7\x82\xa0\xf0"\
        "\xaa\xcc\x3c\x3d\xe6\x21\x58\x07\x16\x1d\xf0\x93\x36\xd4\x70\xb5"\
        "\xb4\xdb\x1c\xc0\xce\x73\xed\x1d\x3e\xa2\x43\x80";

    unsigned char* cmacAes256KeyOut = POST_FIPS_RESULT_STR(
        "\xb5\xb2\xbb\x67\x5f\xe7\xb0\x4a\x52\x34\x0b\xd5\xcf\x24\x8d\x52"\
        "\x58\xa1\xf8\x37\xda\xd7\x47\xee\x8a\x4e\x90\x46\x08\xa8\x97\x7d");

    unsigned char dk6[32];
    memset(dk6, 0, sizeof(dk6));

    int ret6 = ccnistkdf_ctr_cmac_fixed(ccaes_cbc_encrypt_mode(), r_len,
                                       cmacAes256KeyLength, cmacAes256Key,
                                       cmacAes256FixedInputDataLength,
                                       cmacAes256FixedInputData,
                                       sizeof(dk6), dk6);

    if (ret6 != 0) {
        failf("failed ccnistkdf_ctr_cmac_fixed (AES256): %d", ret6);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(cmacAes256KeyOut, dk6, sizeof(dk6))) {
        failf("failed CMAC_AES256 KAT");
        status = CCPOST_KAT_FAILURE;
    }

    return status;
}
