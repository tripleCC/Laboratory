/* Copyright (c) (2017-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include <corecrypto/ccaes.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_aes_cbc.h"

// Test the AES CBC mode
int fipspost_post_aes_cbc(uint32_t fips_mode)
{
    size_t key128Length = 16;
    int rc = CCERR_OK;

    typedef struct
    {
        size_t				keyLength;
        int                 forEncryption;
        unsigned char*		keyData;
        unsigned char*		ivData;
        unsigned char*		inputData;
        unsigned char*		outputData;
    } testData;

    // AES 128 Encryption Test Data
    unsigned char* key128EncryptBuffer = (unsigned char*)"\x34\x49\x1b\x26\x6d\x8f\xb5\x4c\x5c\xe1\xa9\xfb\xf1\x7b\x09\x8c";
    unsigned char* iv128EncryptBuffer = (unsigned char*)"\x9b\xc2\x0b\x29\x51\xff\x72\xd3\xf2\x80\xff\x3b\xd2\xdc\x3d\xcc";
    unsigned char* input128EncryptBuffer = (unsigned char*)"\x06\xfe\x99\x71\x63\xcb\xcb\x55\x85\x3e\x28\x57\x74\xcc\xa8\x9d";

    unsigned char* output128EncryptBuffer;
    output128EncryptBuffer = POST_FIPS_RESULT_STR("\x32\x5d\xe3\x14\xe9\x29\xed\x08\x97\x87\xd0\xa2\x05\xd1\xeb\x33");

    // AES 128 Decryption Test Data
    unsigned char* key128DecryptBuffer = (unsigned char*)"\xc6\x8e\x4e\xb2\xca\x2a\xc5\xaf\xee\xac\xad\xea\xa3\x97\x11\x94";
    unsigned char* iv128DecryptBuffer = (unsigned char*)"\x11\xdd\x9d\xa1\xbd\x22\x3a\xcf\x68\xc5\xa1\xe1\x96\x4c\x18\x9b";
    unsigned char* input128DecryptBuffer = (unsigned char*)"\xaa\x36\x57\x9b\x0c\x72\xc5\x28\x16\x7b\x70\x12\xd7\xfa\xf0\xde";
    unsigned char* output128DecryptBuffer;
    output128DecryptBuffer = POST_FIPS_RESULT_STR("\x9e\x66\x1d\xb3\x80\x39\x20\x9a\x72\xc7\xd2\x96\x40\x66\x88\xf2");


    testData dataToTest[] =
    {
        {key128Length, 1, key128EncryptBuffer, iv128EncryptBuffer, input128EncryptBuffer, output128EncryptBuffer},
        {key128Length, 0, key128DecryptBuffer, iv128DecryptBuffer, input128DecryptBuffer, output128DecryptBuffer}

    };

    const struct ccmode_cbc* mode_enc = ccaes_cbc_encrypt_mode();
    const struct ccmode_cbc* mode_dec = ccaes_cbc_decrypt_mode();


    struct {
        const struct ccmode_cbc*	enc_mode_ptr;
        const struct ccmode_cbc*	dec_mode_ptr;
    } impl[] = {
        {mode_enc, mode_dec},
    };

    int memCheckResult = 0;
    unsigned char outputBuffer[CCAES_BLOCK_SIZE];

    int numDataToTest = 2;
    int numModesToTest = 1;

    for (int iCnt = 0; iCnt < numDataToTest; iCnt++)
    {
        for(int jCnt = 0; jCnt < numModesToTest; jCnt++)
        {

            if (cccbc_one_shot((dataToTest[iCnt].forEncryption ?
                            impl[jCnt].enc_mode_ptr :
                            impl[jCnt].dec_mode_ptr),
                           dataToTest[iCnt].keyLength, dataToTest[iCnt].keyData,
                           dataToTest[iCnt].ivData,
                           1, /* Only 1 block */
                           dataToTest[iCnt].inputData, outputBuffer)) {
                failf("test %d", iCnt * numDataToTest + jCnt);
                return CCPOST_LIBRARY_ERROR;
            }

            memCheckResult = (0 == memcmp(dataToTest[iCnt].outputData, outputBuffer, CCAES_BLOCK_SIZE));


            if (!memCheckResult)
            {
                failf("AES-CBC KAT Failed %d", iCnt * numDataToTest + jCnt);
                rc |= CCPOST_KAT_FAILURE;
            }
        }
    }

    return rc;
}
