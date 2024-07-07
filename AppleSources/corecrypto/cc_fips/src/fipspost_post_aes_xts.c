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
#include "fipspost_post_aes_xts.h"

int fipspost_post_aes_xts(uint32_t fips_mode)
{
    size_t key128Length = 16;

    //Key = 3970cbb4b09a50f428890024876607d04f9b3621728d8a67549f74aa082d58ef
    unsigned char* key_data;
    key_data = POST_FIPS_RESULT_STR("\x39\x70\xcb\xb4\xb0\x9a\x50\xf4\x28\x89\x00\x24\x87\x66\x07\xd0");

    unsigned char* key2_data = (unsigned char*)"\x4f\x9b\x36\x21\x72\x8d\x8a\x67\x54\x9f\x74\xaa\x08\x2d\x58\xef";
    // PT = 18147bb2a205974d1efd386885b24797
    unsigned char* pt_enc_data =  (unsigned char *)"\x18\x14\x7b\xb2\xa2\x05\x97\x4d\x1e\xfd\x38\x68\x85\xb2\x47\x97";

    // CT = b91a3884ffd4e6151c5aaaaecb5fa9ff
    unsigned char* ct_enc_data =  (unsigned char *)"\xb9\x1a\x38\x84\xff\xd4\xe6\x15\x1c\x5a\xaa\xae\xcb\x5f\xa9\xff";
    unsigned int	dataUnitSeqNumber = 41;

    uint8_t         tweak_buffer[CCAES_BLOCK_SIZE];

    memset(tweak_buffer, 0, CCAES_BLOCK_SIZE);
    unsigned char* dataUnitSeqNumberPtr = (unsigned char*)&dataUnitSeqNumber;
    size_t numBytes = sizeof(dataUnitSeqNumber);
    for(size_t iCnt = 0; iCnt < numBytes; iCnt++)
    {
        tweak_buffer[iCnt] = (unsigned char)*dataUnitSeqNumberPtr;
        dataUnitSeqNumberPtr++;
    }

    const struct ccmode_xts* xts_enc =  ccaes_xts_encrypt_mode();

    unsigned char output[16];
    memset(output, 0, 16);

    if (ccxts_one_shot(xts_enc, key128Length, key_data, key2_data, tweak_buffer, 1, pt_enc_data, output)) {
        failf("encrypt");
        return CCPOST_LIBRARY_ERROR;
    }
    if (memcmp(output, ct_enc_data, 16))
    {
        failf("encrypt");
        return CCPOST_KAT_FAILURE;
    }

    const struct ccmode_xts* xts_dec =  ccaes_xts_decrypt_mode();
    memset(output, 0, 16);
    if (ccxts_one_shot(xts_dec, key128Length, key_data, key2_data, tweak_buffer, 1, ct_enc_data, output)) {
        failf("decrypt");
        return CCPOST_LIBRARY_ERROR;
    }
    if (memcmp(output, pt_enc_data, 16))
    {
        failf("decrypt");
        return CCPOST_KAT_FAILURE;
    }

    return 0; // passed
}
