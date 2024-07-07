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
#include "fipspost_post_aes_gcm.h"

// Test the AES GCM mode
int fipspost_post_aes_gcm(uint32_t fips_mode)
{
	// Decryption data
	unsigned char* keyBufferDecPtr = (unsigned char* )"\x53\xcd\x05\xee\xac\xe3\x60\xbb\x84\x22\xde\xee\xde\xe0\x9d\x85";
	size_t keyBufferDecPtrLength = 16;
	unsigned char* ivBufferDecPtr = (unsigned char* )"\x65\x48\x7a\x4d\x2a\x0e\xc7\x33\xf5\x25\x2b\x9e";
	size_t ivBufferDecPtrLength = 12;

    unsigned char* resultTagDecPtr;
    resultTagDecPtr = POST_FIPS_RESULT_STR("\xf2\xa1\x24\x6b\xff\x2d\x89\x3a\xef\xcd\xe5\x90\x7a\x12\x07\x9b");

	// Encryption Data
	unsigned char* keyBufferEncPtr = (unsigned char* )"\x70\xc8\xbf\xb6\x02\x76\xe2\x18\xa0\xed\xa2\xaa\xd1\xfd\xc1\x9c";
	size_t keyBufferEncPtrLength = 16;
	unsigned char* ivBufferEncPtr = 	(unsigned char* )"\x74\x17\x07\xcb\x56\x6f\x68\xe8\x5d\x00\xc7\xbf";	
	size_t ivBufferEncPtrLength = 12;

    unsigned char* resultTagEncPtr;
    resultTagEncPtr = POST_FIPS_RESULT_STR("\x26\x86\xf5\xa1\x1f\x0c\x4b\x53\x81\x0a\x5b\x32\xb0\xa8\xff\xbc");

	size_t aDataLen		= 0;
	const void*	aData	= NULL;
	size_t dataInLength = 0;
    const void*	dataIn	= NULL;
	uint8_t dataOut[16];
	
	size_t tagLength = 16;
    
	uint8_t tag[16];
    memcpy(tag, resultTagDecPtr, 16);

	// Test Decrypt First
	const struct ccmode_gcm* mode_dec_ptr = ccaes_gcm_decrypt_mode();

	if (ccgcm_one_shot(mode_dec_ptr, keyBufferDecPtrLength, keyBufferDecPtr,
                       ivBufferDecPtrLength, ivBufferDecPtr,
                       aDataLen, aData,
                       dataInLength, dataIn, dataOut,
                       tagLength, tag)) {
        failf("ccgcm_one_shot decrypt");
        return CCPOST_LIBRARY_ERROR;
    }


	if (memcmp(tag, resultTagDecPtr, 16))
	{
		failf("ccgcm_one_shot decrypt");
		return CCPOST_KAT_FAILURE;
	}

	// Test Encryption
	aDataLen	= 0;
	aData		= NULL;
	dataInLength = 0;
    dataIn		= NULL;
	tagLength 	= 16;

	memset(tag, 0, 16);
       
    const struct ccmode_gcm* mode_enc_ptr = ccaes_gcm_encrypt_mode();
	
	if (ccgcm_one_shot(mode_enc_ptr, keyBufferEncPtrLength, keyBufferEncPtr,
                       ivBufferEncPtrLength, ivBufferEncPtr,
                       aDataLen, aData,
                       dataInLength, dataIn, dataOut,
                       tagLength, tag)) {
        failf("ccgcm_one_shot encrypt");
        return CCPOST_LIBRARY_ERROR;
    }


	if (memcmp(tag, resultTagEncPtr, 16))
	{
		failf("ccgcm_one_shot encrypt");
		return CCPOST_KAT_FAILURE;
	}

	return 0; // passed
}
