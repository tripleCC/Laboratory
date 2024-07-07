/* Copyright (c) (2017,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdrbg.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_drbg_ctr.h"
#include "cc_memory.h"

// Test CTR DRBG
int fipspost_post_drbg_ctr(uint32_t fips_mode)
{
    unsigned char*  entropyInputBuffer;
    entropyInputBuffer = POST_FIPS_RESULT_STR("\x74\x7a\xe6\x1f\x3d\xb3\x31\x52\x9a\x13\xc3\x6d\xc6\xeb\xd2\xef");


    const size_t entropyInputBufferLength = 16;
	unsigned char* nonceBuffer = (unsigned char *)"\xff\xbd\xdc\xdf\x7f\xdd\xce\xa4";
    const size_t nonceBufferLength = 8;
	unsigned char* personalizationStringBuffer = (unsigned char *)"\xbd\x93\xc6\xd5\x6b\x07\x7b\xf3\xca\x13\x0c\xc3\xef\xbf\xc7\x10";
    const size_t personalizationStringBufferLength = 16;
	unsigned char* additionalInput1Buffer = (unsigned char *)"\xdf\xb1\xe7\x83\x82\xc8\xdb\xd7\xef\x1a\x20\x0b\x13\x67\x1a\xe2";
    const size_t additionalInput1BufferLength = 16;
	unsigned char* entropyInputPR1Buffer = (unsigned char *)"\x34\x83\x2e\xc3\x2b\x10\x58\xc9\x8d\x72\xb0\xb6\x89\xa8\xda\xe2";
    const size_t entropyInputPR1BufferLength = 16;
	unsigned char* additionalInput2Buffer = (unsigned char *)"\xca\x83\xd6\x45\x5e\x98\xcd\x09\xd6\x65\x86\xe2\x63\x92\x6d\xe6";
    const size_t additionalInput2BufferLength = 16;
	unsigned char* entropyInputPR2Buffer = (unsigned char *)"\xbe\xe1\x92\xef\x26\xdd\xbb\x23\x6a\xf8\x29\xd0\xc7\xd8\x49\xb7";
    const size_t entropyInputPR2BufferLength = 16;
	unsigned char* returnedBitsBuffer = (unsigned char *)"\x52\x58\xdd\xef\x4b\xda\x42\xed\x49\x9e\x57\xf1\x51\x74\xb0\x87";
    const size_t returnedBitsBufferLength = 16;
	
	uint8_t resultBuffer[16];
	memset(resultBuffer, 0, 16);

    static ccdrbg_df_bc_ctx_t df_ctx;
    static struct ccdrbg_info info;
 	struct ccdrbg_nistctr_custom custom;
   	custom.ctr_info = ccaes_ctr_crypt_mode();
    custom.keylen = 16;
    custom.strictFIPS = 0;
    custom.df_ctx = &df_ctx.df_ctx;
	ccdrbg_factory_nistctr(&info, &custom);

    CC_DECL_WORKSPACE_OR_FAIL(ws, ccn_nof_size(info.size));
    struct ccdrbg_state* rng = (struct ccdrbg_state *)CC_ALLOC_WS(ws, ccn_nof_size(info.size));
    int rc;

    rc = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           16);
    if (rc) {
        failf("ccdrbg_df_bc_init");
        rc = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

	rc = ccdrbg_init(&info, rng, entropyInputBufferLength, entropyInputBuffer,
                         nonceBufferLength, nonceBuffer, personalizationStringBufferLength, personalizationStringBuffer);
	if (rc)
	{
		failf("ccdrbg_init");
        rc = CCPOST_GENERIC_FAILURE;
        goto errOut;
	}

	rc = ccdrbg_reseed(&info, rng, entropyInputPR1BufferLength, entropyInputPR1Buffer,
                                  additionalInput1BufferLength, additionalInput1Buffer);
	if (rc)
	{
		failf("ccdrbg_reseed");
        rc = CCPOST_GENERIC_FAILURE;
        goto errOut;
	}

	rc = ccdrbg_generate(&info, rng, 16, resultBuffer, 0, NULL);
	if (rc)
	{
		failf("ccdrbg_generate");
        rc = CCPOST_GENERIC_FAILURE;
        goto errOut;
	}

	rc = ccdrbg_reseed(&info, rng, 
                                  entropyInputPR2BufferLength, entropyInputPR2Buffer,  
                                  additionalInput2BufferLength, additionalInput2Buffer);
	if (rc)
	{
		failf("ccdrbg_reseed 2");
        rc = CCPOST_GENERIC_FAILURE;
        goto errOut;
	}

	rc = ccdrbg_generate(&info, rng, 16, resultBuffer, 0, NULL);
	if (rc)
	{
		failf("ccdrbg_generate 2");
        rc = CCPOST_GENERIC_FAILURE;
        goto errOut;
	}

	rc = (memcmp(resultBuffer, returnedBitsBuffer, returnedBitsBufferLength)) ? CCPOST_KAT_FAILURE : 0;
	if (rc)
	{
		failf("memcmp");
	}

errOut:
    CC_FREE_WORKSPACE(ws);
	return rc;
}
