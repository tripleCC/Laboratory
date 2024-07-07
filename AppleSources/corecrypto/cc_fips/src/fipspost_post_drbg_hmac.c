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
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccsha2.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_drbg_hmac.h"
#include "cc_memory.h"

// Test HMAC DRBG from
/*
 [SHA-256]
 [PredictionResistance = False]
 [EntropyInputLen = 256]
 [NonceLen = 128]
 [PersonalizationStringLen = 256]
 [AdditionalInputLen = 256]
 [ReturnedBitsLen = 1024]

 COUNT = 0
 EntropyInput = cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416
 Nonce = d0c0d01d156016d0eb6b7e9c7c3c8da8
 PersonalizationString = 6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa
 ** INSTANTIATE:
	V   = 6c02577c505aed360be7b1cecb61068d8765be1391bacb10f4180d91bd3915db
	Key = 108a7674f3348216c91f5745dd87a919f552fc44373b84ad4b3b843a26b574cb
 EntropyInputReseed = 8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82
 AdditionalInputReseed = 1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3
 ** RESEED:
	V   = 21a645aeca821899e7e733a10f64565deee5ced3cd5c0356b66c76dc8a906e69
	Key = e57f901d4bff2909f09467003096edfdb46c89af6bd82e904d11b6753d645c90

 AdditionalInput = 16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff
 ** GENERATE (FIRST CALL):
	V   = 490c0b7786c80f16ad5ee1cc0efd29618968dce14cccebecec8964ea8a41b439
	Key = 648f92d385c3fbf61526deef48ca5ca4dfe4646d82fe8e73bc1705824e181dc9

 AdditionalInput = 53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2
 ReturnedBits = dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a183e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a089320b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f
 ** GENERATE (SECOND CALL):
	V   = 47390036d5cb308cf9592fdfe95bf19b8ed1a3db88ed8c3b2b2d77540dfb5470
	Key = db4853ca51700d43c5b6d63eb6cd20ea2dbe3dff512f2dc9531b5b3d9120121c
 */
int fipspost_post_drbg_hmac(uint32_t fips_mode)
{
    int result = CCPOST_GENERIC_FAILURE;

    // Init
    const unsigned char  entropyInputBuffer[] =   {0xcd, 0xb0, 0xd9, 0x11, 0x7c, 0xc6, 0xdb, 0xc9, 0xef, 0x9d, 0xcb, 0x06,
        0xa9, 0x75, 0x79, 0x84, 0x1d, 0x72, 0xdc, 0x18, 0xb2, 0xd4, 0x6a, 0x1c,
        0xb6, 0x1e, 0x31, 0x40, 0x12, 0xbd, 0xf4, 0x16};

    const unsigned char nonceBuffer[] = {0xd0, 0xc0, 0xd0, 0x1d, 0x15, 0x60, 0x16, 0xd0, 0xeb, 0x6b, 0x7e, 0x9c,
        0x7c, 0x3c, 0x8d, 0xa8};

    const unsigned char personalizationStringBuffer[] = {0x6f, 0x0f, 0xb9, 0xea, 0xb3, 0xf9, 0xea, 0x7a, 0xb0, 0xa7, 0x19, 0xbf,
        0xa8, 0x79, 0xbf, 0x0a, 0xae, 0xd6, 0x83, 0x30, 0x7f, 0xda, 0x0c, 0x6d,
        0x73, 0xce, 0x01, 0x8b, 0x6e, 0x34, 0xfa, 0xaa};

    // Reseed
    const unsigned char entropyInputReseedBuffer[] = {
        0x8e, 0xc6, 0xf7, 0xd5, 0xa8, 0xe2, 0xe8, 0x8f, 0x43, 0x98, 0x6f, 0x70,
        0xb8, 0x6e, 0x05, 0x0d, 0x07, 0xc8, 0x4b, 0x93, 0x1b, 0xcf, 0x18, 0xe6,
        0x01, 0xc5, 0xa3, 0xee, 0xe3, 0x06, 0x4c, 0x82};

    const unsigned char additionalInputReseedBuffer[] = {
        0x1a, 0xb4, 0xca, 0x90, 0x14, 0xfa, 0x98, 0xa5, 0x59, 0x38, 0x31, 0x6d,
        0xe8, 0xba, 0x5a, 0x68, 0xc6, 0x29, 0xb0, 0x74, 0x1b, 0xdd, 0x05, 0x8c,
        0x4d, 0x70, 0xc9, 0x1c, 0xda, 0x50, 0x99, 0xb3};

    // Info
    const unsigned char entropyInputPR1Buffer [] = {  0x16, 0xe2, 0xd0, 0x72, 0x1b, 0x58, 0xd8, 0x39, 0xa1, 0x22, 0x85, 0x2a,
        0xbd, 0x3b, 0xf2, 0xc9, 0x42, 0xa3, 0x1c, 0x84, 0xd8, 0x2f, 0xca, 0x74,
        0x21, 0x18, 0x71, 0x88, 0x0d, 0x71, 0x62, 0xff};

    const unsigned char entropyInputPR2Buffer []= {  0x53, 0x68, 0x6f, 0x04, 0x2a, 0x7b, 0x08, 0x7d, 0x5d, 0x2e, 0xca, 0x0d,
        0x2a, 0x96, 0xde, 0x13, 0x1f, 0x27, 0x5e, 0xd7, 0x15, 0x11, 0x89, 0xf7,
        0xca, 0x52, 0xde, 0xaa, 0x78, 0xb7, 0x9f, 0xb2};

    // Output
    unsigned char returnedBitsBuffer[] =   {
        0xdd, 0xa0, 0x4a, 0x2c, 0xa7, 0xb8, 0x14, 0x7a, 0xf1, 0x54, 0x8f, 0x5d,
        0x08, 0x65, 0x91, 0xca, 0x4f, 0xd9, 0x51, 0xa3, 0x45, 0xce, 0x52, 0xb3,
        0xcd, 0x49, 0xd4, 0x7e, 0x84, 0xaa, 0x31, 0xa1, 0x83, 0xe3, 0x1f, 0xbc,
        0x42, 0xa1, 0xff, 0x1d, 0x95, 0xaf, 0xec, 0x71, 0x43, 0xc8, 0x00, 0x8c,
        0x97, 0xbc, 0x2a, 0x9c, 0x09, 0x1d, 0xf0, 0xa7, 0x63, 0x84, 0x83, 0x91,
        0xf6, 0x8c, 0xb4, 0xa3, 0x66, 0xad, 0x89, 0x85, 0x7a, 0xc7, 0x25, 0xa5,
        0x3b, 0x30, 0x3d, 0xde, 0xa7, 0x67, 0xbe, 0x8d, 0xc5, 0xf6, 0x05, 0xb1,
        0xb9, 0x5f, 0x6d, 0x24, 0xc9, 0xf0, 0x6b, 0xe6, 0x5a, 0x97, 0x3a, 0x08,
        0x93, 0x20, 0xb3, 0xcc, 0x42, 0x56, 0x9d, 0xcf, 0xd4, 0xb9, 0x2b, 0x62,
        0xa9, 0x93, 0x78, 0x5b, 0x03, 0x01, 0xb3, 0xfc, 0x45, 0x24, 0x45, 0x65,
        0x6f, 0xce, 0x22, 0x66, 0x48, 0x27, 0xb8, 0x8f};

    uint8_t resultBuffer[128];
    memset(resultBuffer, 0, 16);

    static struct ccdrbg_info info;
    struct ccdrbg_nisthmac_custom custom;
   	custom.di = ccsha256_di();
    custom.strictFIPS = 0;

    ccdrbg_factory_nisthmac(&info, &custom);

    CC_DECL_WORKSPACE_OR_FAIL(ws, ccn_nof_size(info.size));
    struct ccdrbg_state* rng = (struct ccdrbg_state *)CC_ALLOC_WS(ws, ccn_nof_size(info.size));
    
    uint32_t rc=0;
    size_t rc_ctr=0;

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode))
    {
        returnedBitsBuffer[0] = returnedBitsBuffer[0] ^ 0x1;
    }

    if (0==ccdrbg_init(&info, rng, sizeof(entropyInputBuffer), entropyInputBuffer,
                   sizeof(nonceBuffer), nonceBuffer,
                       sizeof(personalizationStringBuffer), personalizationStringBuffer)) {rc|=1<<rc_ctr;}
    rc_ctr++;

    if (0==ccdrbg_reseed(&info, rng, sizeof(entropyInputReseedBuffer), entropyInputReseedBuffer,
                       sizeof(additionalInputReseedBuffer), additionalInputReseedBuffer))  {rc|=1<<rc_ctr;}
    rc_ctr++;

    if (0==ccdrbg_generate(&info, rng, sizeof(resultBuffer), resultBuffer,
                           sizeof(entropyInputPR1Buffer), entropyInputPR1Buffer)) {rc|=1<<rc_ctr;}
    rc_ctr++;

    if (0==ccdrbg_generate(&info, rng, sizeof(resultBuffer), resultBuffer,
                           sizeof(entropyInputPR2Buffer), entropyInputPR2Buffer)) {rc|=1<<rc_ctr;}
    rc_ctr++;

    // Check result
    result  = (rc != ((1<<rc_ctr)-1))
        || (memcmp(resultBuffer, returnedBitsBuffer, sizeof(returnedBitsBuffer))) ? CCPOST_GENERIC_FAILURE : 0;
    if (result)
    {
        failf("rc: %d", (rc != ((1 << rc_ctr) - 1)))
    }
    
    CC_FREE_WORKSPACE(ws);
    return result;
}
