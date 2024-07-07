/* Copyright (c) (2015,2016,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccrsa_priv.h>

int ccrsa_emsa_pss_encode(const struct ccdigest_info* di, const struct ccdigest_info* MgfDi,
                    size_t sSize, const uint8_t *salt,
                    size_t hSize, const uint8_t *mHash,
                    size_t emBits, uint8_t *EM)
{
    CC_ENSURE_DIT_ENABLED

    const size_t emSize = cc_ceiling(emBits,8);
    int rc=0;
    
    
    //0.
    if(emBits< 8*hSize + 8*sSize + 9)
        return CCRSA_ENCODING_ERROR;
    //1.
    
    //2. This function get the hash of the input message in mHash
    //3.
    if(emSize < hSize + sSize + 2)
        return CCRSA_ENCODING_ERROR;
    
    //4. This function expects to get salt in salt input

    
    //5., 6. H = hash(00 00 00 00 00 00 00 00 || mHash ||salt)
    cc_assert(hSize==di->output_size); //or there will be a buffer overrun
    uint8_t *H = EM+emSize-hSize-1; //store H=hash() directly to the output EM
    const uint64_t zero = 0;
    ccdigest_di_decl(di, dc);
    ccdigest_init(di, dc);
    ccdigest_update(di, dc, sizeof(uint64_t), &zero);
    ccdigest_update(di, dc, hSize, mHash);
    if(sSize!=0) ccdigest_update(di, dc, sSize, salt); //sLen=0 can be passed to the function, which means no salt
    ccdigest_final(di, dc, H);
    ccdigest_di_clear(di, dc);
    
    //7.,8.
    //we create PS and DB on the fly. See step 10
    
    //9. mask generation function
    uint8_t *dbMask=EM; //use EM as temp buffer for dbMask
    //if( emSize-hSize-1 < MgfDi->output_size) ccmgf returns error. this is not part of the spec but not acceptable for MGF
    rc = ccmgf(MgfDi, emSize-hSize-1, dbMask, hSize, H); //take H and produce dbMask with the length of emLen-hLen-1

    //10.
    size_t i, j;
    const size_t len=emSize-sSize-hSize-2;
    uint8_t *maskedDB=EM; //store directly to EM
    //wachout maskedDB, dbMask and EM point to the same location
    for(i=0; i<len; i++) //len can be zero
        maskedDB[i] = 0 ^ dbMask[i];

    maskedDB[i] = 0x01 ^ dbMask[i]; i++;
    for(j=0; j<sSize; i++, j++)
         maskedDB[i] = salt[j] ^ dbMask[i];
        
    //11. this makes sure encoded message is smaller than modulus
    const size_t n=8*emSize-emBits;
    uint8_t mask;
    if(n<8) // 0<=n<8,  n==0 means emBits fits in an array of bytes and modBits has one extra bits ie modBits=1 mod 8
        mask = (uint8_t)0xff>>n;
    else{
        mask=0xff; //there is an error and mask value is irrelevant
        rc=-1;
    }
    maskedDB[0] &=mask;
    
    //12., 13.
    //EM <--- maskedDB length is emLen-hLen-1 this has been done in step 10.
    //EM+emLen-hLen-1 <--- H length is  hLen, this has been done at step 5.,6.
    EM[emSize-1] = 0xbc;
    return rc;
}


