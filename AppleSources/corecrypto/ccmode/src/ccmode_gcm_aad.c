/* Copyright (c) (2011,2012,2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_runtime_config.h"
#include "ccaes_vng_gcm.h"
#include "ccmode_internal.h"

/**
 Add AAD to the GCM state
 @param key       The state
 @param in        The additional authentication data to add to the GCM state
 @param nbytes  The length of the AAD data.
 @return 0 on success
 */

//ccmode_gcm_aad(key, 0, NULL) is okay.
int ccmode_gcm_aad(ccgcm_ctx *key, size_t nbytes, const void *in)
{
    const uint8_t *bytes = in;
    uint8_t *X = CCMODE_GCM_KEY_X(key);
    uint32_t X_nbytes = _CCMODE_GCM_KEY(key)->aad_nbytes % CCGCM_BLOCK_NBYTES;
    uint32_t X_nbytes_needed = CCGCM_BLOCK_NBYTES - X_nbytes;
    
    cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_AAD, errOut);
    
    // finish a partial block, if possible
    if (X_nbytes > 0 && nbytes >= X_nbytes_needed) {
        cc_xor(X_nbytes_needed, (X + X_nbytes), (X + X_nbytes), bytes);
        ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
        
        nbytes -= X_nbytes_needed;
        bytes += X_nbytes_needed;
        _CCMODE_GCM_KEY(key)->aad_nbytes += X_nbytes_needed;
        X_nbytes = 0;
    }

    // process full blocks, if any
    if (X_nbytes == 0) {
#if CCMODE_GCM_VNG_SPEEDUP
#ifdef  __x86_64__
        if (CC_HAS_AESNI() && CC_HAS_SupplementalSSE3())
#endif //__x86_64__
            if (nbytes >= CCGCM_BLOCK_NBYTES) {
                size_t j = nbytes & (size_t)(-16);
                gcm_ghash(X, (void *) CCMODE_GCM_VNG_KEY_Htable(key), (const void*) bytes, j);
                
                bytes += j;
                nbytes -= j;
                _CCMODE_GCM_KEY(key)->aad_nbytes += j;
            }
#endif //CCMODE_GCM_VNG_SPEEDUP
        
        /* fallback in absence of vng */
        /* including this in ifdef is tricky */
        /* due to runtime checks for aesni and sse3 */
        while (nbytes >= CCGCM_BLOCK_NBYTES) {
            cc_xor(CCGCM_BLOCK_NBYTES, X, X, bytes);
            ccmode_gcm_mult_h(key, X);
            
            nbytes -= CCGCM_BLOCK_NBYTES;
            bytes += CCGCM_BLOCK_NBYTES;
            _CCMODE_GCM_KEY(key)->aad_nbytes += CCGCM_BLOCK_NBYTES;
        }
    }

    // process the remainder
    if (nbytes > 0) {
        cc_xor(nbytes, (X + X_nbytes), (X + X_nbytes), bytes);
        _CCMODE_GCM_KEY(key)->aad_nbytes += nbytes;
    }

    return 0;
errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;

}
