/* Copyright (c) (2010-2012,2014-2019,2021) Apple Inc. All rights reserved.
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
#include "ccmode_gcm_tables.h"

#include "fipspost_trace.h"

int ccmode_gcm_init(const struct ccmode_gcm *gcm, ccgcm_ctx *key,
                     size_t rawkey_nbytes, const void *rawkey)
{
    FIPSPOST_TRACE_EVENT;

    const struct ccmode_ecb *ecb = gcm->custom;
    cc_require(ecb->block_size == CCGCM_BLOCK_NBYTES, errOut); //gcm only takes 128-bit block ciphers

    cc_assert(((GCM_TABLE_SIZE % CCN_UNIT_SIZE) == 0));
#if CCMODE_GCM_VNG_SPEEDUP
    cc_assert((((uintptr_t)key & 0xF) == 0)); // key context must be aligned on 16 bytes
#endif
    _CCMODE_GCM_ECB_MODE(key)->ecb = ecb;
    _CCMODE_GCM_ECB_MODE(key)->ecb_key = &_CCMODE_GCM_KEY(key)->u[0] + GCM_TABLE_SIZE;
    _CCMODE_GCM_ECB_MODE(key)->encdec = gcm->encdec;

    ecb->init(ecb, CCMODE_GCM_KEY_ECB_KEY(key), rawkey_nbytes, rawkey);
    
    _CCMODE_GCM_KEY(key)->flags = 0;
    /* gmac init: X=0, PAD=0, H = E(0) */
    ccmode_gcm_reset(key);
    ecb->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1, CCMODE_GCM_KEY_X(key), CCMODE_GCM_KEY_H(key));

#if CCMODE_GCM_VNG_SPEEDUP
#ifdef  __x86_64__
    if (CC_HAS_AESNI() && CC_HAS_SupplementalSSE3())
#endif
        (void)gcm_init(CCMODE_GCM_VNG_KEY_Htable(key), CCMODE_GCM_KEY_H(key));

#endif

     return 0;
errOut:
    return -1;
}
