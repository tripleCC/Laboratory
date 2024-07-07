/* Copyright (c) (2011,2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
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

/*!
 GCM multiply by H
 @param key   The GCM state which holds the H value
 @param I     The value to multiply H by
 */
void ccmode_gcm_mult_h(ccgcm_ctx *key, unsigned char *I)
{
#if CCMODE_GCM_VNG_SPEEDUP
#ifdef  __x86_64__
    if (!(CC_HAS_AESNI() && CC_HAS_SupplementalSSE3())) {
        //It can handle in and out buffers to be the same
        ccmode_gcm_gf_mult(CCMODE_GCM_KEY_H(key), I, I);
        return;
    } else
#endif
    {
        // CCMODE_GCM_VNG_KEY_Htable must be the second argument. gcm_gmult() is not a general multiplier function.
        gcm_gmult(I, CCMODE_GCM_VNG_KEY_Htable(key), I );
        return;
    }
#else
    //It can handle in and out buffers to be the same
    ccmode_gcm_gf_mult(CCMODE_GCM_KEY_H(key), I, I);
#endif
}

