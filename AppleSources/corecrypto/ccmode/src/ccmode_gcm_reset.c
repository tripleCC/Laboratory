/* Copyright (c) (2012,2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

int ccmode_gcm_reset(ccgcm_ctx *key)
{
    cc_clear(16, CCMODE_GCM_KEY_X(key));
    cc_clear(16, CCMODE_GCM_KEY_PAD(key));
    CCMODE_GCM_KEY_PAD_LEN(key) = 0;
    _CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_IV;
    _CCMODE_GCM_KEY(key)->aad_nbytes = 0;
    _CCMODE_GCM_KEY(key)->text_nbytes = 0;

    return 0;
}
