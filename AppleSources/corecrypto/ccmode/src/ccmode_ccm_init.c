/* Copyright (c) (2012,2015,2019) Apple Inc. All rights reserved.
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

int ccmode_ccm_init(const struct ccmode_ccm *ccm, ccccm_ctx *key, size_t rawkey_len, const void *rawkey) {
    const struct ccmode_ecb *ecb = ccm->custom;
    CCMODE_CCM_KEY_ECB(key) = ecb;
    ecb->init(ecb, CCMODE_CCM_KEY_ECB_KEY(key), rawkey_len, rawkey);

    return 0;
}
