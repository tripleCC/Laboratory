/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
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

int ccmode_ctr_init(const struct ccmode_ctr *ctr, ccctr_ctx *key,
                    size_t rawkey_len, const void *rawkey,
                    const void *iv) {
    int rc;
    const struct ccmode_ecb *ecb = ctr->custom;
    CCMODE_CTR_KEY_ECB(key) = ecb;

    rc = ecb->init(ecb, CCMODE_CTR_KEY_ECB_KEY(key), rawkey_len, rawkey);
    
    ccctr_setctr(ctr, key, iv);

    return rc;
}
