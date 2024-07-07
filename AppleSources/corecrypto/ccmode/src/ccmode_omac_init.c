/* Copyright (c) (2010,2011,2012,2015,2016,2019) Apple Inc. All rights reserved.
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

int ccmode_omac_init(const struct ccmode_omac *omac, ccomac_ctx *key,
                     size_t tweak_len,
                     size_t rawkey_len, const void *rawkey) {
    const struct ccmode_ecb *ecb = omac->custom;
    CCMODE_OMAC_KEY_ECB(key) = ecb;
    CCMODE_OMAC_KEY_TWEAK_LEN(key) = tweak_len;
    return ecb->init(ecb, CCMODE_OMAC_KEY_ECB_KEY(key), rawkey_len, rawkey);
}
