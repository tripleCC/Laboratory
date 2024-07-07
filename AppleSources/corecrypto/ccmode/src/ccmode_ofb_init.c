/* Copyright (c) (2010-2012,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
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

int ccmode_ofb_init(const struct ccmode_ofb *ofb, ccofb_ctx *key,
                    size_t rawkey_len, const void *rawkey, const void *iv) {
    const struct ccmode_ecb *ecb = ofb->custom;
    CCMODE_OFB_KEY_ECB(key) = ecb;
    cc_memcpy(CCMODE_OFB_KEY_IV(key), iv, ecb->block_size);
    CCMODE_OFB_KEY_PAD_LEN(key) = ecb->block_size;
    return ecb->init(ecb, CCMODE_OFB_KEY_ECB_KEY(key), rawkey_len, rawkey);
}
