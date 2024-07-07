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

int ccmode_cfb8_init(const struct ccmode_cfb8 *cfb8, cccfb8_ctx *key,
                      size_t rawkey_len, const void *rawkey, const void *iv) {
    int rc;
    const struct ccmode_ecb *ecb = cfb8->custom;
    CCMODE_CFB8_KEY_ECB(key) = ecb;
    cc_unit *pad = CCMODE_CFB8_KEY_PAD(key);
    cc_unit *ivbuf = CCMODE_CFB8_KEY_IV(key);
    if (iv)
        cc_memcpy(ivbuf, iv, ecb->block_size);
    else
        cc_clear(ecb->block_size, ivbuf);

    rc = ecb->init(ecb, CCMODE_CFB8_KEY_ECB_KEY(key), rawkey_len, rawkey);
    ecb->ecb(CCMODE_CFB8_KEY_ECB_KEY(key), 1, ivbuf, pad);
    return rc;
}
