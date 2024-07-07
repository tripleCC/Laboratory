/* Copyright (c) (2010,2011,2012,2015,2016,2018,2019) Apple Inc. All rights reserved.
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

int ccmode_cfb_encrypt(cccfb_ctx *key,
                       size_t nbytes, const void *in, void *out) {
    const struct ccmode_ecb *ecb = CCMODE_CFB_KEY_ECB(key);
    const ccecb_ctx *ecb_key = CCMODE_CFB_KEY_ECB_KEY(key);
    uint8_t *iv = (uint8_t *)CCMODE_CFB_KEY_IV(key);
    uint8_t *pad = (uint8_t *)CCMODE_CFB_KEY_PAD(key);
    cc_size pad_len = CCMODE_CFB_KEY_PAD_LEN(key);
    const uint8_t *pt = in;
    uint8_t *ct = out;

    while (nbytes-- != 0) {
        if (pad_len == ecb->block_size) {
            ecb->ecb(ecb_key, 1, iv, pad);
            pad_len = 0;
        }

        iv[pad_len] = *ct++ = *pt++ ^ pad[pad_len];
        ++pad_len;
    }
    CCMODE_CFB_KEY_PAD_LEN(key) = pad_len;
    
    return 0;
}
