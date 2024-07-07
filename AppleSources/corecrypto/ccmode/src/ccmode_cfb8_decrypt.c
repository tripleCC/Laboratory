/* Copyright (c) (2010,2011,2013,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
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

int ccmode_cfb8_decrypt(cccfb8_ctx *key, size_t nbytes,
                        const void *in, void *out) {
    const struct ccmode_ecb *ecb = CCMODE_CFB8_KEY_ECB(key);
    const ccecb_ctx *ecb_key = CCMODE_CFB8_KEY_ECB_KEY(key);
    uint8_t *iv = (uint8_t *)CCMODE_CFB8_KEY_IV(key);
    uint8_t *pad = (uint8_t *)CCMODE_CFB8_KEY_PAD(key);
    const uint8_t *ct = in;
    uint8_t *pt = out;

    while (nbytes-- != 0) {
        cc_memmove(iv, iv + 1, ecb->block_size - 1);
        uint8_t cb = *ct;
        iv[ecb->block_size - 1] = cb;
        *pt = pad[0] ^ cb;
        ecb->ecb(ecb_key, 1, iv, pad);
        ++pt;
        ++ct;
    }
    
    return 0;
}
