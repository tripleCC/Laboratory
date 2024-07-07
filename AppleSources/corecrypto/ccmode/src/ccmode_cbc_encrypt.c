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
#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

/* iv xor p -> ecb -> c, iv = c, p += 1, c += 1. */
int ccmode_cbc_encrypt(const cccbc_ctx *key, cccbc_iv *ivbuf,
                       size_t nblocks, const void *in, void *out) {
    const struct ccmode_ecb *ecb = ccmode_cbc_key_ecb(key);
    const ccecb_ctx *ecb_key = ccmode_cbc_key_ecb_key(key);
    if (nblocks) {
        const unsigned char *p = in;
        unsigned char *c = out;
        const void *iv = ivbuf;
        for (;;) {
            cc_xor(ecb->block_size, c, p, iv);
            ecb->ecb(ecb_key, 1, c, c);
            iv = c;
            if (--nblocks) {
                p += ecb->block_size;
                c += ecb->block_size;
            } else {
                /* Copy the last ciphertext into the iv. */
                cc_memcpy(ivbuf, iv, ecb->block_size);
                break;
            }
        }
    }
    
    return 0;
}
