/* Copyright (c) (2014-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include "ccaes_vng_ctr.h"

#if  CCMODE_CTR_VNG_SPEEDUP

// In assembly
extern void aes_ctr_crypt(const void *pt, void *ct, int, void *ctr, void *) __asm__("_aes_ctr_crypt");

// for arm64 or intel aesni
int ccaes_vng_ctr_crypt(ccctr_ctx *key,
                        size_t nbytes, const void *in, void *out) {
    const struct ccmode_ecb *ecb = CCMODE_CTR_KEY_ECB(key);
    ccecb_ctx *ecb_key = CCMODE_CTR_KEY_ECB_KEY(key);
    uint8_t *ctr = (uint8_t *)CCMODE_CTR_KEY_CTR(key);
    uint8_t *pad = (uint8_t *)CCMODE_CTR_KEY_PAD(key);
    cc_size pad_offset = CCMODE_CTR_KEY_PAD_OFFSET(key);
    const uint8_t *pt = in;
    uint8_t *ct = out;

    while (nbytes) {
        if (pad_offset == CCAES_BLOCK_SIZE) {

#ifdef  __x86_64__
            if ( CC_HAS_AESNI() && CC_HAS_SupplementalSSE3() )
#endif  // __x86_64__
            {
                if (nbytes >= CCAES_BLOCK_SIZE) {
                    size_t j = nbytes & (size_t)(-CCAES_BLOCK_SIZE);
                    aes_ctr_crypt((const void*) pt, (void*) ct, (int)j, (void *) ctr, (void *) ecb_key);
                    ct += j;    pt += j;    nbytes -= j;
                }
            }
            ecb->ecb(ecb_key, 1, ctr, pad);
            pad_offset = 0;

            /* increment the big endian counter (64bit) */
            for (size_t x = CCAES_BLOCK_SIZE; x-- > CCAES_BLOCK_SIZE-8;) {
                ctr[x] = (ctr[x] + (unsigned char)1) & (unsigned char)255;
                if (ctr[x] != (unsigned char)0) {
                    break;
                }
            }

            if (nbytes==0) break;
        }

        do {
            *ct++ = *pt++ ^ pad[pad_offset++];
            --nbytes;
        } while ((nbytes>0)&&(pad_offset<CCAES_BLOCK_SIZE));
    }
    CCMODE_CTR_KEY_PAD_OFFSET(key) = pad_offset;
    
    return 0;
}

#endif  // CCMODE_CTR_VNG_SPEEDUP
