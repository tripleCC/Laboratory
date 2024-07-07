/* Copyright (c) (2010-2012,2014-2017,2019,2020) Apple Inc. All rights reserved.
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

int ccmode_ctr_crypt(ccctr_ctx *key, size_t nbytes, const void *in, void *out)
{
    const struct ccmode_ecb *ecb = CCMODE_CTR_KEY_ECB(key);
    const ccecb_ctx *ecb_key = CCMODE_CTR_KEY_ECB_KEY(key);
    uint8_t *ctr = (uint8_t *)CCMODE_CTR_KEY_CTR(key);
    uint8_t *pad = (uint8_t *)CCMODE_CTR_KEY_PAD(key);
    size_t pad_offset = CCMODE_CTR_KEY_PAD_OFFSET(key);
    const uint8_t *in_bytes = in;
    // Counter is 64bit wide for cipher with block size of 64bit or more
    // This is to match the assembly
    const size_t max_counter_size = 8;
    const size_t counter_size = CC_MIN(ecb->block_size, max_counter_size);
    uint8_t *out_bytes = out;
    size_t n;

    while (nbytes) {
        if (pad_offset == ecb->block_size) {
            ecb->ecb(ecb_key, 1, ctr, pad);
            pad_offset = 0;

            /* increment the big endian counter */
            inc_uint(ctr + ecb->block_size - counter_size, counter_size);
        }

        n = CC_MIN(nbytes, ecb->block_size - pad_offset);
        cc_xor(n, out_bytes, in_bytes, pad + pad_offset);
        nbytes -= n;
        in_bytes += n;
        out_bytes += n;
        pad_offset += n;
    }
    CCMODE_CTR_KEY_PAD_OFFSET(key) = pad_offset;

    return 0;
}
