/* Copyright (c) (2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

#if CCAES_ARM_ASM

#include "AccelerateCrypto.h"

#include "ccmode_internal.h"
#include "arm_aes.h"
#include <corecrypto/ccaes.h>

extern void ccaes_cfb_encrypt_vng_vector(const ccecb_ctx *ctx, uint8_t *iv, int nblocks, const uint8_t *in, uint8_t *out);

static int ccaes_cfb_encrypt_vng(cccfb_ctx *key, size_t nbytes, const void *in, void *out)
{

    const ccecb_ctx *ecb_key = CCMODE_CFB_KEY_ECB_KEY(key);
    uint8_t *iv = (uint8_t *)CCMODE_CFB_KEY_IV(key);
    const uint8_t *pt = in;
    uint8_t *ct = out;
    uint8_t *pad = (uint8_t *)CCMODE_CFB_KEY_PAD(key);
    cc_size pad_len = CCMODE_CFB_KEY_PAD_LEN(key);

    // if there is any previous iv encryption leftover
    while ((pad_len != CCAES_BLOCK_SIZE) && (nbytes != 0)) {
        iv[pad_len] = *ct++ = *pt++ ^ pad[pad_len];
        ++pad_len;
        nbytes--;
    }
    
  if (nbytes>=16) {
    size_t nblocks = nbytes / 16;
#if CC_ARM_ARCH_7 && CC_KERNEL
    /*
     The armv7 implementation of ccaes_arm_encrypt needs in/out to be 4-bytes aligned in kernel mode.
     */
    if ((((int)in&0x03)==0) && (((int)out&0x03)==0)) {  // both in and out are 4-byte aligned
        ccaes_cfb_encrypt_vng_vector(ecb_key, iv, (int)nblocks, pt, ct);
        nblocks = nblocks<<4;
        pt += nblocks;
        ct += nblocks;
        nbytes -= nblocks;
    } else {
        uint32_t aligned_in[4], aligned_out[4];
        while (nblocks) {
            cc_memcpy((void*)aligned_in, pt, CCAES_BLOCK_SIZE);
            ccaes_cfb_encrypt_vng_vector(ecb_key, iv, 1, (const uint8_t*)aligned_in, (uint8_t*)aligned_out);
            cc_memcpy(ct, (void*)aligned_out, CCAES_BLOCK_SIZE);
            pt += CCAES_BLOCK_SIZE;
            ct += CCAES_BLOCK_SIZE;
            nblocks--;
            nbytes -= CCAES_BLOCK_SIZE;
        }
    }
#else
    ccaes_cfb_encrypt_vng_vector(ecb_key, iv, (int)nblocks, pt, ct);
    nblocks = nblocks<<4;
    pt += nblocks;
    ct += nblocks;
    nbytes -= nblocks;
#endif
  }

    while (nbytes != 0) {
        if (pad_len == CCAES_BLOCK_SIZE) {
            if (AccelerateCrypto_AES_encrypt(iv, pad, (const AccelerateCrypto_AES_ctx*) ecb_key)) {
                return -1;
            }
            pad_len = 0;
        }

        iv[pad_len] = *ct++ = *pt++ ^ pad[pad_len];
        ++pad_len;
        nbytes--;
    }
    CCMODE_CFB_KEY_PAD_LEN(key) = pad_len;

    return 0;
}

const struct ccmode_cfb ccaes_arm_cfb_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(cccfb_ctx)) + 3 * sizeof(ccaes_arm_encrypt_ctx),
    .block_size = 1,
    .init = ccmode_cfb_init,
    .cfb = ccaes_cfb_encrypt_vng,
    .custom = (&ccaes_arm_ecb_encrypt_mode), \
};

#endif
