/* Copyright (c) (2015,2016,2019-2021) Apple Inc. All rights reserved.
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
#include "ccmode_internal.h"
#include "arm_aes.h"
#include <corecrypto/ccaes.h>

extern void ccaes_xts_encrypt_vng_vector(void *out, const void *in, cc_unit *tweak, size_t nblocks, const void *);

static void *ccaes_xts_encrypt_vng(const ccxts_ctx *key, ccxts_tweak *tweak,
                                   size_t nblocks, const uint8_t *in, uint8_t *out)
{
    size_t numBlocks = CCMODE_XTS_TWEAK_BLOCK_PROCESSED(tweak);
    numBlocks += nblocks;
    if (numBlocks > (1 << 20))
    {
        return NULL;
    }
    CCMODE_XTS_TWEAK_BLOCK_PROCESSED(tweak) = numBlocks;
    cc_unit *t=CCMODE_XTS_TWEAK_VALUE(tweak);
#if CC_ARM_ARCH_7 && CC_KERNEL
    /*
     The armv7 implementation of ccaes_arm_encrypt needs in/out to be 4-bytes aligned in kernel mode.
     */
    int aligned_in[4], aligned_out[4];
    if ((((int)in&0x03)==0) && (((int)out&0x03)==0)) {  // both in and out are 4-byte aligned
        if (nblocks)
            ccaes_xts_encrypt_vng_vector(out, in, t, nblocks, ccmode_xts_key_data_key(key));
    } else {
        while (nblocks) {
            cc_memcpy((void*)aligned_in, in, CCAES_BLOCK_SIZE);
            ccaes_xts_encrypt_vng_vector(aligned_out, aligned_in, t, 1, ccmode_xts_key_data_key(key));
            cc_memcpy(out, (void*)aligned_out, CCAES_BLOCK_SIZE);
            in += CCAES_BLOCK_SIZE;
            out += CCAES_BLOCK_SIZE;
            nblocks--;
        }
    }
#else
    const cc_unit *input = (const cc_unit *)in;
    cc_unit *output = (cc_unit *)out;
    if (nblocks) {
        ccaes_xts_encrypt_vng_vector(output, input, t, nblocks, ccmode_xts_key_data_key(key));
    }
#endif
    return t;
}

static void *ccaes_xts_encrypt_vng_wrapper(const ccxts_ctx *key, ccxts_tweak *tweak,
                                           size_t nblocks, const void *in, void *out)
{
    return ccaes_xts_encrypt_vng(key, tweak, nblocks, in, out);
}

const struct ccmode_xts ccaes_arm_xts_encrypt_mode = {
    .size = ccn_sizeof_size(sizeof(struct _ccmode_xts_key)) + 2 * ccn_sizeof_size(sizeof(ccaes_arm_encrypt_ctx)),
    .tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) + ccn_sizeof_size(CCAES_BLOCK_SIZE),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccmode_xts_init,
    .key_sched = ccmode_xts_key_sched,
    .set_tweak = ccmode_xts_set_tweak,
    .xts = ccaes_xts_encrypt_vng_wrapper,
    .custom = (&ccaes_arm_ecb_encrypt_mode),
    .custom1 = (&ccaes_arm_ecb_encrypt_mode),
    .impl = CC_IMPL_AES_XTS_ARM,
};


#endif


