/* Copyright (c) (2011,2012,2014-2016,2018-2021) Apple Inc. All rights reserved.
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

#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>
#include "AccelerateCrypto.h"
#include "cc_macros.h"
#include <corecrypto/cc_error.h>
#include "ccaes_internal.h"

#include "arm_aes.h"

#if defined(__arm64__)
extern int ccaes_arm_decrypt_key(const struct ccmode_ecb *, ccecb_ctx *, size_t, const void *);

CC_INLINE int ccaes_arm_decrypt_ecb(const ccecb_ctx *key, size_t nblocks, const void *in, void *out)
{
    return AccelerateCrypto_ecb_AES_decrypt((const AccelerateCrypto_AES_ctx *)key, (uint32_t)nblocks, in, out);
}

// Wrapper for ccaes_arm_decrypt_key with key length validation that supports appropriate errors
static int ccaes_arm_decrypt_key_with_key_length_check(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key, size_t rawkey_nbytes, const void *rawkey) {
    int rc = ccaes_key_length_validation(rawkey_nbytes);
    cc_require_or_return(rc == CCERR_OK, rc);
    return ccaes_arm_decrypt_key(ecb, key, rawkey_nbytes, rawkey);
}

const struct ccmode_ecb ccaes_arm_ecb_decrypt_mode = {
    .size = sizeof(ccaes_arm_decrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_arm_decrypt_key_with_key_length_check,
    .ecb = ccaes_arm_decrypt_ecb,
    .impl = CC_IMPL_AES_ECB_ARM,
};
#else

static int init_wrapper(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                        size_t rawkey_nbytes, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_nbytes);
    cc_require_or_return(rc == CCERR_OK, rc);
    rawkey_nbytes = ccaes_key_length_to_nbytes(rawkey_nbytes);
    
    ccaes_arm_decrypt_ctx *ctx = (ccaes_arm_decrypt_ctx *) key;
    uint32_t alignkey[CCAES_KEY_SIZE_256/sizeof(uint32_t)];

    cc_memcpy(alignkey, rawkey, rawkey_nbytes); /* arm implementation requires 32bits aligned key */
    
    return ccaes_arm_decrypt_key((const unsigned char *)alignkey, (int)rawkey_nbytes, ctx);
}

/* cbc encrypt or decrypt nblocks from in to out. */
static int ecb_impl(const ccecb_ctx *key, size_t nblocks, const uint8_t *in, uint8_t *out)
{
    const ccaes_arm_decrypt_ctx *ctx = (const ccaes_arm_decrypt_ctx *) key;

#if CC_KERNEL
	if ((((int)in&0x03)==0) && (((int)out&0x03)==0)) {        // both in and out are word aligned, which is needed in assembly implementation
#endif
        while(nblocks--) {
            if (AccelerateCrypto_AES_decrypt(in, out, (const AccelerateCrypto_AES_ctx *) ctx)) {
                return -1;
            }
            in += CCAES_BLOCK_SIZE;
            out += CCAES_BLOCK_SIZE;
        }
#if CC_KERNEL
    } else {
        uint32_t tin[CCAES_BLOCK_SIZE/sizeof(uint32_t)];
        uint32_t tout[CCAES_BLOCK_SIZE/sizeof(uint32_t)];
        while(nblocks--) {
            cc_memcpy((void*)tin, in, CCAES_BLOCK_SIZE);
            if (AccelerateCrypto_AES_decrypt((const void *)tin, (void *)tout, (const AccelerateCrypto_AES_ctx *) ctx)) {
                return -1;
            }
            cc_memcpy(out, (void*)tout, CCAES_BLOCK_SIZE);
            in += CCAES_BLOCK_SIZE;
            out += CCAES_BLOCK_SIZE;
        }
    }
#endif
    return 0;
}

static int ecb_wrapper(const ccecb_ctx *key, size_t nblocks, const void *in, void *out)
{
    return ecb_impl(key, nblocks, in, out);
}

const struct ccmode_ecb ccaes_arm_ecb_decrypt_mode = {
    .size = sizeof(ccaes_arm_decrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper,
    .ecb = ecb_wrapper,
    .impl = CC_IMPL_AES_ECB_ARM,
};
#endif

#endif /* CCAES_ARM_ASM */
