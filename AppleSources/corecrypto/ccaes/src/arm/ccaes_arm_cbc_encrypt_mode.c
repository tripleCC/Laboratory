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
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include <corecrypto/cc_error.h>
#include "ccaes_internal.h"

#include "arm_aes.h"

#if CCAES_ARM_ASM

struct ccaes_arm_encrypt_wrapper_ctx
{
    ccaes_arm_encrypt_ctx cx[1];
};


#if defined(__arm64__)
extern int ccaes_arm_encrypt_key(const struct ccmode_cbc *, cccbc_ctx *, size_t, const void *);
extern int ccaes_arm_encrypt_cbc(const cccbc_ctx *, cccbc_iv *, size_t, const void *, void *);

// Wrapper for ccaes_arm_encrypt_key with key length validation that supports appropriate errors
static int ccaes_arm_encrypt_key_with_length_check(const struct ccmode_cbc *cbc, cccbc_ctx *key, size_t rawkey_nbytes, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_nbytes);
    cc_require_or_return(rc == CCERR_OK, rc);
    return ccaes_arm_encrypt_key(cbc, key, rawkey_nbytes, rawkey);
}

const struct ccmode_cbc ccaes_arm_cbc_encrypt_mode = {
    .size = sizeof(struct ccaes_arm_encrypt_wrapper_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_arm_encrypt_key_with_length_check,
    .cbc = ccaes_arm_encrypt_cbc,
    .custom = NULL,
};
#else
static int init_wrapper(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                        size_t rawkey_nbytes, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_nbytes);
    cc_require_or_return(rc == CCERR_OK, rc);
    rawkey_nbytes = ccaes_key_length_to_nbytes(rawkey_nbytes);

    struct ccaes_arm_encrypt_wrapper_ctx *ctx = (struct ccaes_arm_encrypt_wrapper_ctx *) key;
    uint32_t alignkey[CCAES_KEY_SIZE_256/sizeof(uint32_t)];

    cc_memcpy(alignkey, rawkey, rawkey_nbytes); /* arm implementation requires 32bits aligned key */

    return ccaes_arm_encrypt_key((uint8_t *)alignkey, (int)rawkey_nbytes, ctx->cx);
}
/* cbc encrypt or decrypt nblocks from in to out, iv will be used and updated. */
static int cbc_wrapper(const cccbc_ctx *key, cccbc_iv *iv,
                       size_t nblocks, const void *in, void *out)
{
    const struct ccaes_arm_encrypt_wrapper_ctx *ctx = (const struct ccaes_arm_encrypt_wrapper_ctx *) key;

    if (nblocks == 0) {
        return 0;
    }

    ccaes_arm_encrypt_cbc(in, (unsigned char *)iv, nblocks, out, ctx->cx);

    cc_memcpy(iv, (uint8_t *)out + (nblocks-1) * CCAES_BLOCK_SIZE, CCAES_BLOCK_SIZE);

    return 0;
}

const struct ccmode_cbc ccaes_arm_cbc_encrypt_mode = {
    .size = sizeof(struct ccaes_arm_encrypt_wrapper_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper,
    .cbc = cbc_wrapper,
    .custom = NULL,
};
#endif

#endif /* CCAES_ARM_ASM */
