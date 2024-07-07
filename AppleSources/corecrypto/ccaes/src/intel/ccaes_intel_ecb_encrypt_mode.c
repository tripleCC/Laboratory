/* Copyright (c) (2012,2015,2016,2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_config.h>
#include "AccelerateCrypto.h"
#include "cc_macros.h"
#include <corecrypto/cc_error.h>
#include "ccaes_internal.h"

#if CCAES_INTEL_ASM

#include "vng_aesPriv.h"
#define ECB_CTX_SIZE sizeof(vng_aes_encrypt_ctx) 		/* The size of the context */

/* ==========================================================================
	VNG Optimized AES implementation.  This implementation is optimized but
	does not use the AESNI instructions
   ========================================================================== */

/* Initialize a context with the key */
static int init_wrapper_opt(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                            size_t rawkey_len, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_len);
    cc_require_or_return(rc == CCERR_OK, rc);
    return vng_aes_encrypt_opt_key((const unsigned char *)rawkey, (int) rawkey_len, (vng_aes_encrypt_ctx*) key);
}

/* cbc encrypt or decrypt nblocks from in to out. */
static int ecb_wrapper_opt(const ccecb_ctx *key, size_t nblocks, const void *in, void *out)
{
    for (unsigned i = 0; i < nblocks; i++) {
        size_t offset = CCAES_BLOCK_SIZE * i;
        AccelerateCrypto_AES_encrypt_nonaesni((const unsigned char *)in + offset,
                                              (unsigned char *)out + offset,
                                              (const AccelerateCrypto_AES_ctx *)key);
    }

    return 0;
}

const struct ccmode_ecb ccaes_intel_ecb_encrypt_opt_mode = {
    .size = ECB_CTX_SIZE,
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_opt,
    .ecb = ecb_wrapper_opt,
    .impl = CC_IMPL_AES_ECB_INTEL_OPT,
};

/* ==========================================================================
	VNG AESNI implementation.  This implementation uses the AESNI 
	instructions
   ========================================================================== */

/* Initialize a context with the key */
static int init_wrapper_aesni(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                              size_t rawkey_len, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_len);
    cc_require_or_return(rc == CCERR_OK, rc);
    return vng_aes_encrypt_aesni_key((const unsigned char *)rawkey, (int) rawkey_len, (vng_aes_encrypt_ctx*) key);
}

static int ecb_wrapper_aesni(const ccecb_ctx *key, size_t nblocks, const void *in,
                             void *out)
{
    for (unsigned i = 0; i < nblocks; i++) {
        size_t offset = CCAES_BLOCK_SIZE * i;
        AccelerateCrypto_AES_encrypt_aesni((const unsigned char *)in + offset,
                                           (unsigned char *)out + offset,
                                           (const AccelerateCrypto_AES_ctx *)key);
    }

    return 0;
}

const struct ccmode_ecb ccaes_intel_ecb_encrypt_aesni_mode = {
    .size = ECB_CTX_SIZE,
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_aesni,
    .ecb = ecb_wrapper_aesni,
    .impl = CC_IMPL_AES_ECB_INTEL_AESNI,
};

#endif /* CCAES_INTEL_ASM */
