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
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include "ccaes_internal.h"
#include <corecrypto/cc_error.h>

#if CCAES_INTEL_ASM

#include "vng_aesPriv.h"

struct ccaes_intel_decrypt_wrapper_ctx
{
    vng_aes_decrypt_ctx cx[1];
};

#define CBC_CTX_SIZE sizeof(struct ccaes_intel_decrypt_wrapper_ctx)

/* ==========================================================================
	VNG Optimized AES implementation.  This implementation is optimized but
	does not use the AESNI instructions
   ========================================================================== */


/* Initialize a context with the key and iv*/
static int init_wrapper_opt(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                            size_t rawkey_len, const void *rawkey)
{
	struct ccaes_intel_decrypt_wrapper_ctx *ctx = (struct ccaes_intel_decrypt_wrapper_ctx *) key;
    int rc = ccaes_key_length_validation(rawkey_len);
    cc_require_or_return(rc == CCERR_OK, rc);
	return vng_aes_decrypt_opt_key(rawkey, (int)rawkey_len, ctx->cx);
}

/* cbc encrypt or decrypt nblocks from in to out, iv will be used and updated. */
static int cbc_wrapper_opt(const cccbc_ctx *key, cccbc_iv *iv, size_t nblocks,
                           const void *in, void *out)
{
    const struct ccaes_intel_decrypt_wrapper_ctx *ctx = (const struct ccaes_intel_decrypt_wrapper_ctx *) key;
    unsigned char lastiv[CCAES_BLOCK_SIZE];

    if (0 == nblocks) {
        return 0;
    }

    cc_memcpy(lastiv, (const uint8_t *)in + (nblocks-1) * CCAES_BLOCK_SIZE, CCAES_BLOCK_SIZE);

    vng_aes_decrypt_opt_cbc(in, (unsigned char *) iv, (unsigned int) nblocks, out, ctx->cx);

    cc_memcpy(iv, lastiv, CCAES_BLOCK_SIZE);

    return 0;
}

const struct ccmode_cbc ccaes_intel_cbc_decrypt_opt_mode = {
    .size = CBC_CTX_SIZE,
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_opt,
    .cbc = cbc_wrapper_opt,
    .custom = NULL,
};

/* ==========================================================================
	VNG AESNI implementation.  This implementation uses the AESNI 
	instructions
   ========================================================================== */

/* Initialize a context with the key and iv*/
static int init_wrapper_aesni(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                              size_t rawkey_len, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_len);
    cc_require_or_return(rc == CCERR_OK, rc);
    struct ccaes_intel_decrypt_wrapper_ctx *ctx = (struct ccaes_intel_decrypt_wrapper_ctx *) key;
	return vng_aes_decrypt_aesni_key(rawkey, (int)rawkey_len, ctx->cx);

}

/* cbc encrypt or decrypt nblocks from in to out, iv will be used and updated. */
static int cbc_wrapper_aesni(const cccbc_ctx *key, cccbc_iv *iv, size_t nblocks,
                             const void *in, void *out)
{
    const struct ccaes_intel_decrypt_wrapper_ctx *ctx = (const struct ccaes_intel_decrypt_wrapper_ctx *) key;
    unsigned char lastiv[CCAES_BLOCK_SIZE];

    if (0 == nblocks) {
        return 0;
    }

    cc_memcpy(lastiv, (const uint8_t *)in + (nblocks-1) * CCAES_BLOCK_SIZE, CCAES_BLOCK_SIZE);

    vng_aes_decrypt_aesni_cbc(in, (unsigned char *) iv, (unsigned int) nblocks, out, ctx->cx);

    cc_memcpy(iv, lastiv, CCAES_BLOCK_SIZE);

    return 0;
}

const struct ccmode_cbc ccaes_intel_cbc_decrypt_aesni_mode = {
    .size = CBC_CTX_SIZE,
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_aesni,
    .cbc = cbc_wrapper_aesni,
    .custom = NULL,
};

#endif /* CCAES_INTEL_ASM */

