/* Copyright (c) (2012,2015,2016,2019,2021) Apple Inc. All rights reserved.
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

#if CCAES_INTEL_ASM

#include "ccmode_internal.h"
#include "vng_aesPriv.h"

struct ccaes_intel_decrypt_wrapper_ctx
{
    vng_aes_decrypt_ctx cx[1];
    vng_aes_encrypt_ctx tweak_cx[1];
};

#define XTS_CTX_SIZE sizeof(struct ccaes_intel_decrypt_wrapper_ctx)

/* ==========================================================================
	VNG Optimized AES implementation.  This implementation is optimized but
	does not use the AESNI instructions
   ========================================================================== */

/* Create a xts key from a xts mode object.  The tweak_len here
 determines how long the tweak is in bytes, for each subsequent call to
 ccmode_xts->xts(). */
static void key_sched_wrapper_opt (const struct ccmode_xts *xts_not CC_UNUSED, ccxts_ctx *ctx,
                                   size_t key_nbytes, const void *data_key,
                                   const void *tweak_key)
{
    struct ccaes_intel_decrypt_wrapper_ctx *xts = (struct ccaes_intel_decrypt_wrapper_ctx *) ctx;

    vng_aes_decrypt_opt_key(data_key, (int)key_nbytes, xts->cx);
    vng_aes_encrypt_opt_key(tweak_key, (int)key_nbytes, xts->tweak_cx);
}

/* Set the tweak (sector number), the block within the sector zero. */
static int set_tweak_wrapper_opt(const ccxts_ctx *ctx, ccxts_tweak *tweak, const void *iv)
{
	const struct ccaes_intel_decrypt_wrapper_ctx *xts = (const struct ccaes_intel_decrypt_wrapper_ctx *) ctx;
    uint8_t *T=((struct ccaes_intel_xts_tweak_ctx *)tweak)->T;

    /* encrypt the tweak */
    AccelerateCrypto_AES_encrypt_nonaesni(iv, T, (const AccelerateCrypto_AES_ctx *)&xts->tweak_cx);

    return 0;
}

/* Encrypt blocks for a sector, clients must call set_tweak before calling
 this function.  Return a pointer to the current tweak (used by ccpad_xts). */
static void *xts_wrapper_opt(const ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nblocks,
                         const void *in, void *out)
{
	const struct ccaes_intel_decrypt_wrapper_ctx *xts = (const struct ccaes_intel_decrypt_wrapper_ctx *) ctx;
    uint8_t *T=((struct ccaes_intel_xts_tweak_ctx *)tweak)->T;

    vng_aes_xts_decrypt_opt(in, nblocks*CCAES_BLOCK_SIZE, out, T, xts->cx);
    
    return T;
}

const struct ccmode_xts ccaes_intel_xts_decrypt_opt_mode = {
    .size = XTS_CTX_SIZE,
    .tweak_size = sizeof(struct ccaes_intel_xts_tweak_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccmode_xts_init,
    .key_sched = key_sched_wrapper_opt,
    .set_tweak = set_tweak_wrapper_opt,
    .xts = xts_wrapper_opt,
    .custom = NULL,
    .custom1 = NULL,
    .impl = CC_IMPL_AES_XTS_INTEL_OPT,
};

/* ==========================================================================
	VNG AESNI implementation.  This implementation uses the AESNI 
	instructions
   ========================================================================== */


/* Create a xts key from a xts mode object.  The tweak_len here
 determines how long the tweak is in bytes, for each subsequent call to
 ccmode_xts->xts(). */
static void key_sched_wrapper_aesni (const struct ccmode_xts *xts_not CC_UNUSED, ccxts_ctx *ctx,
                                     size_t key_nbytes, const void *data_key,
                                     const void *tweak_key)
{
    struct ccaes_intel_decrypt_wrapper_ctx *xts = (struct ccaes_intel_decrypt_wrapper_ctx *) ctx;

    vng_aes_decrypt_aesni_key(data_key, (int)key_nbytes, xts->cx);
    vng_aes_encrypt_aesni_key(tweak_key, (int)key_nbytes, xts->tweak_cx);
}

/* Set the tweak (sector number), the block within the sector zero. */
static int set_tweak_wrapper_aesni(const ccxts_ctx *ctx, ccxts_tweak *tweak, const void *iv)
{
	const struct ccaes_intel_decrypt_wrapper_ctx *xts = (const struct ccaes_intel_decrypt_wrapper_ctx *) ctx;
    uint8_t *T=((struct ccaes_intel_xts_tweak_ctx *)tweak)->T;

    /* encrypt the tweak */
    AccelerateCrypto_AES_encrypt_aesni(iv, T, (const AccelerateCrypto_AES_ctx *) &xts->tweak_cx);

    return 0;
}

/* Encrypt blocks for a sector, clients must call set_tweak before calling
 this function.  Return a pointer to the current tweak (used by ccpad_xts). */
static void *xts_wrapper_aesni(const ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nblocks,
                         const void *in, void *out)
{
	const struct ccaes_intel_decrypt_wrapper_ctx *xts = (const struct ccaes_intel_decrypt_wrapper_ctx *) ctx;
    uint8_t *T=((struct ccaes_intel_xts_tweak_ctx *)tweak)->T;

    vng_aes_xts_decrypt_aesni(in, nblocks*CCAES_BLOCK_SIZE, out, T, xts->cx);

    return T;

}

const struct ccmode_xts ccaes_intel_xts_decrypt_aesni_mode = {
    .size = XTS_CTX_SIZE,
    .tweak_size = sizeof(struct ccaes_intel_xts_tweak_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccmode_xts_init,
    .key_sched = key_sched_wrapper_aesni,
    .set_tweak = set_tweak_wrapper_aesni,
    .xts = xts_wrapper_aesni,
    .custom = NULL,
    .custom1 = NULL,
    .impl = CC_IMPL_AES_XTS_INTEL_AESNI,
};

#endif /* CCAES_INTEL_ASM */

