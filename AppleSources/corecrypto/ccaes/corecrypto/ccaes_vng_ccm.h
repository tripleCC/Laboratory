/* Copyright (c) (2015-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCAES_VNG_CCM_H_
#define _CORECRYPTO_CCAES_VNG_CCM_H_

#include <corecrypto/ccaes.h>
#include "ccmode_internal.h"

#if (CCAES_INTEL_ASM && defined(__x86_64__)) || CCAES_ARM_ASM
#define CCMODE_CCM_VNG_SPEEDUP 1
#else
#define CCMODE_CCM_VNG_SPEEDUP 0
#endif

#if CCMODE_CCM_VNG_SPEEDUP

int ccaes_vng_ccm_decrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes,
                          const uint8_t *in, uint8_t *out);

static int ccaes_vng_ccm_decrypt_wrapper(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx,
                                         size_t nbytes, const void *in, void *out)
{
    return ccaes_vng_ccm_decrypt(ctx, nonce_ctx, nbytes, in, out);
}

int ccaes_vng_ccm_encrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes,
                          const uint8_t *in, uint8_t *out);

static int ccaes_vng_ccm_encrypt_wrapper(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx,
                                         size_t nbytes, const void *in, void *out)
{
    return ccaes_vng_ccm_encrypt(ctx, nonce_ctx, nbytes, in, out);
}


/* Use this to statically initialize a ccmode_ccm object for decryption. */
#define CCAES_VNG_CCM_DECRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_key)) + ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.nonce_size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_nonce)), \
.block_size = 1, \
.init = ccmode_ccm_init, \
.set_iv = ccmode_ccm_set_iv, \
.cbcmac = ccmode_ccm_cbcmac, \
.ccm = ccaes_vng_ccm_decrypt_wrapper, \
.finalize = ccmode_ccm_finalize, \
.reset = ccmode_ccm_reset, \
.custom = (ECB_ENCRYPT), \
.enc_mode = false, \
}

/* Use this to statically initialize a ccmode_ccm object for encryption. */
#define CCAES_VNG_CCM_ENCRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_key)) + ccn_sizeof_size((ECB_ENCRYPT)->block_size) + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.nonce_size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_nonce)), \
.block_size = 1, \
.init = ccmode_ccm_init, \
.set_iv = ccmode_ccm_set_iv, \
.cbcmac = ccmode_ccm_cbcmac, \
.ccm = ccaes_vng_ccm_encrypt_wrapper, \
.finalize = ccmode_ccm_finalize, \
.reset = ccmode_ccm_reset, \
.custom = (ECB_ENCRYPT), \
.enc_mode = true, \
}

/* Use this function to runtime initialize a ccmode_ccm decrypt object (for
 example if it's part of a larger structure). For CCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccaes_vng_ccm_decrypt_mode_setup(struct ccmode_ccm *ccm) {
    struct ccmode_ccm ccm_decrypt = CCAES_VNG_CCM_DECRYPT(ccaes_ecb_encrypt_mode());
    *ccm = ccm_decrypt;
}

/* Use this function to runtime initialize a ccmode_ccm encrypt object (for
 example if it's part of a larger structure). For CCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccaes_vng_ccm_encrypt_mode_setup(struct ccmode_ccm *ccm) {
    struct ccmode_ccm ccm_encrypt = CCAES_VNG_CCM_ENCRYPT(ccaes_ecb_encrypt_mode());
    *ccm = ccm_encrypt;
}

#endif /* CCMODE_CCM_VNG_SPEEDUP */

#endif /* _CORECRYPTO_CCAES_VNG_CCM_H_ */

