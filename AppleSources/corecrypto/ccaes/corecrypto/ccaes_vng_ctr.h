/* Copyright (c) (2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCAES_VNG_CTR_H_
#define _CORECRYPTO_CCAES_VNG_CTR_H_

#include <corecrypto/ccaes.h>
#include "ccmode_internal.h"

#if (CCAES_INTEL_ASM && defined(__x86_64__)) || CCAES_ARM_ASM
#define CCMODE_CTR_VNG_SPEEDUP 1
#else
#define CCMODE_CTR_VNG_SPEEDUP 0
#endif


#if CCMODE_CTR_VNG_SPEEDUP
int ccaes_vng_ctr_crypt(ccctr_ctx *ctx, size_t nbytes,
                        const void *in, void *out);

/* Use this to statically initialize a ccmode_ctr object for decryption. */
#define CCMODE_VNG_AES_CTR_CRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_ctr_key)) + 2 * ccn_sizeof_size(CCAES_BLOCK_SIZE) \
        + ccn_sizeof_size((ECB_ENCRYPT)->size), \
.block_size = 1, \
.ecb_block_size = CCAES_BLOCK_SIZE, \
.init = ccmode_ctr_init, \
.setctr = ccmode_ctr_setctr, \
.ctr = ccaes_vng_ctr_crypt, \
.custom = (ECB_ENCRYPT) \
}

/* Use this function to runtime initialize a ccmode_ctr crypt object (for
 example if it's part of a larger structure). For CTR you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccaes_vng_ctr_crypt_mode_setup(struct ccmode_ctr *ctr) {
    struct ccmode_ctr ctr_decrypt = CCMODE_VNG_AES_CTR_CRYPT(ccaes_ecb_encrypt_mode());
    *ctr = ctr_decrypt;
}

#endif /* CCMODE_CTR_VNG_SPEEDUP */

#endif /* _CORECRYPTO_CCAES_VNG_CTR_H_ */

