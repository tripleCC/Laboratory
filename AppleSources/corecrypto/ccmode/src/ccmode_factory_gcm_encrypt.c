/* Copyright (c) (2015,2017-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "ccmode_internal.h"
#include "ccmode_gcm_tables.h"

#if !CC_KERNEL || !CC_USE_ASM

/* Use this to statically initialize a ccmode_gcm object for encryption. */
#define CCMODE_FACTORY_GCM_ENCRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key)) \
+ GCM_ECB_KEY_SIZE(ECB_ENCRYPT) \
+ GCM_TABLE_SIZE, \
.block_size = 1, \
.init = ccmode_gcm_init, \
.set_iv = ccmode_gcm_set_iv, \
.gmac = ccmode_gcm_aad, \
.gcm = ccmode_gcm_encrypt, \
.finalize = ccmode_gcm_finalize, \
.reset = ccmode_gcm_reset, \
.custom = (ECB_ENCRYPT), \
.encdec = CCMODE_GCM_ENCRYPTOR\
}

void ccmode_factory_gcm_encrypt(struct ccmode_gcm *gcm,
                                const struct ccmode_ecb *ecb_encrypt) {
    CC_ENSURE_DIT_ENABLED

    struct ccmode_gcm gcm_encrypt = CCMODE_FACTORY_GCM_ENCRYPT(ecb_encrypt);
    *gcm = gcm_encrypt;
}
#endif

