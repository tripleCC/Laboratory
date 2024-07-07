/* Copyright (c) (2011,2015,2017-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccaes.h>
#include "ccaes_vng_gcm.h"
#include "ccmode_internal.h"

static CC_READ_ONLY_LATE(struct ccmode_gcm) gcm_decrypt;

const struct ccmode_gcm *ccaes_gcm_decrypt_mode(void)
{
    if (!CC_CACHE_DESCRIPTORS || NULL == gcm_decrypt.init) {
#if CCMODE_GCM_VNG_SPEEDUP
        ccaes_vng_factory_gcm_decrypt(&gcm_decrypt);
#else
        ccmode_factory_gcm_decrypt(&gcm_decrypt, ccaes_ecb_encrypt_mode());
#endif
    }
    return &gcm_decrypt;
}
