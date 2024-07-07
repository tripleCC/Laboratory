/* Copyright (c) (2011,2014-2023) Apple Inc. All rights reserved.
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
#include "ccmode_internal.h"
#include "ccaes_vng_ctr.h"

static CC_READ_ONLY_LATE(struct ccmode_ctr) ctr_crypt;

const struct ccmode_ctr *ccaes_ctr_crypt_mode(void)
{
    if (!CC_CACHE_DESCRIPTORS || NULL == ctr_crypt.init) {
#if CCMODE_CTR_VNG_SPEEDUP
        ccaes_vng_ctr_crypt_mode_setup(&ctr_crypt);
#else
        ccmode_factory_ctr_crypt(&ctr_crypt, ccaes_ecb_encrypt_mode());
#endif
    }
    return &ctr_crypt;
}
