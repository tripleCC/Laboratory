/* Copyright (c) (2011,2015,2016,2018-2021) Apple Inc. All rights reserved.
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
#include "cc_runtime_config.h"

#if !CCAES_ARM_ASM
static CC_READ_ONLY_LATE(struct ccmode_cfb) cfb_encrypt;
#endif

const struct ccmode_cfb *ccaes_cfb_encrypt_mode(void)
{
#if CCAES_ARM_ASM
    return &ccaes_arm_cfb_encrypt_mode;
#else
    if (!CC_CACHE_DESCRIPTORS || NULL == cfb_encrypt.init) {
        const struct ccmode_ecb *ecb = ccaes_ecb_encrypt_mode();
        ccmode_factory_cfb_encrypt(&cfb_encrypt, ecb);
    }
    return &cfb_encrypt;
#endif
}
