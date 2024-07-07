/* Copyright (c) (2011,2012,2014-2021) Apple Inc. All rights reserved.
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

#include "fipspost_trace.h"

#if !CCAES_INTEL_ASM && !CCAES_ARM_ASM
static CC_READ_ONLY_LATE(struct ccmode_xts) xts_encrypt;
#endif

const struct ccmode_xts *ccaes_xts_encrypt_mode(void)
{
    FIPSPOST_TRACE_EVENT;

#if CCAES_INTEL_ASM
    return (CC_HAS_AESNI() ? &ccaes_intel_xts_encrypt_aesni_mode : &ccaes_intel_xts_encrypt_opt_mode);
#elif CCAES_ARM_ASM
    return &ccaes_arm_xts_encrypt_mode;
#else
    if (!CC_CACHE_DESCRIPTORS || NULL == xts_encrypt.init) {
        const struct ccmode_ecb *ecb_base_mode = ccaes_ecb_encrypt_mode();
        const struct ccmode_ecb *ecb_base_encrypt_mode = ccaes_ecb_encrypt_mode();
        ccmode_factory_xts_encrypt(&xts_encrypt, ecb_base_mode, ecb_base_encrypt_mode);
    }
    return &xts_encrypt;
#endif
}
