/* Copyright (c) (2010-2012,2015-2019,2021-2023) Apple Inc. All rights reserved.
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

#if CC_KERNEL && CC_SMALL_CODE
 #error "Must use CC_READ_ONLY_LATE with CC_KERNEL=1"
#endif

const struct ccmode_cbc *ccaes_cbc_decrypt_mode(void)
{
#if CCAES_INTEL_ASM
    return (CC_HAS_AESNI() ? &ccaes_intel_cbc_decrypt_aesni_mode : &ccaes_intel_cbc_decrypt_opt_mode);
#elif CCAES_ARM_ASM
    return &ccaes_arm_cbc_decrypt_mode;
#elif CC_SMALL_CODE
    static struct ccmode_cbc cbc;
    ccmode_factory_cbc_decrypt(&cbc, ccaes_ecb_decrypt_mode());
    return &cbc;
#else
    return &ccaes_gladman_cbc_decrypt_mode;
#endif
}
