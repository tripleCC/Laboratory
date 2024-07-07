/* Copyright (c) (2010-2012,2014-2019,2021) Apple Inc. All rights reserved.
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
#include "cc_runtime_config.h"

#include "fipspost_trace.h"

const struct ccmode_ecb *ccaes_ecb_encrypt_mode(void)
{
    FIPSPOST_TRACE_EVENT;

#if CCAES_INTEL_ASM
    return (CC_HAS_AESNI() ? &ccaes_intel_ecb_encrypt_aesni_mode : &ccaes_intel_ecb_encrypt_opt_mode);
#elif CCAES_ARM_ASM
    return &ccaes_arm_ecb_encrypt_mode;
#else
    return &ccaes_ltc_ecb_encrypt_mode;
#endif
}
