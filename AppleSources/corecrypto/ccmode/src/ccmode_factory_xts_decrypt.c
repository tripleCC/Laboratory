/* Copyright (c) (2015,2017,2019,2021) Apple Inc. All rights reserved.
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

#if !CC_KERNEL || !CC_USE_ASM

void ccmode_factory_xts_decrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt) {
    CC_ENSURE_DIT_ENABLED

    struct ccmode_xts xts_decrypt = CCMODE_FACTORY_XTS_DECRYPT(ecb, ecb_encrypt);
    *xts = xts_decrypt;
}
#endif
