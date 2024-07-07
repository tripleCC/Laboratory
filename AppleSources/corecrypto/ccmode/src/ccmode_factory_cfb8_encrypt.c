/* Copyright (c) (2015,2019,2021) Apple Inc. All rights reserved.
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

void ccmode_factory_cfb8_encrypt(struct ccmode_cfb8 *cfb8,
                                 const struct ccmode_ecb *ecb) {
    CC_ENSURE_DIT_ENABLED

    struct ccmode_cfb8 cfb8_encrypt = CCMODE_FACTORY_CFB8_ENCRYPT(ecb);
    *cfb8 = cfb8_encrypt;
}
