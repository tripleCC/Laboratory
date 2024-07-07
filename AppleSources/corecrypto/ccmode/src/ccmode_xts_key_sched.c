/* Copyright (c) (2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
//  Copyright (c) 2016 Apple Inc. All rights reserved.
//
//

#include "ccmode_internal.h"

void ccmode_xts_key_sched(const struct ccmode_xts *mode, ccxts_ctx *ctx,
                          size_t key_nbytes, const void *data_key,
                          const void *tweak_key) {
    const struct ccmode_ecb *ecb = mode->custom;
    const struct ccmode_ecb *ecb_encrypt = mode->custom1;
    CCMODE_XTS_KEY_ECB(ctx) = ecb;
    CCMODE_XTS_KEY_ECB_ENCRYPT(ctx) = ecb_encrypt;
    ecb->init(ecb, CCMODE_XTS_KEY_DATA_KEY(ctx), key_nbytes, data_key);
    ecb_encrypt->init(ecb, CCMODE_XTS_KEY_TWEAK_KEY(ctx), key_nbytes, tweak_key);
}
