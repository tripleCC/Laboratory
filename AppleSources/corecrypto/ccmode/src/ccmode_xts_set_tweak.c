/* Copyright (c) (2011,2012,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

int ccmode_xts_set_tweak(const ccxts_ctx *ctx, ccxts_tweak *tweak,
                         const void *iv) {
    const struct ccmode_ecb *ecb_encrypt = ccmode_xts_key_ecb_encrypt(ctx);
	CCMODE_XTS_TWEAK_BLOCK_PROCESSED(tweak) = 0;
    cc_unit *t = CCMODE_XTS_TWEAK_VALUE(tweak);
    return ecb_encrypt->ecb(ccmode_xts_key_tweak_key(ctx), 1, iv, t);
}
