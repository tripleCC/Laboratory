/* Copyright (c) (2012,2015,2018,2019) Apple Inc. All rights reserved.
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

int ccmode_ccm_reset(ccccm_ctx *key CC_UNUSED, ccccm_nonce *nonce_ctx)
{
    cc_clear(16, CCMODE_CCM_KEY_MAC(nonce_ctx));
    cc_clear(16, CCMODE_CCM_KEY_PAD(nonce_ctx));

    CCMODE_CCM_KEY_PAD_LEN(nonce_ctx) = 0;
    CCMODE_CCM_KEY_MAC_LEN(nonce_ctx) = 0;
    CCMODE_CCM_KEY_NONCE_LEN(nonce_ctx) = 0;
    CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) = 0;

    _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_CCM_STATE_IV;

    return 0;
}
