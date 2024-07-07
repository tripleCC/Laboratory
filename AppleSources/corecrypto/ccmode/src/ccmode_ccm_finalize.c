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

int ccmode_ccm_finalize(ccccm_ctx *key, ccccm_nonce *nonce_ctx, void *mac) {

    cc_require(_CCMODE_CCM_NONCE(nonce_ctx)->mode != CCMODE_CCM_STATE_IV,errOut); /* CRYPT_INVALID_ARG */

    /* final cbc encrypt of B_i */
    if (CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) != 0) {
        CCMODE_CCM_KEY_ECB(key)->ecb(CCMODE_CCM_KEY_ECB_KEY(key), 1,
                                     CCMODE_CCM_KEY_B_I(nonce_ctx),
                                     CCMODE_CCM_KEY_B_I(nonce_ctx));
    }

    /* xor B_i into MAC */
    cc_xor(CCMODE_CCM_KEY_ECB(key)->block_size, CCMODE_CCM_KEY_MAC(nonce_ctx),
           CCMODE_CCM_KEY_MAC(nonce_ctx), CCMODE_CCM_KEY_B_I(nonce_ctx));

    /* output mac_size mac */
    cc_memcpy(mac, CCMODE_CCM_KEY_MAC(nonce_ctx), CCMODE_CCM_KEY_MAC_LEN(nonce_ctx));

    return 0;
errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;
}
