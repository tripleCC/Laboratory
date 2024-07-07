/* Copyright (c) (2012,2015,2016,2019) Apple Inc. All rights reserved.
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

void ccmode_ccm_macdata(ccccm_ctx *key, ccccm_nonce *nonce_ctx, unsigned new_block, size_t nbytes, const void *in) {
    const char *bytes = in;
    unsigned block_size = (unsigned)CCMODE_CCM_KEY_ECB(key)->block_size;

    if (new_block) {
        /* transition to new block between auth and enc data */
        CCMODE_CCM_KEY_ECB(key)->ecb(CCMODE_CCM_KEY_ECB_KEY(key), 1,
                                     CCMODE_CCM_KEY_B_I(nonce_ctx),
                                     CCMODE_CCM_KEY_B_I(nonce_ctx));
        CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) = 0;
    }

    unsigned b_i_len = CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx);
    for (size_t l = 0; l < nbytes;) {

        size_t consume = CC_MIN(nbytes - l, block_size - b_i_len);

        cc_xor(consume, CCMODE_CCM_KEY_B_I(nonce_ctx) + b_i_len,
               CCMODE_CCM_KEY_B_I(nonce_ctx) + b_i_len, bytes + l);

        l += consume;
        b_i_len += consume;
        b_i_len %= block_size;

        if (0 == b_i_len) {
            CCMODE_CCM_KEY_ECB(key)->ecb(CCMODE_CCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_CCM_KEY_B_I(nonce_ctx),
                                         CCMODE_CCM_KEY_B_I(nonce_ctx));
        }
    }
    CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) = b_i_len;
}


int ccmode_ccm_cbcmac(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in) {

    cc_require(nbytes==0 || _CCMODE_CCM_NONCE(nonce_ctx)->mode == CCMODE_STATE_AAD,errOut); /* CRYPT_INVALID_ARG */

    ccmode_ccm_macdata(key, nonce_ctx, 0, nbytes, in);

    return 0;
errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;
}
