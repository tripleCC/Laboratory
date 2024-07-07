/* Copyright (c) (2012,2015,2017,2019) Apple Inc. All rights reserved.
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

#if !CC_KERNEL || !CC_USE_ASM

int ccmode_ccm_decrypt(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in, void *out) {

    unsigned new_block = 0;
    if (_CCMODE_CCM_NONCE(nonce_ctx)->mode == CCMODE_STATE_AAD) {
        if (CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx))
            new_block = 1;
        _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_STATE_TEXT;
    }

    cc_require(_CCMODE_CCM_NONCE(nonce_ctx)->mode == CCMODE_STATE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    ccmode_ccm_crypt(key, nonce_ctx, nbytes, in, out);
    ccmode_ccm_macdata(key, nonce_ctx, new_block, nbytes, out);

    return 0;
errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;
}

#endif
