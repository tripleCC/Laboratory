/* Copyright (c) (2012,2015,2016,2019,2021) Apple Inc. All rights reserved.
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

static void inc(uint8_t *ctr_ptr, size_t ctr_len)
{
    // Walk from the end of the counter, increasing each byte value
    // while avoiding the implicit conversion.
    for (int i = (int) ctr_len - 1; i >= 0; i--) {
        ctr_ptr[i] = (ctr_ptr[i] + 1) & 0xff;
        if (ctr_ptr[i] != 0) {
            break;
        }
    }
}

void ccmode_ccm_crypt(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t nbytes,
                        const void *in, void *out) {

    const unsigned char *input = in;
    unsigned char *output = out;

    size_t blocksize = CCMODE_CCM_KEY_ECB(key)->block_size;
    size_t ctr_len = blocksize - 1 - CCMODE_CCM_KEY_NONCE_LEN(nonce_ctx);
    
    for (size_t x=0; x < nbytes; x++) {
        if (CCMODE_CCM_KEY_PAD_LEN(nonce_ctx) == 0) {

            // The start of the counter depends on the counter length
            inc(CCMODE_CCM_KEY_A_I(nonce_ctx) + blocksize - ctr_len, ctr_len);

            CCMODE_CCM_KEY_ECB(key)->ecb(CCMODE_CCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_CCM_KEY_A_I(nonce_ctx),
                                         CCMODE_CCM_KEY_PAD(nonce_ctx));
        }

        output[x] = input[x] ^ CCMODE_CCM_KEY_PAD(nonce_ctx)[CCMODE_CCM_KEY_PAD_LEN(nonce_ctx)];
        CCMODE_CCM_KEY_PAD_LEN(nonce_ctx) = (CCMODE_CCM_KEY_PAD_LEN(nonce_ctx) + 1) % blocksize;
    }
}


int ccmode_ccm_encrypt(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t nbytes,
                        const void *in, void *out) {

    unsigned new_block = 0;
    if (_CCMODE_CCM_NONCE(nonce_ctx)->mode == CCMODE_STATE_AAD) {
        if (CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx))
            new_block = 1;
        _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_STATE_TEXT;
    }

    cc_require(_CCMODE_CCM_NONCE(nonce_ctx)->mode == CCMODE_STATE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    ccmode_ccm_macdata(key, nonce_ctx, new_block, nbytes, in);
    ccmode_ccm_crypt(key, nonce_ctx, nbytes, in, out);

    return 0;
errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;
}

