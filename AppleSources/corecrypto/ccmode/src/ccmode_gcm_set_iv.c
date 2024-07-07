/* Copyright (c) (2011,2012,2015,2016,2018-2021) Apple Inc. All rights reserved.
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

/*
 NIST SP-800-38D, section 5.2.1.1
 The bit lengths of the input strings to the authenticated encryption function shall meet the following requirements:
 • len(P) ≤ 2^39-256;
 • len(A) ≤ 2^64-1;
 • 1 ≤ len(IV) ≤ 2^64-1.
*/

int ccmode_gcm_set_iv(ccgcm_ctx *key, size_t iv_nbytes, const void *iv)
{
    uint8_t *Y = CCMODE_GCM_KEY_Y(key);

    cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_IV, errOut);
    cc_require((_CCMODE_GCM_KEY(key)->flags & CCGCM_FLAGS_INIT_WITH_IV) == 0, errOut);

    cc_require(iv_nbytes != 0 && iv != NULL, errOut); //IV is required

    if (iv_nbytes == CCGCM_IV_NBYTES) {
        cc_memcpy(Y, iv, CCGCM_IV_NBYTES);
        cc_store32_be(1, Y + 12);
    } else {
        const uint8_t *iv_bytes = iv;
        uint8_t buf[16];

        // format the length to mix in at the end
        cc_clear(8, buf);
        cc_store64_be((uint64_t) (iv_nbytes * 8), buf + 8);

        cc_clear(CCGCM_BLOCK_NBYTES, Y);

        while (iv_nbytes >= CCGCM_BLOCK_NBYTES) {
            cc_xor(CCGCM_BLOCK_NBYTES, Y, Y, iv_bytes);
            ccmode_gcm_mult_h(key, Y);
            iv_bytes += CCGCM_BLOCK_NBYTES;
            iv_nbytes -= CCGCM_BLOCK_NBYTES;
        }

        if (iv_nbytes > 0) {
            cc_xor(iv_nbytes, Y, Y, iv_bytes);
            ccmode_gcm_mult_h(key, Y);
        }

        cc_xor(CCGCM_BLOCK_NBYTES, Y, Y, buf);
        ccmode_gcm_mult_h(key, Y);
    }

    cc_memcpy(CCMODE_GCM_KEY_Y_0(key), Y, CCGCM_BLOCK_NBYTES);
    ccmode_gcm_update_pad(key);

    _CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_AAD;

    return 0;
errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;
}
