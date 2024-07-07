/* Copyright (c) (2012-2016,2018,2019,2021) Apple Inc. All rights reserved.
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

/* Implementation per SP800-38C standard */
int ccmode_ccm_set_iv(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t n, const void *nonce, size_t t, size_t a, size_t p)
{

    /*  n: size of the nonce
        t: size of the tag
        p: size of the plaintext
        q: size of the size of the plaintext
        a: size of the authenticated data
     */

    /* blocksize should not have been an size_t. */
    unsigned block_size = (unsigned)CCMODE_CCM_KEY_ECB(key)->block_size;
    cc_require(block_size==16, errOut);
    size_t q = block_size - 1 - n;   // q+n = 15

    /* reset so you can't start without initializing successfully */
    _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_CCM_STATE_IV;
    cc_clear(16, CCMODE_CCM_KEY_PAD(nonce_ctx));
    CCMODE_CCM_KEY_PAD_LEN(nonce_ctx) = 0;

    /* Length requirements, SP800-38C, A.2.2 */
    cc_require((4 <= t) && (t <= block_size) && !(t & 1), errOut);
    cc_require((2 <= q) && (q <= 8), errOut);
    cc_require((7 <= n) && (n <= block_size - 3), errOut);
    cc_require((q >= sizeof(p)) || p < ((size_t)1 << (8 * q)), errOut);

    /*  SP800-38C - A.2.2
        If 0 < a < 2^16-2^8, then a is encoded as [a]16, i.e., two octets.
        If 2^16-2^8 ≤ a < 2^32, then a is encoded as 0xff || 0xfe || [a]32, i.e., six octets.
        If 2^32 ≤ a < 2^64, then a is encoded as 0xff || 0xff || [a]64, i.e., ten octets. */

    const size_t two_octet_bound = ((1 << 16) - (1 << 8));

    // We only implement authenticated and unencrypted data lengths up to 2^32-1
    // On 32 bit machines this is implicit in that size_t is represented in 32 bits
    // On 64 bit machines this may not work because size_t may be in a 64 bit machine;
    // in principle C99 standard says the value of size_t maxes out at 2^32-1, but we don't trust it.
    if (sizeof(size_t) > 4){
        /* encoding of lengths larger than 2^32 unimplemented */
        cc_require((unsigned long long) a < ((unsigned long long) 1 << 32), errOut);
    }

    CCMODE_CCM_KEY_NONCE_LEN(nonce_ctx) = n;
    CCMODE_CCM_KEY_MAC_LEN(nonce_ctx) = t;

    /* set up B_0 parameters per SP800-38C, A.2.1 */
    CCMODE_CCM_KEY_B_I(nonce_ctx)[0] =
        (unsigned char)(
            ((a > 0) ? (1 << 6) : 0) |
            ((CCMODE_CCM_KEY_MAC_LEN(nonce_ctx) / 2 - 1) << 3) |
            (q - 1)
        );

    /* B_0 nonce */
    cc_memcpy(&CCMODE_CCM_KEY_B_I(nonce_ctx)[1], nonce, n);

    /* B_0 length = data_len */
    uint64_t len = p;
    for (size_t l = 0; l < q; l++) {
        CCMODE_CCM_KEY_B_I(nonce_ctx)[block_size - 1 - l] = (len & 255);
        len >>= 8;
    }

    /* encrypt B_0 in place */
    CCMODE_CCM_KEY_ECB(key)->ecb(CCMODE_CCM_KEY_ECB_KEY(key), 1,
                                 CCMODE_CCM_KEY_B_I(nonce_ctx),
                                 CCMODE_CCM_KEY_B_I(nonce_ctx));

    /* set up A_0 */
    CCMODE_CCM_KEY_A_I(nonce_ctx)[0] = (unsigned char)(q - 1);
    cc_memcpy(&CCMODE_CCM_KEY_A_I(nonce_ctx)[1], nonce, n);
    cc_clear(q, &CCMODE_CCM_KEY_A_I(nonce_ctx)[1] + n);

    /* A_0 encrypts MAC */
    CCMODE_CCM_KEY_ECB(key)->ecb(CCMODE_CCM_KEY_ECB_KEY(key), 1,
                                 CCMODE_CCM_KEY_A_I(nonce_ctx),
                                 CCMODE_CCM_KEY_MAC(nonce_ctx));

    /* prepare for authenticated data */
    if (a == 0) {
        CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) = 0;
        _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_STATE_TEXT;
    } else if (a < two_octet_bound) { // two octet formatting as specified by NIST
        // Note that the values below are XORed in, as they are part of the CBC mac and are being XORed with current output of
        // cipher output.
        CCMODE_CCM_KEY_B_I(nonce_ctx)[0] ^= a >> 8;
        CCMODE_CCM_KEY_B_I(nonce_ctx)[1] ^= a & 255;
        CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) = 2;
        _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_STATE_AAD;
    } else { // six octet formatting as specified by NIST for values between 2^32 and 2^16-2^8
        CCMODE_CCM_KEY_B_I(nonce_ctx)[0] ^= 0xff;
        CCMODE_CCM_KEY_B_I(nonce_ctx)[1] ^= 0xfe;
        CCMODE_CCM_KEY_B_I(nonce_ctx)[2] ^= (a>>24) & 0xff;
        CCMODE_CCM_KEY_B_I(nonce_ctx)[3] ^= (a>>16) & 0xff;
        CCMODE_CCM_KEY_B_I(nonce_ctx)[4] ^= (a>>8) & 0xff;
        CCMODE_CCM_KEY_B_I(nonce_ctx)[5] ^= a & 0xff;
        CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) = 6;
        _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_STATE_AAD;
    }

    return 0;
errOut:
    return -1;
}
