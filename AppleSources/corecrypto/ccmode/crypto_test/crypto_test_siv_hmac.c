/* Copyright (c) (2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "crypto_test_modes.h"
#include <corecrypto/ccmode.h>
#include "testmore.h"
#include "ccmode_siv_hmac_internal.h"

#define HMAC_SHA256_TAG_MAX 32

int ccmode_siv_hmac_state_tests(cc_ciphermode_descriptor cm, cc_symmetric_context_p ctx)
{
    int rc;
    size_t tag_len = 20; // 128 Bits below allowed value of 160
    uint8_t key[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    
    size_t key_len = sizeof(key);
    is(key_len, 32, "Key Length is supposed to be 32 bytes long");
    uint8_t *adata = (uint8_t *)"This is the first piece of authenticated data";
    size_t adata_len CC_UNUSED = strlen((char *)adata);
    uint8_t *adata2 = (uint8_t *)"This is the second piece of authenticated data";
    size_t adata2_len = strlen((char *)adata2);
    uint8_t *iv = (uint8_t *)"This is the IV/nonce";
    size_t iv_len CC_UNUSED = strlen((char *)iv);
    
    uint8_t *plaintext = (uint8_t *)"This is a sample plaintext";
    size_t plaintext_n = strlen((char *)plaintext);
    uint8_t ciphertext[plaintext_n + tag_len];
    
    // Test to ensure that improper state changes throw errors.
    is(ccsiv_hmac_init(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, 14, (uint8_t *)key, tag_len),
       CCMODE_NOT_SUPPORTED,
       "Improper key size accepted in hmac_siv initialization");
    is(ccsiv_hmac_init(cm->ciphermode.siv_hmac,
                       ctx->ctx.siv_hmac,
                       key_len,
                       (uint8_t *)key,
                       _CCMODE_SIV_HMAC_MINIMUM_ACCEPTABLE_COLLISION_RESISTANT_TAG_LENGTH - 1),
       CCMODE_TAG_LENGTH_TOO_SHORT,
       "Not catching tag length that is too short");
    is(ccsiv_hmac_init(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, key_len, (uint8_t *)key, HMAC_SHA256_TAG_MAX + 1),
       CCMODE_TAG_LENGTH_REQUEST_TOO_LONG,
       "Not catching tag length that is too short");
    
    rc = ccsiv_hmac_init(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, key_len, key, tag_len);
    rc |= ccsiv_hmac_set_nonce(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, adata2_len, adata2);
    is(rc, CCERR_OK, "Setting nonce in state machine testing of siv_hmac should not induce error codes");
    rc = ccsiv_hmac_aad(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, adata2_len, adata2);
    is(rc, CCMODE_INVALID_CALL_SEQUENCE, "Should receive an invalid call sequence error when calling \"aad\" after nonce");
    
    rc = ccsiv_hmac_reset(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac);
    rc |= ccsiv_hmac_crypt(ctx->mode_desc->ciphermode.siv_hmac, ctx->ctx.siv_hmac, plaintext_n, plaintext, ciphertext);
    is(rc, CCERR_OK, "Resetting state machine and encrypting should not induce error codes");
    rc = ccsiv_hmac_crypt(ctx->mode_desc->ciphermode.siv_hmac, ctx->ctx.siv_hmac, plaintext_n, plaintext, ciphertext);
    is(rc, CCMODE_INVALID_CALL_SEQUENCE, "Should receive an invalid call sequence error when calling crypt twice in a row");
    
    rc = ccsiv_hmac_reset(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac);
    is(rc, CCERR_OK, "Resetting state machine should not induce error codes");
    rc = ccsiv_hmac_aad(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, 0, adata);
    is(rc, CCMODE_AD_EMPTY, "Empty AD set:Not Allowed");
    rc = ccsiv_hmac_set_nonce(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, 0, iv);
    is(rc, CCMODE_NONCE_EMPTY, "Empty Nonce set:Not Allowed");
    
    return 1;
}
