/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode_siv_hmac.h>
#include "ccmode_siv_hmac_internal.h"
#include "ccmode_internal.h"
#include <corecrypto/cc_priv.h>

// Unique 4 byte encoding to represent that no authenticated data, no nonce and no plaintext was provided
// This encoding is far from encodings of 0 length AD, nonce and empty plaintext to ensure there are no
// accidental encoding errors on incorrect implementations.
// The length 4 encoding ensures that it is unique from any other string output to the HMAC, which must be longer than
// 4 by the current length encoding and mark encoding rules.
#define NO_AD_NO_NONCE_AND_EMPTY_PLAINTEXT_ENCODING 0x01020304
#define EMPTY_STRING_ENCODING_SYMBOL_LENGTH sizeof(NO_AD_NO_NONCE_AND_EMPTY_PLAINTEXT_ENCODING)
#define LENGTH_ENCODING_BUFFER_LENGTH 9

void ccmode_siv_hmac_auth_backend(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t mark)
{
    uint8_t length_buffer[LENGTH_ENCODING_BUFFER_LENGTH];
    cchmac_update(_CCMODE_SIV_HMAC_DIGEST(ctx), _CCMODE_SIV_HMAC_HMAC_CTX(ctx), nbytes, in);
    cc_store64_be((uint64_t) nbytes, length_buffer);
    length_buffer[8] = mark;
    cchmac_update(_CCMODE_SIV_HMAC_DIGEST(ctx),
                  _CCMODE_SIV_HMAC_HMAC_CTX(ctx),
                  sizeof(length_buffer),
                  length_buffer); // We encode the length of each piece of authenticated data so that we can accept multiple
                                  // authenticated data inputs with no collision attack concerns
}

int ccmode_siv_hmac_auth(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in)
{
    // Ensure proper call sequence
    if ((_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_INIT) && (_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_AAD)) {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }
    if (nbytes == 0) {
        return CCMODE_AD_EMPTY;
    }
    ccmode_siv_hmac_auth_backend(ctx, nbytes, in, CCSIV_HMAC_AD_MARK);
    _CCMODE_SIV_HMAC_STATE(ctx) = CCMODE_STATE_AAD;
    return CCERR_OK;
}

int ccmode_siv_hmac_auth_finalize(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *V)
{
    int rc = -1;
    size_t hash_length = _CCMODE_SIV_HMAC_DIGEST(ctx)->output_size;
    size_t tag_length = _CCMODE_SIV_HMAC_TAG_LENGTH(ctx);
    uint8_t length_buffer[LENGTH_ENCODING_BUFFER_LENGTH];
    uint8_t hash_buffer[MAX_DIGEST_OUTPUT_SIZE];
    
    /* State checks */
    if ((_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_INIT) && (_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_AAD) &&
        (_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_NONCE)) {
        rc = CCMODE_INVALID_CALL_SEQUENCE;
        goto errOut;
    }
    
    /* Special case, nothing to encrypt or authenticate:
     output is simply tag of magic string 0x01020304;
     Note we use this magic string as defensive programming, so it is harder for incorrect implementations
     to create collisions to the empty string.
     Note the HMAC of this string cannot be achieved any otherway due to length encodings.*/
    if ((nbytes == 0) && _CCMODE_SIV_HMAC_STATE(ctx) == CCMODE_STATE_INIT) {
        cc_store32_be(NO_AD_NO_NONCE_AND_EMPTY_PLAINTEXT_ENCODING, length_buffer);
        cchmac(_CCMODE_SIV_HMAC_DIGEST(ctx),
               _CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2,
               _CCMODE_SIV_HMAC_MAC_KEY(ctx),
               EMPTY_STRING_ENCODING_SYMBOL_LENGTH,
               length_buffer,
               hash_buffer);
    } else {
        ccmode_siv_hmac_auth_backend(ctx, nbytes, in, CCSIV_HMAC_PLAINTEXT_MARK);
        cchmac_final(_CCMODE_SIV_HMAC_DIGEST(ctx), _CCMODE_SIV_HMAC_HMAC_CTX(ctx), hash_buffer);
    }
    cc_memcpy(V, hash_buffer, tag_length);
    _CCMODE_SIV_HMAC_STATE(ctx) = CCMODE_STATE_TEXT;
    cc_clear(hash_length, hash_buffer);
    return CCERR_OK;
errOut:
    cc_clear(hash_length, hash_buffer);
    _CCMODE_SIV_HMAC_STATE(ctx) = CCMODE_STATE_INVALID;
    return rc;
}
