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

int ccmode_siv_hmac_nonce(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in)
{
    if ((_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_INIT) && (_CCMODE_SIV_HMAC_STATE(ctx) != CCMODE_STATE_AAD)) {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }
    if (nbytes == 0) {
        return CCMODE_NONCE_EMPTY;
    }
    
    ccmode_siv_hmac_auth_backend(ctx, nbytes, in, CCSIV_HMAC_NONCE_MARK);
    // Set state to Nonce so no more authenticated data (other than the plaintext) can be added.
    _CCMODE_SIV_HMAC_STATE(ctx) = CCMODE_STATE_NONCE;
    return CCERR_OK;
}
