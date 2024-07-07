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

#include <corecrypto/ccmode_siv_hmac.h>
#include "ccmode_siv_hmac_internal.h"
#include "ccmode_internal.h"
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

int ccmode_siv_hmac_reset(ccsiv_hmac_ctx *ctx)
{
    // Start from fresh with same key.
    cchmac_init(_CCMODE_SIV_HMAC_DIGEST(ctx),
                _CCMODE_SIV_HMAC_HMAC_CTX(ctx),
                _CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2,
                _CCMODE_SIV_HMAC_MAC_KEY(ctx));
    _CCMODE_SIV_HMAC_STATE(ctx) = CCMODE_STATE_INIT;
    return 0;
}
