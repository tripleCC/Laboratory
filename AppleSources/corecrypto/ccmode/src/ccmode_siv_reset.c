/* Copyright (c) (2015-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccmode_siv.h>
#include "ccmode_siv_internal.h"
#include "ccmode_internal.h"
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

// Start from fresh with same key.
int ccmode_siv_reset(ccsiv_ctx *ctx)
{
    // Supports only 128-bit block ciphers.
    if (_CCMODE_SIV_CBC_MODE(ctx)->block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    // D = AES-CMAC(K, <zero>)
    uint8_t block[16] = { 0 };

    cccmac_one_shot_generate(_CCMODE_SIV_CBC_MODE(ctx),
                             _CCMODE_SIV_KEYSIZE(ctx) / 2, _CCMODE_SIV_K1(ctx),
                             sizeof(block), block,
                             sizeof(block), _CCMODE_SIV_D(ctx));

    // Initial state
    _CCMODE_SIV_STATE(ctx) = CCMODE_STATE_INIT; // init

    return CCERR_OK;
}
