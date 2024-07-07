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

int ccmode_siv_init(const struct ccmode_siv *siv, ccsiv_ctx *ctx,
                     size_t rawkey_byte_len, const uint8_t *rawkey) {

    _CCMODE_SIV_CTX(ctx)->siv=siv;

    // Check if the key size is valid
    if ((rawkey_byte_len>CCSIV_MAX_KEY_BYTESIZE) // Too big for structure
        || (    (rawkey_byte_len != 32)          // Not compliant with spec
                && (rawkey_byte_len != 48)
                && (rawkey_byte_len != 64))){
        return CCMODE_NOT_SUPPORTED;
    }
    _CCMODE_SIV_KEYSIZE(ctx)=rawkey_byte_len;

    // SIV is designed for 128bit block size.
    if (_CCMODE_SIV_CBC_MODE(ctx)->block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    // sanity check on structure size
    cc_memcpy(_CCMODE_SIV_K1(ctx),rawkey,rawkey_byte_len/2); // Save MAC key
    cc_memcpy(_CCMODE_SIV_K2(ctx),rawkey+(rawkey_byte_len/2),rawkey_byte_len/2); // Save CTR key

    // D = AES-CMAC(K, <zero>) and Initial state
    return ccmode_siv_reset(ctx);
}
