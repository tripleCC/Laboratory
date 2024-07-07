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
#include <corecrypto/cc_priv.h>
#include "cccmac_internal.h"

int ccmode_siv_encrypt(ccsiv_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out)
{
    size_t block_size = _CCMODE_SIV_CBC_MODE(ctx)->block_size;

    // Supports only 128-bit block ciphers.
    if (block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    uint8_t V[16];
    uint8_t *Q = _CCMODE_SIV_D(ctx);
    int rc;
    const struct ccmode_ctr *ctr = _CCMODE_SIV_CTR_MODE(ctx);

    // Verify that it is not the case that: in - block_size < out < in + nbytes,
    // as we don't support in place memory encryption. However we can have out = in - block_size
    // which is close to inplace if memory is tight.
    if ((in - block_size < out) && (out < in + nbytes)) {
        return CCMODE_BUFFER_OUT_IN_OVERLAP;
    }

    // Finalize S2V
    if ((rc = ccmode_siv_auth_finalize(ctx, nbytes, in, V)) != 0) {
        return rc;
    }
    if (_CCMODE_SIV_STATE(ctx) != CCMODE_STATE_TEXT) {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }

    // CTR encryption with IV V
    cc_memcpy(Q, V, block_size);
    Q[8] &= 0x7F;
    Q[12] &= 0x7F;

    // Ctr encryption, may be called with data of size zero
    rc = ccctr_one_shot(ctr, _CCMODE_SIV_KEYSIZE(ctx) / 2, _CCMODE_SIV_K2(ctx), Q, nbytes, in, out + block_size);

    cc_memcpy(out, V, block_size);
    if (rc) {
        cc_clear(nbytes + block_size, out);
    }
    return rc;
}
