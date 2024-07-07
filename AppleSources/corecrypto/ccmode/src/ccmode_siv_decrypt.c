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

int ccmode_siv_decrypt(ccsiv_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out)
{
    int rc=-1;
    size_t block_size = _CCMODE_SIV_CBC_MODE(ctx)->block_size;

    // Supports only 128-bit block ciphers.
    if (block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    uint8_t V[16];
    uint8_t T[16];
    uint8_t Q[16];
    const struct ccmode_ctr *ctr=_CCMODE_SIV_CTR_MODE(ctx);

    // Sanity checks
    if (   (_CCMODE_SIV_STATE(ctx)!=CCMODE_STATE_INIT)
        && (_CCMODE_SIV_STATE(ctx)!=CCMODE_STATE_AAD)) {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }
    if (nbytes<block_size) return CCMODE_INVALID_INPUT; // Input is too small! Invalid/missing tag

    // CTR encryption with IV V
    cc_memcpy(V,in,block_size);
    cc_memcpy(Q,V,block_size);
    Q[8]&=0x7F;
    Q[12]&=0x7F;

    // Ctr encryption, may be called with data of size zero
    if ((rc=ccctr_one_shot(ctr, _CCMODE_SIV_KEYSIZE(ctx)/2, _CCMODE_SIV_K2(ctx),
                           Q, nbytes-block_size, in+block_size, out))!=0) {
        goto errOut; // Failure, output should not be used
    }

    // Compute integrity tag
    if ((rc=ccmode_siv_auth_finalize(ctx,nbytes-block_size,out,T))!=0) {
        goto errOut; // Failure, output should not be used
    }

    // Check integrity
    if ((cc_cmp_safe(block_size,T,V)==0)
        && (_CCMODE_SIV_STATE(ctx)==CCMODE_STATE_TEXT)) {
        rc=0; // Success
    } else {
        rc=CCMODE_INTEGRITY_FAILURE; // Failure, output should not be used
    }

errOut:
    // Fail after decrypting data: erase the output
    if (rc) {cc_clear(nbytes-block_size,out);}
    return rc;
}
