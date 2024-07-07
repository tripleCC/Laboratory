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
#include "ccmode_siv_internal.h"
#include "ccmode_siv_hmac_internal.h"
#include "ccmode_internal.h"
#include <corecrypto/cc_priv.h>

/*We create a key for the CTR mode encryption that is "unique" for each message./
Let T be all be the tag computed from HMAC.
We compute x0=BC_k(T),x1=BC_k(T||1),...,xn=BC_k(T||n), where BC is the block cipher being used in CTR mode in this
construction. The key actually used for CTR mode encryption is the concatenation of the _first_half_ of each xi.
The reason we use only the first half of the output of each call to the BC is that BC produces permutations and not
random functions, so this output is signifincatly close to a random functions output.*/

int ccmode_siv_hmac_temp_key_gen(ccsiv_hmac_ctx *ctx, uint8_t *temp_key, const uint8_t *iv)
{
    int error;
    
    /* The following assert ensures that when we use ctr mode to derive a key we don't have any overflow issues
    For this invariant not to hold, the HMAC key would have to be bigger then 64* the block size.
    This should never be an issue.
     */
     cc_assert(_CCMODE_SIV_HMAC_KEYSIZE(ctx) <= 128 * _CCMODE_SIV_HMAC_CTR_MODE(ctx)->ecb_block_size);
    
    const struct ccmode_ctr *ctr = _CCMODE_SIV_HMAC_CTR_MODE(ctx);
    size_t block_size = _CCMODE_SIV_HMAC_CTR_MODE(ctx)->ecb_block_size;

    // Supports only 128-bit block ciphers.
    if (block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    uint8_t temp_iv[16];
    cc_memcpy(temp_iv, iv, block_size);
    temp_iv[block_size - 1] &= 0x7F;  // Zero out the 8th bit to ensure we don't have overflow on fewer than 128 counter increments.
    uint8_t zero_pad[CCSIV_MAX_KEY_BYTESIZE];
    uint8_t expanded_key[CCSIV_MAX_KEY_BYTESIZE];
    cc_clear(_CCMODE_SIV_HMAC_KEYSIZE(ctx), zero_pad);
    
    // Compute x0=BC_k(T||0),x1=BC_k(T||1),...,xn=BC_k(T||n),
    error = ccctr_one_shot(ctr,
                           _CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2,
                           _CCMODE_SIV_HMAC_CTR_KEY(ctx),
                           temp_iv,
                           _CCMODE_SIV_HMAC_KEYSIZE(ctx),
                           zero_pad,
                           expanded_key);
    size_t base = block_size / 2;
    
    // Take first half of each xi, and concatenate them all together.
    cc_memcpy(temp_key, expanded_key, block_size/2);
    for (size_t i = 0; i < (_CCMODE_SIV_HMAC_KEYSIZE(ctx) / block_size) / 2; i++) {
        cc_memcpy(&temp_key[base], &expanded_key[base+block_size / 2], block_size/2);
        base += block_size;
    }
    
    cc_clear(block_size, temp_iv);
    return error;
}
