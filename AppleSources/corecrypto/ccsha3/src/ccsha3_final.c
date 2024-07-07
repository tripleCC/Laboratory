/* Copyright (c) (2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha3.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

#include "cckeccak_internal.h"
#include "ccsha3_internal.h"

void ccsha3_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, uint8_t *digest, cckeccak_permutation permutation)
{
    // Sanity check to recover from ctx corruptions.
    if (ccdigest_num(di, ctx) >= di->block_size) {
        ccdigest_num(di, ctx) = 0;
    }

    // Clone the state.
    ccdigest_di_decl(di, tmp);
    cc_memcpy(tmp, ctx, ccdigest_di_size(di));

    // Absorb the remaining data and add padding.
    cckeccak_absorb_and_pad((cckeccak_state_t)ccdigest_u64(ccdigest_state(di, tmp)),
                            di->block_size,
                            ccdigest_num(di, tmp),
                            ccdigest_data(di, tmp),
                            0x06,
                            permutation);
    // Squeeze.
    cckeccak_squeeze((cckeccak_state_t)ccdigest_u64(ccdigest_state(di, tmp)), di->block_size, di->output_size, digest, permutation);

    // Clean the cloned state.
    ccdigest_di_clear(di, tmp);
}
