/* Copyright (c) (2010,2011,2015,2017-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cc_priv.h>
#include "ccdigest_internal.h"

void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest)
{
    // Sanity check to recover from ctx corruptions.
    if (ccdigest_num(di, ctx) >= di->block_size) {
        ccdigest_num(di, ctx) = 0;
    }

    // Clone the state.
    ccdigest_di_decl(di, tmp);
    cc_memcpy(tmp, ctx, ccdigest_di_size(di));

    ccdigest_nbits(di, tmp) += ccdigest_num(di, tmp) << 3;
    ccdigest_data(di, tmp)[ccdigest_num(di, tmp)++] = 0x80;

    /* If we don't have at least 8 bytes (for the length) left we need to add
     a second block. */
    if (ccdigest_num(di, tmp) > 64 - 8) {
        while (ccdigest_num(di, tmp) < 64) {
            ccdigest_data(di, tmp)[ccdigest_num(di, tmp)++] = 0;
        }
        di->compress(ccdigest_state(di, tmp), 1, ccdigest_data(di, tmp));
        ccdigest_num(di, tmp) = 0;
    }

    /* pad upto block_size minus 8 with 0s */
    while (ccdigest_num(di, tmp) < 64 - 8) {
        ccdigest_data(di, tmp)[ccdigest_num(di, tmp)++] = 0;
    }

    cc_store64_le(ccdigest_nbits(di, tmp), ccdigest_data(di, tmp) + 64 - 8);
    di->compress(ccdigest_state(di, tmp), 1, ccdigest_data(di, tmp));

    /* copy output */
    for (unsigned int i = 0; i < di->output_size / 4; i++) {
        cc_store32_le(ccdigest_state_u32(di, tmp)[i], digest + (4 * i));
    }

    ccdigest_di_clear(di, tmp);
}
