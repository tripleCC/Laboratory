/* Copyright (c) (2013,2016-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "cccmac_internal.h"

#define CMAC_BUFFER_NB_BLOCKS ((size_t)16)

// CMAC compression. Always keep some data in cccmac_block for final
int cccmac_update(cccmac_ctx_t ctx, size_t data_nbytes, const void *data)
{
    CC_ENSURE_DIT_ENABLED

    if (!data_nbytes || !data) {
        return 0;
    }

    const struct ccmode_cbc *cbc=cccmac_cbc(ctx);
    uint8_t tmp[CMAC_BUFFER_NB_BLOCKS*CMAC_BLOCKSIZE];
    size_t nblocks;
    size_t leftover_nbytes;
    size_t first_block_nbytes = CC_MIN(data_nbytes,CMAC_BLOCKSIZE-cccmac_block_nbytes(ctx));

    // data should be a uint8_t*.
    const uint8_t *in = data;
    data = NULL;

    // Check for abnormality which would result in overflow
    if (cccmac_block_nbytes(ctx) > CMAC_BLOCKSIZE) return -1;

    // Skip for the following for first update (optimization)
    if (cccmac_block_nbytes(ctx) > 0) {
        cc_memcpy((uint8_t*)cccmac_block(ctx)+cccmac_block_nbytes(ctx), in, first_block_nbytes);
        cccmac_block_nbytes(ctx) += first_block_nbytes;
        in += first_block_nbytes;
        data_nbytes-=first_block_nbytes;
        if (data_nbytes == 0) {
            return 0; /* done. Not enough to process yet. */
        }

        // Sanity / debug
        cc_assert(data_nbytes>0);
        cc_assert(cccmac_block_nbytes(ctx) <= CMAC_BLOCKSIZE);

        // Process the first block
        cccbc_update(cbc, cccmac_mode_sym_ctx(cbc, ctx),
                     cccmac_mode_iv(cbc, ctx),
                     1, cccmac_block(ctx), tmp);
        cccmac_cumulated_nbytes(ctx) += CMAC_BLOCKSIZE;
    }

    // Process the remaining blocks
    nblocks = ((data_nbytes-1) >> 4); //  divide by 16, keep at least one byte
    leftover_nbytes = data_nbytes-(CMAC_BLOCKSIZE*nblocks);
    cc_assert(leftover_nbytes>0);

    // Most blocks
    while (nblocks) {
        size_t process_nblocks=CC_MIN(CMAC_BUFFER_NB_BLOCKS,nblocks);
        cccbc_update(cbc, cccmac_mode_sym_ctx(cbc, ctx), cccmac_mode_iv(cbc, ctx), process_nblocks, in, tmp);
        in += (CMAC_BLOCKSIZE*process_nblocks);
        nblocks-=process_nblocks;
    }

    // Keep the leftover bytes, at least one byte
    cc_memcpy(cccmac_block(ctx), in, leftover_nbytes);
    cccmac_block_nbytes(ctx) = leftover_nbytes;

    // Keep track of how much we processed
    cccmac_cumulated_nbytes(ctx) += (CMAC_BLOCKSIZE*(nblocks));
    return 0;
}



