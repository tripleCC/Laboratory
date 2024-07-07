/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccxof_internal.h"

void ccxof_init(const struct ccxof_info *xi, ccxof_ctx_t ctx)
{
    ccxof_nbytes(xi, ctx) = 0;
    ccxof_squeezing(xi, ctx) = false;

    xi->init(xi, ccxof_state(xi, ctx));
}

void ccxof_absorb(const struct ccxof_info *xi, ccxof_ctx_t ctx, size_t in_nbytes, const uint8_t *in)
{
    cc_assert(!ccxof_squeezing(xi, ctx));
    ccxof_state_t state = ccxof_state(xi, ctx);

    size_t buffer_nbytes = (size_t)ccxof_nbytes(xi, ctx);
    uint8_t *buffer = ccxof_buffer(xi, ctx);

    // Absorb partial pending data.
    if (buffer_nbytes > 0) {
        size_t nbytes_to_copy = CC_MIN(xi->block_nbytes - buffer_nbytes, in_nbytes);
        cc_memcpy(buffer + buffer_nbytes, in, nbytes_to_copy);

        in += nbytes_to_copy;
        in_nbytes -= nbytes_to_copy;

        buffer_nbytes += nbytes_to_copy;
        ccxof_nbytes(xi, ctx) = (uint32_t)buffer_nbytes;

        if (buffer_nbytes == xi->block_nbytes) {
            xi->absorb(xi, state, 1, buffer);
            ccxof_nbytes(xi, ctx) = 0;
        }
    }

    // Absorb full blocks.
    size_t nblocks = in_nbytes / xi->block_nbytes;

    if (nblocks > 0) {
        xi->absorb(xi, state, nblocks, in);
    }

    in += nblocks * xi->block_nbytes;
    in_nbytes -= nblocks * xi->block_nbytes;

    // Store remaining data that doesn't fill a block.
    if (in_nbytes > 0) {
        cc_memcpy(buffer, in, in_nbytes);
        ccxof_nbytes(xi, ctx) = (uint32_t)in_nbytes;
    }
}

void ccxof_squeeze(const struct ccxof_info *xi, ccxof_ctx_t ctx, size_t out_nbytes, uint8_t *out)
{
    ccxof_state_t state = ccxof_state(xi, ctx);
    uint8_t *buffer = ccxof_buffer(xi, ctx);

    // Absorb partial pending data and pad.
    if (!ccxof_squeezing(xi, ctx)) {
        xi->absorb_last(xi, state, (size_t)ccxof_nbytes(xi, ctx), buffer);

        ccxof_squeezing(xi, ctx) = true;
        ccxof_nbytes(xi, ctx) = 0;
    }

    size_t buffer_nbytes = (size_t)ccxof_nbytes(xi, ctx);

    while (out_nbytes > 0) {
        // Squeeze a single block into the buffer, if needed.
        if (buffer_nbytes == 0) {
            xi->squeeze(xi, state, xi->block_nbytes, buffer);
            buffer_nbytes = xi->block_nbytes;
        }

        size_t nbytes_to_copy = CC_MIN(out_nbytes, buffer_nbytes);
        cc_memcpy(out, buffer + (xi->block_nbytes - buffer_nbytes), nbytes_to_copy);

        buffer_nbytes -= nbytes_to_copy;
        out_nbytes -= nbytes_to_copy;
        out += nbytes_to_copy;
    }

    // Set watermark for valid bytes remaining in the buffer.
    ccxof_nbytes(xi, ctx) = (uint32_t)buffer_nbytes;
}
