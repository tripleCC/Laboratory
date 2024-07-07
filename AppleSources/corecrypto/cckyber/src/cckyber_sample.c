/* Copyright (c) (2023) Apple Inc. All rights reserved.
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
#include "cckyber_internal.h"
#include "ccshake_internal.h"

/*! @function cckyber_sample_uniform
 @abstract Runs rejection sampling on uniform random bytes to generate uniform
           random integers mod q.

 @param buf     Uniform random bytes to sample from.
 @param ncoeffs Max. number of coefficients to sample.
 @param coeffs  Output coefficients.

 @return The number of sampled coefficients.
 */
CC_NONNULL_ALL CC_WARN_RESULT
static size_t cckyber_sample_uniform(const uint8_t buf[168], size_t ncoeffs, int16_t *coeffs)
{
    cc_assert(0 < ncoeffs);

    size_t ctr = 0;

    for (unsigned i = 0; i < (168 / 3) && ctr < ncoeffs; i += 1) {
        uint16_t v0 = (((uint16_t)buf[3 * i + 1] << 8) |
                                 (buf[3 * i + 0] >> 0)) & 0xfff;
        uint16_t v1 = (((uint16_t)buf[3 * i + 2] << 4) |
                                 (buf[3 * i + 1] >> 4)) & 0xfff;

        if (v0 < CCKYBER_Q) {
            coeffs[ctr++] = (int16_t)v0;
        }

        if (ctr < ncoeffs && v1 < CCKYBER_Q) {
            coeffs[ctr++] = (int16_t)v1;
        }
    }

    return ctr;
}

void cckyber_sample_ntt(const cckyber_params_t *params,
                        const uint8_t *seed,
                        int transposed,
                        int16_t *a)
{
    uint8_t buf[CCSHAKE128_RATE];

    const struct ccxof_info *xi = ccshake128_xi();
    ccshake128_ctx_decl(ctx);

    for (unsigned i = 0; i < params->k; i++) {
        for (unsigned j = 0; j < params->k; j++) {
            ccxof_init(xi, ctx);
            ccxof_absorb(xi, ctx, CCKYBER_SYM_NBYTES, seed);

            // Absorb j and i -- SHAKE128(p, j, i).
            const uint8_t xy[] = { (uint8_t)j, (uint8_t)i, (uint8_t)j };
            ccxof_absorb(xi, ctx, 2U, xy + (transposed & 1));

            // We want 256 coefficients and per each 168-byte SHAKE128 block we
            // can sample at most 112 12-bit numbers < q. So we need to squeeze
            // three blocks or more.
            size_t ctr = 0;
            while (ctr < CCKYBER_N) {
                ccxof_squeeze(xi, ctx, sizeof(buf), buf);
                ctr += cckyber_sample_uniform(buf, CCKYBER_N - ctr, &a[(params->k * i + j) * CCKYBER_N] + ctr);
            }
        }
    }

    ccshake128_ctx_clear(ctx);
}

void cckyber_sample_cbd_eta2(int16_t coeffs[CCKYBER_N], const uint8_t buf[128])
{
    for (unsigned i = 0; i < CCKYBER_N / 16; i += 1) {
        uint64_t t = cc_load64_le(buf + 8 * i);

        uint64_t d = ((t >> 0) & 0x5555555555555555) +
                     ((t >> 1) & 0x5555555555555555);

        for (unsigned j = 0; j < 16; j += 1) {
            int16_t a = (d >> (4 * j + 0)) & 0x3;
            int16_t b = (d >> (4 * j + 2)) & 0x3;
            coeffs[16 * i + j] = a - b;
        }
    }
}
