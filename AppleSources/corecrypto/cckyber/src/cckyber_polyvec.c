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

void cckyber_polyvec_encode(const cckyber_params_t *params,
                            uint8_t *out,
                            const int16_t *coeffs)
{
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_encode(out + k * CCKYBER_POLY_NBYTES, coeffs + k * CCKYBER_N);
    }
}

void cckyber_polyvec_decode(const cckyber_params_t *params,
                            int16_t *coeffs,
                            const uint8_t *in)
{
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_decode(coeffs + k * CCKYBER_N, in + k * CCKYBER_POLY_NBYTES);
    }
}

void cckyber_polyvec_compress(const cckyber_params_t *params,
                              uint8_t *out,
                              const int16_t *coeffs)
{
    unsigned step = (CCKYBER_N * params->du) >> 3;

    for (unsigned k = 0; k < params->k; k++) {
        params->polyvec_compress(out + k * step, coeffs + k * CCKYBER_N);
    }
}

void cckyber_polyvec_decompress(const cckyber_params_t *params,
                                int16_t *coeffs,
                                const uint8_t *in)
{
    unsigned step = (CCKYBER_N * params->du) >> 3;

    for (unsigned k = 0; k < params->k; k++) {
        params->polyvec_decompress(coeffs + k * CCKYBER_N, in + k * step);
    }
}

void cckyber_polyvec_add(const cckyber_params_t *params,
                         int16_t *coeffs,
                         const int16_t *a,
                         const int16_t *b)
{
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_add(coeffs + k * CCKYBER_N, a + k * CCKYBER_N, b + k * CCKYBER_N);
    }
}

void cckyber_polyvec_reduce(const cckyber_params_t *params, int16_t *coeffs)
{
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_reduce(coeffs + k * CCKYBER_N);
    }
}

void cckyber_polyvec_ntt_forward(const cckyber_params_t *params, int16_t *coeffs)
{
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_ntt_forward(coeffs + k * CCKYBER_N);
    }
}

void cckyber_polyvec_basemul(const cckyber_params_t *params,
                             int16_t *coeffs,
                             const int16_t *a,
                             const int16_t *b)
{
    int16_t t[CCKYBER_N];

    cckyber_ntt_basemul(coeffs, a, b);

    for (unsigned k = 1; k < params->k; k++) {
        cckyber_ntt_basemul(t, a + k * CCKYBER_N, b + k * CCKYBER_N);
        cckyber_poly_add(coeffs, coeffs, t);
    }
}
