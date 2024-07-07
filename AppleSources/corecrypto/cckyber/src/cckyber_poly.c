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
#include "cckyber_mult.h"

void cckyber_poly_getnoise(int16_t coeffs[CCKYBER_N],
                           const uint8_t seed[CCKYBER_SYM_NBYTES],
                           uint8_t nonce)
{
    uint8_t buf[128];
    cckyber_prf(seed, nonce, buf);
    cckyber_sample_cbd_eta2(coeffs, buf);
}

void cckyber_poly_to_msg(uint8_t msg[CCKYBER_MSG_NBYTES], const int16_t coeffs[CCKYBER_N])
{
    cckyber_poly_compress_d1(msg, coeffs);
}

void cckyber_poly_from_msg(int16_t coeffs[CCKYBER_N], const uint8_t msg[CCKYBER_MSG_NBYTES])
{
    cckyber_poly_decompress_d1(coeffs, msg);
}

void cckyber_poly_encode(uint8_t out[CCKYBER_POLY_NBYTES], const int16_t coeffs[CCKYBER_N])
{
    for (unsigned i = 0; i < CCKYBER_N / 2; i++) {
        int16_t u0 = coeffs[2 * i + 0];
        int16_t u1 = coeffs[2 * i + 1];

        // To positive standard representatives. If u < 0 then u += q.
        u0 += (u0 >> 15) & CCKYBER_Q;
        u1 += (u1 >> 15) & CCKYBER_Q;

        out[3 * i + 0] = (uint8_t)  (u0 >> 0);
        out[3 * i + 1] = (uint8_t) ((u0 >> 8) | (u1 << 4));
        out[3 * i + 2] = (uint8_t)  (u1 >> 4);
    }
}

void cckyber_poly_decode(int16_t coeffs[CCKYBER_N], const uint8_t in[CCKYBER_POLY_NBYTES])
{
    for (unsigned i = 0; i < CCKYBER_N / 2; i++) {
        int16_t u0 = ((in[3 * i + 0] >> 0) | ((uint16_t)in[3 * i + 1] << 8)) & 0xfff;
        int16_t u1 = ((in[3 * i + 1] >> 4) | ((uint16_t)in[3 * i + 2] << 4)) & 0xfff;

        // Reduce mod q, if needed.
        u0 -= CCKYBER_Q;
        u1 -= CCKYBER_Q;

        coeffs[2 * i + 0] = u0 + ((u0 >> 15) & CCKYBER_Q);
        coeffs[2 * i + 1] = u1 + ((u1 >> 15) & CCKYBER_Q);
    }
}

void cckyber_poly_compress(const cckyber_params_t *params,
                           uint8_t *out,
                           const int16_t coeffs[CCKYBER_N])
{
    params->poly_compress(out, coeffs);
}

void cckyber_poly_decompress(const cckyber_params_t *params,
                             int16_t coeffs[CCKYBER_N],
                             const uint8_t *in)
{
    params->poly_decompress(coeffs, in);
}

void cckyber_poly_add(int16_t coeffs[CCKYBER_N], const int16_t a[CCKYBER_N], const int16_t b[CCKYBER_N])
{
    for (unsigned i = 0; i < CCKYBER_N; i++) {
        coeffs[i] = a[i] + b[i];
    }
}

void cckyber_poly_sub(int16_t coeffs[CCKYBER_N], const int16_t a[CCKYBER_N], const int16_t b[CCKYBER_N])
{
    for (unsigned i = 0; i < CCKYBER_N; i++) {
        coeffs[i] = a[i] - b[i];
    }
}

void cckyber_poly_reduce(int16_t coeffs[CCKYBER_N])
{
    for (unsigned i = 0; i < CCKYBER_N; i++) {
        coeffs[i] = cckyber_mult_reduce(coeffs[i]);
    }
}

void cckyber_poly_toplant(int16_t coeffs[CCKYBER_N])
{
    for (unsigned i = 0; i < CCKYBER_N; i++) {
        coeffs[i] = cckyber_mult_toplant(coeffs[i]);
    }
}
