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

/*! @function cckyber_compress_coefficient
 @abstract Compress a given coefficient down to `d` bits.

 @param coeff Coefficient.
 @param d     Parameter d.

 @return The compressed d-bit coefficient.
 */
CC_INLINE CC_WARN_RESULT CC_NONNULL_ALL
int16_t cckyber_compress_coefficient(int16_t coeff, unsigned d)
{
    // Precompute M, for fast division by q.
    const uint64_t M = 0xffffffff / CCKYBER_Q + 1;

    // Mask the `d` lowest bits.
    uint32_t mask = (1U << d) - 1;

    // To positive standard representative. If u < 0 then u += q.
    coeff += (coeff >> 15) & CCKYBER_Q;

    // Compress to `d` bits.
    return (((((uint32_t)coeff << d) + (CCKYBER_Q >> 1)) * M) >> 32) & mask;
}

void cckyber_poly_compress_d1(uint8_t out[32], const int16_t coeffs[CCKYBER_N])
{
    for (unsigned i = 0; i < CCKYBER_N / 8; i++) {
        out[i] = 0;

        for (unsigned j = 0; j < 8; j++) {
            out[i] |= cckyber_compress_coefficient(coeffs[8 * i + j], 1) << j;
        }
    }
}

void cckyber_poly_compress_d4(uint8_t out[128], const int16_t coeffs[CCKYBER_N])
{
    int16_t u[2];

    for (unsigned i = 0; i < CCKYBER_N / 2; i++) {
        for (unsigned j = 0; j < 2; j++) {
            u[j] = cckyber_compress_coefficient(coeffs[2 * i + j], 4);
        }

        *(out++) = (uint8_t) (u[1] << 4) | (u[0] & 15);
    }
}

void cckyber_poly_compress_d5(uint8_t out[160], const int16_t coeffs[CCKYBER_N])
{
    int16_t u[8];

    for (unsigned i = 0; i < CCKYBER_N / 8; i++) {
        for (unsigned j = 0; j < 8; j++) {
            u[j] = cckyber_compress_coefficient(coeffs[8 * i + j], 5);
        }

        *(out++) = (uint8_t) ((u[0] >> 0) | (u[1] << 5));
        *(out++) = (uint8_t) ((u[1] >> 3) | (u[2] << 2) | (u[3] << 7));
        *(out++) = (uint8_t) ((u[3] >> 1) | (u[4] << 4));
        *(out++) = (uint8_t) ((u[4] >> 4) | (u[5] << 1) | (u[6] << 6));
        *(out++) = (uint8_t) ((u[6] >> 2) | (u[7] << 3));
    }
}

void cckyber_poly_compress_d10(uint8_t out[320], const int16_t coeffs[CCKYBER_N])
{
    int16_t u[4];

    for (unsigned i = 0; i < (CCKYBER_N / 4); i++) {
        for (unsigned j = 0; j < 4; j++) {
            u[j] = cckyber_compress_coefficient(coeffs[4 * i + j], 10);
        }

        *(out++) = (uint8_t)  (u[0] >> 0);
        *(out++) = (uint8_t) ((u[0] >> 8) | (u[1] << 2));
        *(out++) = (uint8_t) ((u[1] >> 6) | (u[2] << 4));
        *(out++) = (uint8_t) ((u[2] >> 4) | (u[3] << 6));
        *(out++) = (uint8_t)  (u[3] >> 2);
    }
}

void cckyber_poly_compress_d11(uint8_t out[352], const int16_t coeffs[CCKYBER_N])
{
    int16_t u[8];

    for (unsigned i = 0; i < (CCKYBER_N / 8); i++) {
        for (unsigned j = 0; j < 8; j++) {
            u[j] = cckyber_compress_coefficient(coeffs[8 * i + j], 11);
        }

        *(out++) = (uint8_t)  (u[0] >>  0);
        *(out++) = (uint8_t) ((u[0] >>  8) | (u[1] << 3));
        *(out++) = (uint8_t) ((u[1] >>  5) | (u[2] << 6));
        *(out++) = (uint8_t)  (u[2] >>  2);
        *(out++) = (uint8_t) ((u[2] >> 10) | (u[3] << 1));
        *(out++) = (uint8_t) ((u[3] >>  7) | (u[4] << 4));
        *(out++) = (uint8_t) ((u[4] >>  4) | (u[5] << 7));
        *(out++) = (uint8_t)  (u[5] >>  1);
        *(out++) = (uint8_t) ((u[5] >>  9) | (u[6] << 2));
        *(out++) = (uint8_t) ((u[6] >>  6) | (u[7] << 5));
        *(out++) = (uint8_t)  (u[7] >>  3);
    }
}

/*! @function cckyber_decompress_coefficient
 @abstract Uncompresses a given d-bit coefficient.

 @param coeff Coefficient.
 @param d     Parameter d.

 @return The uncompressed coefficient.
 */
CC_INLINE CC_WARN_RESULT CC_NONNULL_ALL
int16_t cckyber_decompress_coefficient(uint16_t coeff, unsigned d)
{
    // Mask the `d` lowest bits.
    uint32_t mask = (1U << d) - 1;

    // Compute round((q / 2^d) * u).
    return (int16_t) (((uint32_t)(coeff & mask) * CCKYBER_Q + (1U << (d-1))) >> d);
}

void cckyber_poly_decompress_d1(int16_t coeffs[CCKYBER_N], const uint8_t in[32])
{
    for (unsigned i = 0; i < CCKYBER_N / 8; i++) {
        for (unsigned j = 0; j < 8; j++) {
            *(coeffs++) = cckyber_decompress_coefficient((in[i] >> j) & 1, 1);
        }
    }
}

void cckyber_poly_decompress_d4(int16_t coeffs[CCKYBER_N], const uint8_t in[128])
{
    for (unsigned i = 0; i < CCKYBER_N / 2; i++) {
        *(coeffs++) = cckyber_decompress_coefficient(in[i] >> 0, 4);
        *(coeffs++) = cckyber_decompress_coefficient(in[i] >> 4, 4);
    }
}

void cckyber_poly_decompress_d5(int16_t coeffs[CCKYBER_N], const uint8_t in[160])
{
    uint8_t u[8];

    for (unsigned i = 0; i < CCKYBER_N / 8; i++) {
        u[0] = (uint8_t)  (in[5 * i + 0] >> 0);
        u[1] = (uint8_t) ((in[5 * i + 1] << 3) | (in[5 * i + 0] >> 5));
        u[2] = (uint8_t)  (in[5 * i + 1] >> 2);
        u[3] = (uint8_t) ((in[5 * i + 2] << 1) | (in[5 * i + 1] >> 7));
        u[4] = (uint8_t) ((in[5 * i + 3] << 4) | (in[5 * i + 2] >> 4));
        u[5] = (uint8_t)  (in[5 * i + 3] >> 1);
        u[6] = (uint8_t) ((in[5 * i + 4] << 2) | (in[5 * i + 3] >> 6));
        u[7] = (uint8_t)  (in[5 * i + 4] >> 3);

        for (unsigned j = 0; j < 8; j++) {
            *(coeffs++) = cckyber_decompress_coefficient(u[j], 5);
        }
    }
}

void cckyber_poly_decompress_d10(int16_t coeffs[CCKYBER_N], const uint8_t in[320])
{
    uint16_t u[4];

    for (unsigned i = 0; i < CCKYBER_N / 4; i++) {
        u[0] = (uint16_t) ((in[5 * i + 0] >> 0) | ((uint16_t)in[5 * i + 1] << 8));
        u[1] = (uint16_t) ((in[5 * i + 1] >> 2) | ((uint16_t)in[5 * i + 2] << 6));
        u[2] = (uint16_t) ((in[5 * i + 2] >> 4) | ((uint16_t)in[5 * i + 3] << 4));
        u[3] = (uint16_t) ((in[5 * i + 3] >> 6) | ((uint16_t)in[5 * i + 4] << 2));

        for (unsigned j = 0; j < 4; j++) {
            *(coeffs++) = cckyber_decompress_coefficient(u[j], 10);
        }
    }
}

void cckyber_poly_decompress_d11(int16_t coeffs[CCKYBER_N], const uint8_t in[352])
{
    uint16_t u[8];

    for (unsigned i = 0; i < CCKYBER_N / 8; i++) {
        u[0] = (uint16_t) ((in[11 * i + 0] >> 0) | ((uint16_t)in[11 * i +  1] << 8));
        u[1] = (uint16_t) ((in[11 * i + 1] >> 3) | ((uint16_t)in[11 * i +  2] << 5));
        u[2] = (uint16_t) ((in[11 * i + 2] >> 6) | ((uint16_t)in[11 * i +  3] << 2) | ((uint16_t)in[11 * i + 4] << 10));
        u[3] = (uint16_t) ((in[11 * i + 4] >> 1) | ((uint16_t)in[11 * i +  5] << 7));
        u[4] = (uint16_t) ((in[11 * i + 5] >> 4) | ((uint16_t)in[11 * i +  6] << 4));
        u[5] = (uint16_t) ((in[11 * i + 6] >> 7) | ((uint16_t)in[11 * i +  7] << 1) | ((uint16_t)in[11 * i + 8] <<  9));
        u[6] = (uint16_t) ((in[11 * i + 8] >> 2) | ((uint16_t)in[11 * i +  9] << 6));
        u[7] = (uint16_t) ((in[11 * i + 9] >> 5) | ((uint16_t)in[11 * i + 10] << 3));

        for (unsigned j = 0; j < 8; j++) {
            *(coeffs++) = cckyber_decompress_coefficient(u[j], 11);
        }
    }
}
