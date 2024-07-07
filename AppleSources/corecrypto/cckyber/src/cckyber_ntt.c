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

#include "cckyber_internal.h"
#include "cckyber_mult.h"

/*
q = 3329

# Primitive 256-th root of unity.
z = 17

# Plantard domain factor.
R = -2^32 % q

# Precomputation for Plantard multiplication.
qi = q.inverse_mod(2^32)

def to_ctr(x):
    return x - q if x >= q/2 else x

def reverse_bits(n):
    return int("{:0{width}b}".format(n, width=7)[::-1], 2)

tree = [reverse_bits(x) for x in range(0, 128)]

tmp = [R]
for i in range(1, 128):
    tmp.append((tmp[i-1] * z) % q)

print([(to_ctr(tmp[t]) * qi) % 2^32 for t in tree])
 */

// Precomputed powers of zeta, the 256-th primitive root of unity. Each power
// is converted to Plantard domain (z *= R, where R = -2^32 mod q) and then
// multiplied by q^(-1) mod± 2^32 to save one multiplication.
static const uint32_t cckyber_zetas[128] = {
       1290167, 2230699446, 3328631909, 4243360600,
    3408622288,  812805466, 2447447570, 1094061961,
    1370157786, 2475831253,  249002309, 1028263423,
    3594406394, 4205945745,  734105254, 2252632292,
     381889552, 3157039644, 1727534157, 1904287092,
    3929849920,   72249375, 2889974990, 1719793153,
    1839778722, 2701610549,  690239562, 3718262465,
    3087370604, 3714391963, 2546790460, 1059227441,
     372858380,  427045412, 4196914573, 2265533966,
    1544330385, 2972545704, 2937711184, 2651294020,
     838608814, 2550660963, 3242190692,  815385801,
    3696329619,   42575524, 1703020976, 2470670583,
    2991898216, 1851390228, 1041165097,  583155668,
    1855260730, 3700200122, 1979116801, 3098982110,
    3415073125, 3376368103, 1910737929,  836028479,
    3191874164, 4012420634, 1583035408, 1174052340,
      21932846, 3562152209,  752167598, 3417653460,
    2112004044,  932791035, 2951903026, 1419184147,
    1817845876, 3434425636, 4233039260,  300609006,
     975366559, 2781600928, 3889854730, 3935010590,
    2197155093, 2130066388, 3598276897, 2308109490,
    2382939200, 1228239371, 1884934581, 3466679821,
    1211467195, 2977706374, 3144137969, 3080919767,
     945692709, 3015121229,  345764865,  826997308,
    2043625172, 2964804700, 2628071007, 4154339049,
     483812777, 3288636719, 2696449879, 2122325384,
    1371447953,  411563403, 3577634218,  976656727,
    2708061386,  723783915, 3181552824, 3346694252,
    3617629408, 1408862808,  519937465, 1323711759,
    1474661346, 2773859924, 3580214553, 1143088322,
    2221668274, 1563682897, 2417773720, 1327582261,
    2722253228, 3786641338, 1141798155, 2779020593
};

/*! @function cckyber_ntt_forward_layer
 @abstract In-place, single-layer forward NTT.

 @param coeffs Coefficients.
 @param layer  Number of the layer, between 1 and 7, inclusive.
 */
CC_INLINE CC_NONNULL_ALL
void cckyber_ntt_forward_layer(int16_t coeffs[256], unsigned layer)
{
    unsigned len = 1 << layer;
    unsigned k = 128 >> layer;

    for (unsigned i = 0; i < 256; i += 2 * len) {
        uint32_t zeta = cckyber_zetas[k++];

        // CT butterflies.
        for (unsigned j = i; j < i + len; j++) {
            int16_t t = cckyber_mult_partial(zeta, coeffs[j + len]);
            coeffs[j + len] = coeffs[j] - t;
            coeffs[j] += t;
        }
    }
}

void cckyber_ntt_forward(int16_t coeffs[256])
{
    for (unsigned l = 7; l >= 1; l -= 1) {
        cckyber_ntt_forward_layer(coeffs, l);
    }
}

/*! @function cckyber_ntt_inverse_layer
 @abstract In-place, single-layer inverse NTT.

 @param coeffs Coefficients.
 @param layer  Number of the layer, between 1 and 7, inclusive.
 */
CC_INLINE CC_NONNULL_ALL
void cckyber_ntt_inverse_layer(int16_t coeffs[256], unsigned layer)
{
    unsigned len = 1 << layer;
    unsigned k = (128 >> (layer - 1)) - 1;

    for (unsigned i = 0; i < 256; i += 2 * len) {
        uint32_t zeta = cckyber_zetas[k--];

        // GS butterflies.
        for (unsigned j = i; j < i + len; j++) {
            int16_t t = coeffs[j];
            coeffs[j] = cckyber_mult_reduce(t + coeffs[j + len]);
            coeffs[j + len] -= t;
            coeffs[j + len] = cckyber_mult_partial(zeta, coeffs[j + len]);
        }
    }
}

/*! @function cckyber_ntt_inverse_layer_7th
 @abstract In-place, single-layer inverse NTT.

 @param coeffs Coefficients.
 */
CC_INLINE CC_NONNULL_ALL
void cckyber_ntt_inverse_layer_7th(int16_t coeffs[256])
{
    // Instead of z^64 * R (mod± q), use z^64 * R^2 / 128 (mod± q). That way
    // we compensate for factor 1^-128 that accumulates through all seven
    // layers of GS butterflies and convert the final value out of
    // Plantard domain.
    uint32_t zeta = 2492603429; // cckyber_zetas[1];

    // For the part of the butterfly not multiplied by zeta, compensate
    // for factor 1^-128 and convert out of Plantard domain.
    uint32_t f = 2435836063;

    // GS butterfly.
    for (unsigned j = 0; j < 128; j++) {
        int16_t t = coeffs[j];
        coeffs[j] = cckyber_mult_partial(f, t + coeffs[j + 128]);
        coeffs[j + 128] -= t;
        coeffs[j + 128] = cckyber_mult_partial(zeta, coeffs[j + 128]);
    }
}

void cckyber_ntt_inverse(int16_t coeffs[256])
{
    // 6-layer inverse NTT (7th is computed seperately).
    for (unsigned l = 1; l <= 6; l += 1) {
        cckyber_ntt_inverse_layer(coeffs, l);
    }

    // 7th and last layer.
    cckyber_ntt_inverse_layer_7th(coeffs);
}

/*! @function cckyber_ntt_basemul_inner
 @abstract Base multiplication of two degree-1 polynomials.

 @param coeffs Coefficients of the resulting degree-1 polynomial.
 @param a      Coefficients of the first degree-1 polynomial.
 @param b      Coefficients of the second degree-1 polynomial.
 @param zeta   Power of the 256-th root of unity.
 */
CC_INLINE CC_NONNULL_ALL
void cckyber_ntt_basemul_inner(int16_t coeffs[2], const int16_t a[2], const int16_t b[2], uint32_t zeta)
{
    uint32_t a0 = cckyber_mult_precomp(a[0]);
    uint32_t a1 = cckyber_mult_precomp(a[1]);

    // c[0] = (a[0] · b[0]) + ((a[1] · b[1]) · r) (mod q)
    coeffs[0]  = cckyber_mult_partial(a1, b[1]);
    coeffs[0]  = cckyber_mult_partial(zeta, coeffs[0]);
    coeffs[0] += cckyber_mult_partial(a0, b[0]);

    // c[1] = (a[0] · b[1]) + (a[1] · b[0]) (mod q)
    coeffs[1]  = cckyber_mult_partial(a0, b[1]);
    coeffs[1] += cckyber_mult_partial(a1, b[0]);
}

void cckyber_ntt_basemul(int16_t coeffs[256], const int16_t a[256], const int16_t b[256])
{
    for (unsigned i = 0; i < 64; i++) {
        uint32_t zeta = cckyber_zetas[64 + i];

        cckyber_ntt_basemul_inner(&coeffs[4 * i + 0], &a[4 * i + 0], &b[4 * i + 0],  zeta);
        cckyber_ntt_basemul_inner(&coeffs[4 * i + 2], &a[4 * i + 2], &b[4 * i + 2], -zeta);
    }
}
