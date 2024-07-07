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

#ifndef _CORECRYPTO_CCKYBER_MULT_H_
#define _CORECRYPTO_CCKYBER_MULT_H_

#include "cc_internal.h"

/*
 These functions implement Plantard multiplication, which is somewhat similar
 to Montgomery multiplication. Multiplicands need to be converted to Plantard
 domain (x * R) and each multiplication divides by factor R.

 Given: q < 2^(l - a - 1), q' = mod± 2^(2l)

 Input: signed a,b in [-q * 2^a, q * 2^a]

 Output: r = a*b * -2^(-2l) mod± q, where r in (-q/2, q/2)

 Compute: r = [(([[abq'] mod± 2^2l] >> l) + 2^a) * q] >> l


 With l=16, we can pick a=3, so that q < 2^(16-3-1). Indeed q=3329 < 2^12.
 The signed inputs a,b are thus in [-q * 8, q * 8].
 */



/*! @function cckyber_mult_i32_i16
 @abstract Implements the inner core of Plantard multiplication,
           a 32x16-bit multiplication mod 2^32.

           When x=q^(-1), factor a*q' is precomputed.
           When x=a*q^(-1), the Plantard multiplication core abq' is completed.

 @param x Factor x (Either q^(-1) or a*q^(-1)).
 @param y Factor y.

 @return x * y mod 2^32.
 */
CC_INLINE uint32_t cckyber_mult_i32_i16(uint32_t x, int16_t y)
{
    return x * (uint32_t)y;
}

/*! @function cckyber_mult_precomp
 @abstract Used to precompute factor a*q' of the Plantard multiplication core.

           The precomputed factor a*q' can later be used with the function
           `cckyber_mult_partial()` to compute to final product, and save
           (n-1) multiplications for every (n) calls.

 @param a Factor a.

 @return a*q' mod 2^32.
 */
CC_INLINE uint32_t cckyber_mult_precomp(int16_t a)
{
    // q^(-1) mod 2^32.
    const uint32_t f = 1806234369;

    return cckyber_mult_i32_i16(f, a);
}

/*! @function cckyber_mult_partial
 @abstract Takes a precomputed factor a*q', completes the inner core of
           the Plantard multiplication and reduces mod± q.

 @param aqi Precomputed a*q' mod 2^32.
 @param b   Factor b.

 @return a * b / -2^32 (mod± q).
 */
CC_INLINE int16_t cckyber_mult_partial(uint32_t aqi, int16_t b)
{
    // Complete the inner core of the Plantard multiplication (abq').
    int32_t t = (int32_t)cckyber_mult_i32_i16(aqi, b);

    // Reduce mod± q.
    return (((t >> 16) + (1 << 3)) * CCKYBER_Q) >> 16;
}

/*! @function cckyber_mult_reduce
 @abstract Reduces a (mod ±q), where a in (-2^15, 2^15).

 @param a Number to reduce.

 @return a (mod± q).
 */
CC_INLINE int16_t cckyber_mult_reduce(int16_t a)
{
    // q^(-1) * -2^32 mod 2^32.
    const uint32_t f = 1290168;

    return cckyber_mult_partial(f, a);
}

/*! @function cckyber_mult_toplant
 @abstract Converts a to Plantard domain, where a in (-2^15, 2^15).

 @param a Number to convert.

 @return a * -2^32 (mod± q).
 */
CC_INLINE int16_t cckyber_mult_toplant(int16_t a)
{
    // q^(-1) * (-2^32)^2 mod 2^32.
    const uint32_t f = 2549370796;

    return cckyber_mult_partial(f, a);
}

#endif /* _CORECRYPTO_CCKYBER_MULT_H_ */
