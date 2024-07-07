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

#ifndef _CORECRYPTO_CCN_MUX_H
#define _CORECRYPTO_CCN_MUX_H

#include "ccn_internal.h"

/*! @function ccn_mux_next_mask
 @abstract Returns the next pseudorandom mask value to be used for cmov/cswap.

 @return A pseudorandom word, as derived from the state.
 */
cc_unit ccn_mux_next_mask(void);

#if CC_ARM_ARCH_7 || defined(__arm64__)

// Use inline assembly for ARM.
#define ccn_mux_ror(m1, m0, s) \
    __asm__ __volatile__("ror %0, %1, %2" : "=r"(m1) : "r"(m0), "r"(s))

#else

// On all other architectures, implement ROR via bit shifts. An optimizing
// compiler _should_ turn this into a ROR. Just in case it doesn't, we have
// to guard against undefined behavior by ensuring 0 < s < CCN_UNIT_BITS.
#define ccn_mux_ror(m1, m0, s)                                \
    do {                                                      \
        s &= CCN_UNIT_BITS - 1;                               \
        s |= CCN_UNIT_BITS >> 1;                              \
        m1 = ((m0) >> (s)) | ((m0) << (CCN_UNIT_BITS - (s))); \
    } while (0)

#endif

/*! @function ccn_mux_setup
 @abstract Setup for ccn_mux() and similar functions. Prepares bit masks `m0`
           and `m1` according to `s`. `mask` will be a new random mask.

 @param m0    Pointer to bit mask m0.
 @param m1    Pointer to bit mask m1.
 @param mask  Pointer to random mask.
 @param s     Secret bit.
 */
CC_NONNULL_ALL CC_INLINE
void ccn_mux_setup(cc_unit *m0, cc_unit *m1, cc_unit *mask, cc_unit s)
{
    cc_assert((s >> 1) == 0);

    // Randomize `m1`.
    *m1 = *mask = ccn_mux_next_mask();
    *m0 = (cc_unit)0x5555555555555555;

    // Incorporate the secret `s` via bitwise OR. This will result in a random
    // number that is either even or odd depending on `s`.
    // When even, `m1 = m0`. When odd, `m1 = m0 << 1`.
    s |= *mask << 1;

    // Ensure `m1` and `s` were written to before shifting.
    __asm__ __volatile__("" :: "r"(*m1), "r"(s));

    // m1 := m0 >>> s
    ccn_mux_ror(*m1, *m0, s);
}

/*! @function ccn_mux_op
 @abstract Masked multiplexing operation, using bit masks and the random mask
           given by ccn_mux_setup().

 @param r     Pointer to result.
 @param a     Value a.
 @param b     Value b.
 @param m0    Bit mask m0, as given by ccn_mux_setup().
 @param m1    Bit mask m1, as given by ccn_mux_setup().
 @param mask  Random mask, as given by ccn_mux_setup().
 */
CC_NONNULL_ALL CC_INLINE
void ccn_mux_op(cc_unit *r, cc_unit a, cc_unit b, cc_unit m0, cc_unit m1, cc_unit mask)
{
    cc_unit ab = a ^ b;

    // Write the masked value to memory. This is done so the final
    // write to memory isn't just a no-op when it's the same value.
    *r = b ^ mask;

    // (ab & m0) doesn't depend on `s`.
    cc_unit t0 = *r ^ (ab & m0);

    // Ensure instruction order for anything involving register `t0`.
    __asm__ __volatile__("" :: "r"(t0));

    // XOR the other half of `ab` into the masked result. The output is
    // now the masked value `a` or `b`, depending on `s`.
    t0 ^= (ab & m1);

    // Ensure instruction order, so that unmasking comes last.
    // Also ensure that `r[i]` was written to memory.
    __asm__ __volatile__("" :: "r"(t0), "m"(*r));

    // Unmask the result.
    *r = t0 ^ mask;
}

#endif // _CORECRYPTO_CCN_MUX_H
