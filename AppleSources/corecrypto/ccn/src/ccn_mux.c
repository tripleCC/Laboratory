/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"
#include "ccn_mux.h"

void ccn_mux(cc_size n, cc_unit s, cc_unit *r, const cc_unit *a, const cc_unit *b)
{
    cc_unit m0, m1, mask;
    ccn_mux_setup(&m0, &m1, &mask, s);

    for (cc_size i = 0; i < n; i++) {
        ccn_mux_op(&r[i], a[i], b[i], m0, m1, mask);
    }
}

/**
 * xorshift32/64 PRNG.
 *
 * This is not a cryptographically secure PRNG. It is however fast, and
 * small in code and state. It has a period of 2^64-1 and 2^32-1 respectively.
 * It does not pass every statistical test, yet is sufficient for masking of
 * cmov/cswap operations.
 *
 * This is essentially a compromise between high-quality randomness and speed.
 * By keeping overhead low we can afford to change masks between every
 * cswap/cmov operation and (w.h.p.) never use the same mask in a row.
 */

/**
 * The internal state is unprotected against concurrent access. Another thread
 * updating the state doesn't break masking. Worst case, multiple threads
 * accessing the RNG in parallel might use the same mask values.
 */
#if (CCN_UNIT_SIZE == 8)
static uint64_t state = 1;
#else
static uint32_t state = 1;
#endif

cc_unit ccn_mux_next_mask(void)
{
    state ^= state << 13;

#if (CCN_UNIT_SIZE == 8)
    state ^= state >> 7;
    state ^= state << 17;
#else
    state ^= state >> 17;
    state ^= state << 5;
#endif

    return (cc_unit)state;
}

void ccn_mux_seed_mask(cc_unit seed)
{
    state ^= seed;
}
