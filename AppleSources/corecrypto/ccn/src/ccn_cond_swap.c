/* Copyright (c) (2016-2019,2021) Apple Inc. All rights reserved.
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

/* Conditionally swap the content of r0 and r1 buffers in constant time
 r0:r1 <- r1*k1 + s0*(k1-1)  */
void ccn_cond_swap(cc_size n, cc_unit ki, cc_unit *r0, cc_unit *r1)
{
    cc_unit m0, m1, mask;
    ccn_mux_setup(&m0, &m1, &mask, ki);

    for (cc_size i = 0; i < n; i++) {
        cc_unit ab = r0[i] ^ r1[i];

        // Write the masked values to memory. This is done so the final
        // writes to memory aren't just no-ops when we didn't swap values.
        r0[i] ^= mask;
        r1[i] ^= mask;

        // (ab & m0) doesn't depend on `ki`.
        cc_unit t0 = r0[i] ^ (ab & m0);
        cc_unit t1 = r1[i] ^ (ab & m0);

        // Ensure instruction order for anything involving registers `t0`, `t1`.
        __asm__ __volatile__("" :: "r"(t0), "r"(t1));

        // XOR the other half of `ab` into the masked inputs.
        // We have now swapped the masked inputs if `ki=1`.
        t0 ^= (ab & m1);
        t1 ^= (ab & m1);

        // Ensure instruction order, so that unmasking comes last.
        // Also ensure that `r0[i]` and `r1[i]` were written to memory.
        __asm__ __volatile__("" :: "r"(t0), "r"(t1), "m"(r0[i]), "m"(r1[i]));

        // Unmask the results.
        r0[i] = t0 ^ mask;
        r1[i] = t1 ^ mask;
    }
}
