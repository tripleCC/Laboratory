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

/*
 * Based on reference code from <http://ed25519.cr.yp.to/> and <http://bench.cr.yp.to/supercop.html>.
 */

#include "ccn_internal.h"

void ccn_recode_ssw(cc_size n, const cc_unit *s, int w, int8_t *r)
{
    // Initialize r[i] with the value bit s_{i}.
    for (size_t j = 0; j < ccn_bitsof_n(n); j += 1) {
        r[j] = (int8_t)ccn_bit(s, j);
    }

    // For all non-zero bits, starting with least-significant one, combine
    // subsequent non-zero bits into the largest possible signed window in
    // range (-2^w, 2^w).
    for (int i = 0; i < (int)ccn_bitsof_n(n); i += 1) {
        if (r[i] == 0) {
            continue;
        }

        // Check subsequent non-zero bits and combine, if possible.
        for (int b = 1; b + 1 < (1 << (w - 1)) && i + b < (int)ccn_bitsof_n(n); b += 1) {
            if (r[i + b] == 0) {
                continue;
            }

            int t = r[i + b] << b;

            // Is the new window < 2^w?
            if (r[i] + t < (1 << w)) {
                r[i] += t;
                r[i + b] = 0;
                continue;
            }

            // Is the new window > -2^w?
            if (r[i] - t > -(1 << w)) {
                r[i] -= t;

                // Flip all non-zero bits until we hit a zero, flip that too.
                // Accounts for the negative window that was just recorded.
                for (int k = i + b; k < (int)ccn_bitsof_n(n); k += 1) {
                    if (r[k] == 0) {
                        r[k] = 1;
                        break;
                    }

                    r[k] = 0;
                }

                continue;
            }

            // Build the next window if the current one is exhausted.
            break;
        }
    }
}
