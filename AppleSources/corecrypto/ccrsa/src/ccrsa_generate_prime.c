/* Copyright (c) (2011-2013,2015-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"
#include <corecrypto/ccrng.h>

int ccrsa_generate_prime_ws(cc_ws_t ws,
                            cc_size nbits,
                            cc_unit *p,
                            const cc_unit *e,
                            struct ccrng_state *rng,
                            struct ccrng_state *rng_mr)
{
    cc_size n = ccn_nof(nbits);

    if (n == 0) {
        return CCERR_PARAMETER;
    }

    // Public exponent must be >= 3 and odd.
    cc_assert(ccn_bitlen(n, e) > 1 && (e[0] & 1) == 1);

    int rv = CCERR_OK;
    cc_size ne = ccn_n(n, e);
    CC_DECL_BP_WS(ws, bp);

    while (1) {
        /* Generate nbit wide random ccn. */
        rv = ccn_random_bits(nbits, p, rng);
        if (rv) {
            break;
        }

        ccn_set_bit(p, nbits - 1, 1); /* Set high bit. */
        ccn_set_bit(p, nbits - 2, 1); /* Set second highest bit per X9.31. */
        ccn_set_bit(p, 0, 1);         /* Set low bit. */

        /* Check that p is a prime and gcd(p-1,e) == 1. */
        size_t mr_depth = ccrsa_num_mr_iterations(nbits);
        rv = ccrsa_is_valid_prime_ws(ws, n, p, ne, e, mr_depth, rng_mr);

        /* We found a prime. */
        if (rv == 1) {
            rv = CCERR_OK;
            break;
        }

        /* The operation failed. */
        if (rv < 0) {
            break;
        }
    }

    CC_FREE_BP_WS(ws, bp);
    return rv;
}
