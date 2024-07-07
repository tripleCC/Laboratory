/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdh_internal.h"
#include "cc_debug.h"
#include "cc_macros.h"

#define MAX_RETRY 100

size_t ccdh_generate_private_key_bitlen(ccdh_const_gp_t gp)
{
    if (ccdh_gp_order_bitlen(gp) > 0) {
        return ccdh_gp_order_bitlen(gp);
    }

    if (ccdh_gp_l(gp) > 0) {
        return ccdh_gp_l(gp);
    }

    return ccdh_gp_prime_bitlen(gp);
}

int ccdh_generate_private_key_ws(cc_ws_t ws, ccdh_const_gp_t gp, cc_unit *x, struct ccrng_state *rng)
{
    int result;
    cc_size n = ccdh_gp_n(gp);
    size_t l = ccdh_gp_l(gp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *upper_bound = CC_ALLOC_WS(ws, n);

    ccn_zero(n, x);
    ccn_zero(n, upper_bound);

    // Pre-requisite, per PKCS #3 (section 6)
    cc_require_action((l <= ccdh_gp_prime_bitlen(gp)),
                      cleanup, result = CCDH_INVALID_DOMAIN_PARAMETER);

    // Generate the random private key x
    // (following pkcs#3 section 7.1 when order is not present)
    // Three cases
    // a) order q is available
    //    0 < x < q-1
    // b) "l" is set, 2^(l-1) <= x < 2^l
    //      upper bound is implicitely met
    //      lower bound is met by setting MS bit
    // c) "l"==0, 0 < x < p-1

    // "l" <= bitlength(order)+64 is a security risk due to the bias it causes
    // Using the order to generate the key is more secure and efficient
    // and therefore takes precedence.

    size_t rand_bitlen = ccdh_generate_private_key_bitlen(gp);
    cc_require(((result = ccn_random_bits(rand_bitlen, x, rng)) == CCERR_OK), cleanup);

    if (ccdh_gp_order_bitlen(gp) == 0 && l > 0) {
        // Bounds are implicitely met
        ccn_set_bit(x, l - 1, 1); // 2^(l-1)
        goto cleanup;
    }

    if (ccdh_gp_order_bitlen(gp) > 0) {
        // Bounds: 0 < x <= q-2
        ccn_sub1(n, upper_bound, ccdh_gp_order(gp), 2);
    } else {
        // Bounds: 0 < x <= p-2
        ccn_sub1(n, upper_bound, ccdh_gp_prime(gp), 2);
    }

    // Try until finding an integer in the correct range
    // This avoids bias in key generation that occurs when using mod.
    size_t i;
    for (i = 0; i < MAX_RETRY; i++) {
        // Check that 0 < x <= upper bound.
        if (ccn_cmp(n, x, upper_bound) <= 0 && !ccn_is_zero(n, x)) {
            break;
        }

        // Generate a new candidate.
        cc_require(((result = ccn_random_bits(rand_bitlen, x, rng)) == CCERR_OK), cleanup);
    }

    // Check that an integer has been found.
    if (i >= MAX_RETRY) {
        result = CCDH_GENERATE_KEY_TOO_MANY_TRIES;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccdh_generate_private_key(ccdh_const_gp_t gp, cc_unit *x, struct ccrng_state *rng)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCDH_GENERATE_PRIVATE_KEY_WORKSPACE_N(ccdh_gp_n(gp)));
    int rv = ccdh_generate_private_key_ws(ws, gp, x, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
