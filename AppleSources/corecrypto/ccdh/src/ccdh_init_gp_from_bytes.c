/* Copyright (c) (2016-2022) Apple Inc. All rights reserved.
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
#include "ccdh_internal.h"
#include "ccprime_internal.h"
#include "cc_macros.h"

#define MR_ITERATIONS 5

CC_NONNULL_ALL CC_WARN_RESULT
static int ccdh_is_safe_prime_group_ws(cc_ws_t ws, ccdh_const_gp_t gp, struct ccrng_state *rng)
{
    // Prime needs to be odd.
    if ((ccdh_gp_prime(gp)[0] & 1) == 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccdh_gp_n(gp);
    cc_unit *pm1h = CC_ALLOC_WS(ws, n);

    // pm1h := (p - 1) / 2
    ccn_shift_right(n, pm1h, ccdh_gp_prime(gp), 1);

    // Check if (p - 1) / 2 is prime.
    int rv = ccprime_rabin_miller_ws(ws, n, pm1h, MR_ITERATIONS, rng);

    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_NONNULL((1, 2, 5, 7)) CC_WARN_RESULT
static int ccdh_init_gp_from_bytes_ws(cc_ws_t ws, ccdh_gp_t gp, cc_size n,
                                      size_t p_nbytes, const uint8_t *p,
                                      size_t g_nbytes, const uint8_t *g,
                                      size_t q_nbytes, const uint8_t *q,
                                      size_t l_bits)
{
    int rv = ccn_read_uint(n, CCDH_GP_PRIME(gp), p_nbytes, p);
    cc_require_or_return(rv == CCERR_OK, rv);

    // Correct `n`, in case `p` has leading zeros.
    n = ccn_n(n, ccdh_gp_prime(gp));

    CCDH_GP_N(gp) = n;
    rv = ccn_read_uint(n, CCDH_GP_G(gp), g_nbytes, g);
    cc_require_or_return(rv == CCERR_OK, rv);

    // See if we can find a matching pre-defined group.
    ccdh_const_gp_t known_group = ccdh_lookup_gp(n, ccdh_gp_prime(gp), n, ccdh_gp_g(gp));

    // If the group is known, copy q and l parameters.
    // Otherwise read in whatever was provided as q and l.
    if (known_group) {
        (void)ccdh_copy_gp(gp, known_group);

        // If there's no defined group length, use the one provided, if any.
        if (ccdh_gp_l(gp) == CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH && l_bits != CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH) {
            CCDH_GP_L(gp) = CC_MAX_EVAL(l_bits, CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH);
        }

        return CCERR_OK;
    }

    struct ccrng_state *rng = ccrng(NULL);
    cc_require_or_return(rng != NULL, CCERR_INTERNAL);

    CC_DECL_BP_WS(ws, bp);

    // Check that p is prime.
    rv = ccprime_rabin_miller_ws(ws, n, ccdh_gp_prime(gp), MR_ITERATIONS, rng);
    cc_require(rv >= 0, errOut);

    // Fail when p is not a prime.
    cc_require_action(rv == 1, errOut, rv = CCDH_GP_P_NOTPRIME);

    // Default setting, ignored when q is given.
    CCDH_GP_L(gp) = CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH;

    if (q) {
        rv = ccn_read_uint(n, CCDH_GP_Q(gp), q_nbytes, q);
        cc_require(rv == CCERR_OK, errOut);

        // Check that q is prime.
        rv = ccprime_rabin_miller_ws(ws, n, ccdh_gp_order(gp), MR_ITERATIONS, rng);
        cc_require(rv >= 0, errOut);

        // Fail when q is not a prime.
        cc_require_action(rv == 1, errOut, rv = CCDH_GP_Q_NOTPRIME);
    } else {
        ccn_zero(n, CCDH_GP_Q(gp));

        if (l_bits != CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH) {
            CCDH_GP_L(gp) = CC_MAX_EVAL(l_bits, CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH);
        }

        // Check that p is a safe prime when no order is given.
        rv = ccdh_is_safe_prime_group_ws(ws, gp, rng);
        cc_require(rv >= 0, errOut);

        // Fail when p is not a safe prime.
        cc_require_action(rv == 1, errOut, rv = CCDH_GP_NONSAFE_PRIME);
    }

    rv = cczp_init_ws(ws, CCDH_GP_ZP(gp));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccdh_init_gp_from_bytes(ccdh_gp_t gp, cc_size n,
                            size_t p_nbytes, const uint8_t *p,
                            size_t g_nbytes, const uint8_t *g,
                            size_t q_nbytes, const uint8_t *q,
                            size_t l_bits)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCDH_INIT_GP_FROM_BYTES_WORKSPACE_N(n));
    int rv = ccdh_init_gp_from_bytes_ws(ws, gp, n, p_nbytes, p, g_nbytes, g, q_nbytes, q, l_bits);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
