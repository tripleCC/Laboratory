/* Copyright (c) (2019-2023) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccrsa_internal.h"
#include "cc_workspaces.h"

// The probability that one of the values of y in an iteration of
// `ccrsa_find_prime_multiple_ws()` reveals the prime factors p and q is at least
// 1/2. If we fail to recover p and q, then the modulus is with very high
// probability not a product of two prime factors or (d,e) are inconsistent.
#define RECOVER_MAX_TRIES 100

/*! @function ccrsa_find_prime_multiple_ws
 @abstract Probabilistic algorithm to find a multiple (+1) of prime factor
           p or q, for a given RSA modulus m and exponents (e,d).

 @param zm   Z/(m) where m is the RSA modulus
 @param e    Public exponent e
 @param d    Private exponent d
 @param y    Resulting multiple of either prime factor
 @param rng  RNG instance

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
static int ccrsa_find_prime_multiple_ws(cc_ws_t ws, cczp_t zm,
                                        const cc_unit *e, const cc_unit *d,
                                        cc_unit *y, struct ccrng_state *rng)
{
    cc_size n = cczp_n(zm);

    CC_DECL_BP_WS(ws, bp)
    cc_unit *nm1 = CC_ALLOC_WS(ws, n);
    cc_unit *g = CC_ALLOC_WS(ws, n);
    cc_unit *k = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *one = CC_ALLOC_WS(ws, n);

    // e is public and usually much smaller.
    // Let's work with its actual size.
    cc_size ne = ccn_n(n, e);

    // Use Montgomery multiplication to speed up exponentiation.
    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(n));
    cczp_mm_init_copy(zpmm, zm);

    // Let k = de - 1 (we'll subtract 1 later).
    ccn_clear(n + ne, k);
    for (unsigned i = 0; i < ne; i++) {
        k[n + i] = ccn_addmul1(n, k + i, d, e[i]);
    }

    int rv = CCRSA_INVALID_INPUT;

    // If k would be odd, bail.
    if ((k[0] & 1) == 0) {
        goto cleanup;
    }

    // k = de - 1.
    k[0] &= ~CC_UNIT_C(1);

    // Write k as k = 2^t * r.
    size_t t = ccn_trailing_zeros(n + ne, k);
    cc_assert(t >= 1);

    // r is the largest odd integer dividing k.
    cc_unit *r = k;
    ccn_shift_right_multi(n + ne, r, k, t);
    cc_assert(r[0] & 1);

    // nm1 = n - 1
    ccn_set(n, nm1, cczp_prime(zm));
    nm1[0] &= ~CC_UNIT_C(1);
    cczp_to_ws(ws, zpmm, nm1, nm1);

    ccn_seti(n, one, 1);
    cczp_to_ws(ws, zpmm, one, one);

    // Hide r's actual bit length.
    size_t r_bitlen = ccn_bitsof_n(n + ne);

    for (unsigned i = 0; i < RECOVER_MAX_TRIES; i++) {
        // Generate a random int in range [1,n-1].
        // Note: The element returned will be interpreted as being in Montgomery
        // space. So g will effectively be g/R, as we don't (need to) convert it.
        rv = cczp_generate_non_zero_element_ws(ws, zm, rng, g);
        if (rv) {
            goto cleanup;
        }

        // y = g^r (mod n)
        rv = cczp_power_ws(ws, zpmm, y, g, r_bitlen, r);
        if (rv) {
            goto cleanup;
        }

        // if y=1 or y=n-1, try next candidate
        if (ccn_cmp(n, y, one) == 0 || ccn_cmp(n, nm1, y) == 0) {
            continue;
        }

        cc_unit *x = g;
        for (unsigned j = 0; j < t; j++) {
            // x = y^2 (mod n)
            cczp_sqr_ws(ws, zpmm, x, y);

            // if x=1, return y
            if (ccn_cmp(n, x, one) == 0) {
                goto cleanup;
            }

            // if x=n-1, try next candidate
            if (ccn_cmp(n, nm1, x) == 0) {
                break;
            }

            ccn_set(n, y, x);
        }
    }

    // If we get here, with very high probability, the modulus is either not the
    // product of two prime factors, or (e,d) are not consistent with each other.
    rv = CCRSA_INVALID_INPUT;

cleanup:
    cczp_from_ws(ws, zpmm, y, y);
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/*! @function ccrsa_recover_pq_ws
 @abstract Recovers prime factors p,q for a given RSA context and a multiple (+1)
           of either p or q.

 @param fk  Full RSA context
 @param y   Multiple (+1) of prime factor p or q

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
static int ccrsa_recover_pq_ws(cc_ws_t ws, ccrsa_full_ctx_t fk, const cc_unit *y)
{
    int rv = CCRSA_INVALID_INPUT;
    cc_size n = ccrsa_ctx_n(fk);
    cczp_t zm = ccrsa_ctx_zm(fk);

    CC_DECL_BP_WS(ws, bp)
    cc_unit *p = CC_ALLOC_WS(ws, n);
    cc_unit *q = CC_ALLOC_WS(ws, n);

    // p = gcd(n, y - 1)
    ccn_sub1(n, p, y, 1);
    size_t k = ccn_gcd_ws(ws, n, p, n, cczp_prime(zm), ccn_n(n, p), p);

    // p can't be of form p = 2^k * x with k > 0.
    if (k > 0) {
        goto cleanup;
    }

    // q = n/p
    ccn_div_exact_ws(ws, n, q, cczp_prime(zm), p);

    // We require that p > q.
    unsigned int s = (unsigned int)ccn_cmp(n, p, q);

    // ccrsa_find_prime_multiple_ws() should fail if p=q, but let's make sure.
    if (s == 0) {
        goto cleanup;
    }

    // Restore order so that p > q.
    ccn_cond_swap(n, (cc_unit)(s >> (sizeof(unsigned int) * 8 - 1)), p, q);

    cczp_t zp = ccrsa_ctx_private_zp(fk);
    CCZP_N(zp) = ccn_n(n, p);
    ccn_set(cczp_n(zp), CCZP_PRIME(zp), p);
    rv = cczp_init_ws(ws, zp);
    if (rv) {
        goto cleanup;
    }

    cczp_t zq = ccrsa_ctx_private_zq(fk);
    CCZP_N(zq) = ccn_n(n, q);
    ccn_set(cczp_n(zq), CCZP_PRIME(zq), q);
    rv = cczp_init_ws(ws, zq);
    if (rv) {
        goto cleanup;
    }

    // p can be up to 2 bits longer than q.
    if (cczp_bitlen(zp) - cczp_bitlen(zq) > 2) {
        rv = CCRSA_INVALID_INPUT;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_NONNULL_ALL
static int ccrsa_recover_priv_ws(cc_ws_t ws, ccrsa_full_ctx_t fk,
                                 size_t m_nbytes, const uint8_t *m_bytes,
                                 size_t e_nbytes, const uint8_t *e_bytes,
                                 size_t d_nbytes, const uint8_t *d_bytes,
                                 struct ccrng_state *rng)
{
    cc_size n = ccn_nof_size(m_nbytes);
    ccrsa_ctx_n(fk) = n;

    cczp_t zm = ccrsa_ctx_zm(fk);
    cc_unit *e = ccrsa_ctx_e(fk);
    int rv = CCRSA_INVALID_INPUT;

    CC_DECL_BP_WS(ws, bp)

    cc_unit *m = CC_ALLOC_WS(ws, n);
    cc_unit *d = CC_ALLOC_WS(ws, n);
    cc_unit *y = CC_ALLOC_WS(ws, n);

    if (ccn_read_uint(n, m, m_nbytes, m_bytes)) {
        goto cleanup;
    }

    // Sanity check the modulus.
    if ((m[0] & 1) == 0) {
        goto cleanup;
    }

    if (ccn_read_uint(n, e, e_nbytes, e_bytes)) {
        goto cleanup;
    }

    if (ccn_read_uint(n, d, d_nbytes, d_bytes)) {
        goto cleanup;
    }

    ccn_set(n, CCZP_PRIME(zm), m);
    rv = cczp_init_ws(ws, zm);
    if (rv) {
        goto cleanup;
    }

    // Find a multiple (+1) of p or q.
    rv = ccrsa_find_prime_multiple_ws(ws, zm, e, d, y, rng);
    if (rv) {
        goto cleanup;
    }

    // Recover prime factors p,q from the multiple y-1.
    rv = ccrsa_recover_pq_ws(ws, fk, y);
    if (rv) {
        goto cleanup;
    }

    // Compute the remaining CRT components dp,dq,qinv. This will re-compute
    // n=p*q and d=1/e, we'll use those for sanity checks at the end.
    rv = ccrsa_crt_makekey_ws(ws, fk);
    if (rv) {
        goto cleanup;
    }

    // Sanity check against the original modulus.
    if (ccn_cmp(n, m, cczp_prime(zm))) {
        rv = CCRSA_INVALID_INPUT;
    }

    // Sanity check against the original private exponent.
    if (ccn_cmp(n, d, ccrsa_ctx_d(fk))) {
        rv = CCRSA_INVALID_INPUT;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccrsa_recover_priv(ccrsa_full_ctx_t fk,
                       size_t m_nbytes, const uint8_t *m_bytes,
                       size_t e_nbytes, const uint8_t *e_bytes,
                       size_t d_nbytes, const uint8_t *d_bytes,
                       struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccn_nof_size(m_nbytes);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_RECOVER_PRIV_WORKSPACE_N(n));
    int rv = ccrsa_recover_priv_ws(ws, fk, m_nbytes, m_bytes, e_nbytes, e_bytes, d_nbytes, d_bytes, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
