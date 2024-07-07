/* Copyright (c) (2014-2023) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "cc_workspaces.h"

/*! @function cczp_sqrt_3mod4_ws
 @abstract Computes the square root r for r^2 = x mod p as r = x^((p+1)/4).
           Requires that p = 3 mod 4.

 @param ws Workspace
 @param zp Multiplicative group Z/(p)
 @param r  Square root of x
 @param x  Quadratic residue

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL CC_WARN_RESULT
static int cczp_sqrt_3mod4_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_assert((cczp_prime(zp)[0] % 4) == 3);

    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    // t = (p+1)/4
    cc_unit *t = CC_ALLOC_WS(ws, n);
    ccn_add1_ws(ws, n, t, cczp_prime(zp), 1);
    ccn_shift_right(n, t, t, 2);

    // r = x^((p+1)/4)
    int rv = cczp_power_fast_ws(ws, zp, r, x, t);
    if (rv) {
        goto cleanup;
    }

    // r^2 == x ?
    cczp_sqr_ws(ws, zp, t, r);
    if (ccn_cmp(n, t, x)) {
        rv = CCERR_PARAMETER;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cczp_sqrt_tonelli_shanks_precomp_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r,
                                        const cc_unit *x, size_t c1,
                                        const cc_unit *c3, const cc_unit *c5)
{
    int rv = CCERR_PARAMETER;
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);
    cc_unit *b = CC_ALLOC_WS(ws, n);
    cc_unit *c = CC_ALLOC_WS(ws, n);
    cc_unit *one = CC_ALLOC_WS(ws, n);

    // r = x^c3
    rv = cczp_power_fast_ws(ws, zp, r, x, c3);
    if (rv) {
        goto cleanup;
    }

    ccn_seti(n, one, 1);
    cczp_to_ws(ws, zp, one, one);

    // c = c5
    ccn_set(n, c, c5);

    // t = r * r * x
    cczp_sqr_ws(ws, zp, t, r);
    cczp_mul_ws(ws, zp, t, t, x);

    // r = r * x
    cczp_mul_ws(ws, zp, r, r, x);

    // for k in (c1, c1 - 1, ..., 2):
    for (size_t k = c1; k >= 2; k--) {
        // b = t
        ccn_set(n, b, t);

        // for j in (1, 2, ..., k - 1):
        for (size_t j = 1; j < k - 1; j++) {
             // b = b * b
             cczp_sqr_ws(ws, zp, b, b);
        }

        // r = CMOV(r * c, r, b == 1)
        cc_unit s = (cc_unit)ccn_cmp(n, b, one) & 1;
        cczp_mul_ws(ws, zp, b, r, c);
        ccn_mux(n, s, r, b, r);

        // c = c * c
        cczp_sqr_ws(ws, zp, c, c);

        // t = CMOV(t * c, t, b == 1)
        cczp_mul_ws(ws, zp, b, t, c);
        ccn_mux(n, s, t, b, t);
    }

    // r^2 == x ?
    cczp_sqr_ws(ws, zp, b, r);
    if (ccn_cmp(n, b, x)) {
        rv = CCERR_PARAMETER;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}


/*! @function cczp_sqrt_tonelli_shanks_ws
 @abstract Computes x^(1/2) (mod p) via constant-time Tonelli-Shanks.

 @discussion This follows the constant-time algorithm described by the CFRG's
             "Hashing to Elliptic Curves" document.

 @param ws Workspace
 @param zp Multiplicative group Z/(p)
 @param r  Square root of x
 @param x  Quadratic residue

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL CC_WARN_RESULT CC_UNUSED
static int cczp_sqrt_tonelli_shanks_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    // c1, the largest integer such that 2^c1 divides p - 1.
    cc_unit *pm1 = CC_ALLOC_WS(ws, n);
    ccn_set(n, pm1, cczp_prime(zp));
    pm1[0] &= ~CC_UNIT_C(1);
    size_t c1 = ccn_trailing_zeros(n, pm1);

    // c2 = (p - 1) / (2^c1)
    cc_unit *c2 = pm1;
    ccn_shift_right_multi(n, c2, pm1, c1);

    // c3 = (c2 - 1) / 2
    cc_unit *c3 = CC_ALLOC_WS(ws, n);
    ccn_sub1(n, c3, c2, 1);
    ccn_shift_right(n, c3, c3, 1);

    // c4, a non-square value in F.
    cc_unit *c4 = CC_ALLOC_WS(ws, n);
    ccn_seti(n, c4, 1);

    while (cczp_is_quadratic_residue_ws(ws, zp, c4) == 1) {
        ccn_add1_ws(ws, n, c4, c4, 1);
    }

    // c5 = c4^c2 in F.
    cc_unit *c5 = c4;
    int rv = cczp_power_fast_ws(ws, zp, c5, c4, c2);
    if (rv) {
        goto cleanup;
    }

    rv = cczp_sqrt_tonelli_shanks_precomp_ws(ws, zp, r, x, c1, c3, c5);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cczp_sqrt_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    int rv = CCERR_PARAMETER;
    cc_assert(r != x);

    // Both functions check whether r^2 == x.
    if ((cczp_prime(zp)[0] & 3) == 3) {
        rv = cczp_sqrt_3mod4_ws(ws, zp, r, x);
#if CCZP_SUPPORT_SQRT_1MOD4
    } else {
        rv = cczp_sqrt_tonelli_shanks_ws(ws, zp, r, x);
#endif
    }

    return rv;
}

CC_WORKSPACE_OVERRIDE(cczp_sqrt_ws, cczp_sqrt_default_ws)

// Override workspace definitions so they're correct for CC_SMALL_CODE=0 and =1.
CC_WORKSPACE_OVERRIDE(cczp_sqrt_default_ws, cczp_sqrt_3mod4_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqrt_default_ws, cczp_sqrt_tonelli_shanks_ws)

int cczp_sqrt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    return CCZP_FUNCS_GET(zp, cczp_sqrt)(ws, zp, r, x);
}

int cczp_sqrt(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_SQRT_WORKSPACE_N(cczp_n(zp)));
    int rv = cczp_sqrt_ws(ws, zp, r, x);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
