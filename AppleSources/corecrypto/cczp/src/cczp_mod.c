/* Copyright (c) (2011,2012,2014-2023) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"

#define NUM_ITERATIONS(_n_, _nx_) CC_MAX_EVAL(((_nx_) - 1) / (_n_), 1U)

void cczp_modn_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, cc_size nx, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    cc_assert(nx >= n);

    size_t iterations = NUM_ITERATIONS(n, nx);

    CC_DECL_BP_WS(ws, bp);

    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);
    ccn_set(n, t, x);

    // Reduce x until it fits into '2n' limbs.
    for (size_t j = 0; j < iterations - 1; j += 1) {
        ccn_set(n, &t[n], &x[(j + 1) * n]);
        cczp_mm_redc_ws(ws, zp, t, t);
    }

    // Last round. Reduce x to 'n' limbs.
    ccn_setn(n, &t[n], nx - (iterations * n), &x[iterations * n]);
    cczp_mm_redc_ws(ws, zp, r, t);

    // r now fits into 'n' limbs. We have r = x / R^iterations (mod p).
    // To correct r, we'll multiply by R^iterations in the loop below
    // to arrive at r = x (mod p).

    // The REDC algorithm requires x < p * 2^(n*w) to fully reduce x (mod p).
    // If p << 2^(n*w), the last round above might leave us with r >= p. But
    // we also know that r < 2^(n*w). The first iteration of the next loop
    // will multiply by R^2 (mod p), so the result will be < p*R and the
    // REDC algorithm fully reduces (mod p).

    for (size_t j = 0; j < iterations; j += 1) {
        ccn_mul_ws(ws, n, t, r, cczp_r2(zp));
        cczp_mm_redc_ws(ws, zp, r, t);
    }

    // Invariant.
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);

    CC_FREE_BP_WS(ws, bp);
}

int cczp_modn(cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MODN_WORKSPACE_N(cczp_n(zp)));
    cczp_modn_ws(ws, zp, r, ns, s);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}

void cczp_mod_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s2n)
{
    cczp_modn_ws(ws, zp, r, cczp_n(zp) * 2, s2n);
}

CC_WORKSPACE_OVERRIDE(cczp_mod_ws, cczp_mod_default_ws)

void cczp_mod_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CCZP_FUNCS_GET(zp, cczp_mod)(ws, zp, r, x);
}

int cczp_mod(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MOD_WORKSPACE_N(cczp_n(zp)));
    CC_DECL_BP_WS(ws, bp);
    cczp_mod_ws(ws, zp, r, x);
    CC_FREE_BP_WS(ws,bp);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
