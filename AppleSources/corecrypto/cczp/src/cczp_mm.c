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

#include "ccn_internal.h"
#include "cczp_internal.h"
#include "cc_workspaces.h"

/*! @function cczp_mm_mul_ws
 @abstract Multiplies two numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void cczp_mm_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    CC_DECL_BP_WS(ws, bp);
    cc_size n = cczp_n(zp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, n, rbig, x, y);
    cczp_mm_redc_ws(ws, zp, r, rbig);
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_sqr_ws
 @abstract Squares a number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void cczp_mm_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);
    cc_size n = cczp_n(zp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, n, rbig, x);
    cczp_mm_redc_ws(ws, zp, r, rbig);
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_mod_ws
 @abstract Reduces a number x modulo p.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to reduce
 */
CC_NONNULL_ALL
static void cczp_mm_mod_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size n = cczp_n(zp);
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);
    ccn_set(2 * n, t, x);

    cczp_mm_redc_ws(ws, zp, r, t);
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_inv_ws
 @abstract Computes r := 1 / x (mod p).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the inverstion
 @param x   Number to invert
 */
static int cczp_mm_inv_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, CC_UNUSED cc_unit *r, CC_UNUSED const cc_unit *x)
{
    // cczp_inv() maps to this function, which is used by EC code only.
    cc_try_abort("not implemented");
    return CCERR_INTERNAL;
}

/*! @function cczp_mm_sqrt_ws
 @abstract Computes r := x^(1/2) (mod p).

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Square root of x
 @param x   Quadratic residue
 */
static int cczp_mm_sqrt_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, CC_UNUSED cc_unit *r, CC_UNUSED const cc_unit *x)
{
    // cczp_sqrt() maps to this function, which is used by EC code only.
    cc_try_abort("not implemented");
    return CCERR_INTERNAL;
}

/*! @function cczp_mm_to_ws
 @abstract Computes r := x * R (mod p) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
static void cczp_mm_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, n, rbig, x, cczp_r2(zp));
    cczp_mm_redc_ws(ws, zp, r, rbig);
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function cczp_mm_from_ws
 @abstract Computes r := x / R (mod p) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
static void cczp_mm_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_setn(2 * n, rbig, n, x);
    cczp_mm_redc_ws(ws, zp, r, rbig);
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);
    CC_FREE_BP_WS(ws, bp);
}

CC_WORKSPACE_OVERRIDE(cczp_mul_ws, cczp_mm_mul_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqr_ws, cczp_mm_sqr_ws)
CC_WORKSPACE_OVERRIDE(cczp_mod_ws, cczp_mm_mod_ws)
CC_WORKSPACE_OVERRIDE(cczp_inv_ws, cczp_mm_inv_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqrt_ws, cczp_mm_sqrt_ws)
CC_WORKSPACE_OVERRIDE(cczp_to_ws, cczp_mm_to_ws)
CC_WORKSPACE_OVERRIDE(cczp_from_ws, cczp_mm_from_ws)

// Montgomery multiplication functions for cczp.
static const struct cczp_funcs cczp_montgomery_funcs = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = cczp_mm_mul_ws,
    .cczp_sqr = cczp_mm_sqr_ws,
    .cczp_mod = cczp_mm_mod_ws,
    .cczp_inv = cczp_mm_inv_ws,
    .cczp_sqrt = cczp_mm_sqrt_ws,
    .cczp_to = cczp_mm_to_ws,
    .cczp_from = cczp_mm_from_ws
};

int cczp_mm_init_ws(cc_ws_t ws, cczp_t zp, cc_size n, const cc_unit *p)
{
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);

    int rv = cczp_init_ws(ws, zp);
    CCZP_FUNCS(zp) = &cczp_montgomery_funcs;

    return rv;
}

void cczp_mm_init_copy(cczp_t dst, cczp_const_t src)
{
    cc_size n = cczp_n(src);
    cc_memcpy(dst, src, cczp_sizeof_n(n));
    CCZP_FUNCS(dst) = &cczp_montgomery_funcs;
}

int cczp_mm_power_fast_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *e)
{
    cc_assert(r != e);

    cc_size n = cczp_n(zp);

    // cczp_power_fast() requires x < p.
    if (ccn_cmp(n, x, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    CC_CLEAR_BP_WS(ws, bp);

    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(n));
    cczp_mm_init_copy(zpmm, zp);

    cczp_mm_to_ws(ws, zpmm, t0, x);

    int rv = cczp_power_fast_ws(ws, zpmm, t1, t0, e);
    cc_require(rv == CCERR_OK, out);

    cczp_mm_from_ws(ws, zpmm, r, t1);

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int cczp_mm_power_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, size_t ebitlen, const cc_unit *e)
{
    cc_assert(r != e);
    cc_size n = cczp_n(zp);

    // cczp_power() requires x < p.
    if (ccn_cmp(n, x, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(n));
    cczp_mm_init_copy(zpmm, zp);

    cczp_mm_to_ws(ws, zpmm, r, x);

    int rv = cczp_power_ws(ws, zpmm, r, r, ebitlen, e);
    cc_require(rv == CCERR_OK, out);

    cczp_mm_from_ws(ws, zpmm, r, r);

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
