/* Copyright (c) (2012,2015-2023) Apple Inc. All rights reserved.
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
#include "cc_workspaces.h"
#include "cc_unit_internal.h"

#define msb(_x_) ((cc_unit)(_x_) >> (CCN_UNIT_BITS - 1))
#define mask_msb (CC_UNIT_C(1) << (CCN_UNIT_BITS - 1))

#define mask_hi (CCN_UNIT_MASK << (CCN_UNIT_HALF_BITS - 1))
#define mask_lo (CCN_UNIT_LOWER_HALF_MASK >> 1)

#define CC_MAYBE_SWAP(_s_, _a_, _b_) {                  \
    cc_unit _t_ = ((-(_s_)) & _b_) | (~(-(_s_)) & _a_); \
    _b_ ^= _a_ ^ _t_;                                   \
    _a_ = _t_;                                          \
}

/*
 * Builds an approximation of u and v over the architecture's word size 2k.
 * For any given number we'll merge the most and the least significant k bits
 * into a 2k-bit variable (a register).
 *
 * If len(u) <= 2k and len(v) <= 2k, then we'll simply use u and v.
 *
 * Otherwise, set n = max(len(u), len(v)) and:
 *   ua = (u mod 2^(k-1)) + 2^(k-1) * ⌊u / 2^(n-k-1)⌋
 *   va = (v mod 2^(k-1)) + 2^(k-1) * ⌊v / 2^(n-k-1)⌋
 */
static void approximate(cc_size n, const cc_unit *u, cc_unit *ua, const cc_unit *v, cc_unit *va)
{
    *ua = u[n - 1];
    *va = v[n - 1];

    for (cc_size i = n - 2; i < n; i--) {
        // lzm = min(clz(ua), clz(va))
        size_t lzm = cc_clz_nonzero(*ua | *va | 1);

        cc_unit uv_nz; // (ua | va) ≠ 0?
        CC_HEAVISIDE_STEP(uv_nz, *ua | *va);

        // s = max(lzm, 1)
        size_t s = lzm + msb(*ua | *va);

        // s = uv_nz ? CCN_UNIT_BITS - s : 0
        s = (CCN_UNIT_BITS - s) & -(size_t)uv_nz;

        *ua = (*ua << lzm) | (u[i] >> s);
        *va = (*va << lzm) | (v[i] >> s);
    }

    *ua = (*ua & mask_hi) | (u[0] & mask_lo);
    *va = (*va & mask_hi) | (v[0] & mask_lo);
}

/*
 * Updates either u or v, using update factors f and g.
 *
 * This is called after every k-1 iterations of the main loop, where k is half
 * the architecture's word size.
 *
 * The update factors f and g allow computing the actual value of either u or
 * v after k-1 iterations with only approximations of u and v.
 *
 * Computes u * f + v * g.
 */
static cc_unit cczp_inv_update_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *u, cc_unit f, const cc_unit *v, cc_unit g)
{
    CC_DECL_BP_WS(ws, bp);

    cc_unit *t0 = CC_ALLOC_WS(ws, n + 1);
    cc_unit *t1 = CC_ALLOC_WS(ws, n + 1);

    // f,g < 0?
    cc_unit f_lt_z = msb(f);
    cc_unit g_lt_z = msb(g);

    // In two's complement multiplication, the multiplier has to be
    // non-negative. If f < 0, negate f and u.
    ccn_setn(n + 1, t0, n, u);
    ccn_cond_neg(n + 1, f_lt_z, t0, t0);
    f = (f ^ -f_lt_z) + f_lt_z;

    // If g < 0, negate g and v.
    ccn_setn(n + 1, t1, n, v);
    ccn_cond_neg(n + 1, g_lt_z, t1, t1);
    g = (g ^ -g_lt_z) + g_lt_z;

    // u = u * f + v * g
    (void)ccn_mul1(n + 1, t0, t0, f);
    (void)ccn_addmul1(n + 1, t0, t1, g);

    cc_unit is_neg = msb(t0[n]);

    // u = |u|
    ccn_cond_neg(n + 1, is_neg, t0, t0);
    cc_assert((t0[0] & mask_lo) == 0);

    // u = u >> CCN_UNIT_HALF_BITS-1
    ccn_shift_right(n + 1, t0, t0, CCN_UNIT_HALF_BITS - 1);
    cc_assert(t0[n] == 0);
    ccn_set(n, r, t0);

    CC_FREE_BP_WS(ws, bp);

    return is_neg;
}

/*
 * Updates either a or b, using update factors f and g.
 *
 * This is called after every k-1 iterations of the main loop, where k is half
 * the architecture's word size.
 *
 * The update factors f and g allow computing the actual value of either a or
 * b after k-1 iterations with only approximations of u and v.
 *
 * Computes a * f + b * g (mod p).
 */
static void cczp_inv_update_redc_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *a, cc_unit f, const cc_unit *b, cc_unit g)
{
    cc_size n = cczp_n(zp);
    CC_DECL_BP_WS(ws, bp);

    cc_unit *t0 = CC_ALLOC_WS(ws, n + 1);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);

    // f,g < 0?
    cc_unit f_lt_z = msb(f);
    cc_unit g_lt_z = msb(g);

    // In two's complement multiplication, the multiplier has to be
    // non-negative. If f < 0, negate f and a.
    cczp_cond_negate(zp, f_lt_z, t0, a);
    f = (f ^ -f_lt_z) + f_lt_z;

    // If g < 0, negate g and b.
    cczp_cond_negate(zp, g_lt_z, t1, b);
    g = (g ^ -g_lt_z) + g_lt_z;

    // u = u * f + v * g
    t0[n] = ccn_mul1(n, t0, t0, f);
    t0[n] += ccn_addmul1(n, t0, t1, g);

    // Montgomery REDC to divide by 2^(CCN_UNIT_HALF_BITS - 1).
    t0[n] += ccn_addmul1(n, t0, cczp_prime(zp), (t0[0] * cczp_p0inv(zp)) & mask_lo);
    ccn_shift_right(n + 1, t0, t0, CCN_UNIT_HALF_BITS - 1);
    ccn_set(n, r, t0);

    // Optional final reduction.
    cc_unit borrow = ccn_subn(n + 1, t0, t0, n, cczp_prime(zp));
    ccn_mux(n, borrow, r, r, t0);

    // Sanity check.
    cc_assert(ccn_cmp(n, r, cczp_prime(zp)) < 0);

    CC_FREE_BP_WS(ws, bp);
}

int cczp_inv_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = cczp_n(zp);
    size_t iterations = ccn_bitsof_n(2 * n);

    if (ccn_cmp(n, x, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    cczp_from_ws(ws, zp, u, x);
    ccn_set(n, v, cczp_prime(zp));

    cc_unit *a = CC_ALLOC_WS(ws, n);
    cc_unit *b = CC_ALLOC_WS(ws, n);

    ccn_seti(n, a, 1);
    ccn_clear(n, b);

    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    for (size_t i = 0; i < cc_ceiling(iterations, CCN_UNIT_HALF_BITS - 1); i++) {
        cc_unit ua, va;

        // Compute word-size approximations of u and v.
        approximate(n, u, &ua, v, &va);

#if CORECRYPTO_DEBUG
        {
            // abits = max(len(u), len(v), 2k)
            size_t abits = CC_MAX(ccn_bitlen(n, u), ccn_bitlen(n, v));
            abits = CC_MAX(abits, CCN_UNIT_BITS);

            // Check the approximation of u against the computed value.
            ccn_shift_right_multi(n, tmp, u, abits - CCN_UNIT_BITS);
            cc_assert(ua == ((tmp[0] & mask_hi) | (u[0] & mask_lo)));

            // Check the approximation of v against the computed value.
            ccn_shift_right_multi(n, tmp, v, abits - CCN_UNIT_BITS);
            cc_assert(va == ((tmp[0] & mask_hi) | (v[0] & mask_lo)));
        }
#endif

        // These are the update factors that we'll use to reconstruct the
        // correct values for u and v, after using only their approximations
        // in the inner loop. These factors basically keep track of the
        // operations that are usually performed on u and v directly.
        cc_unit f0 = CC_UNIT_C(1) << (CCN_UNIT_HALF_BITS - 1);
        cc_unit g1 = CC_UNIT_C(1) << (CCN_UNIT_HALF_BITS - 1);
        cc_unit f1 = 0, g0 = 0;

        for (size_t j = 0; j < CCN_UNIT_HALF_BITS - 1; j++) {
            // if u is even, u /= 2
            cc_unit u_even = (ua & 1) ^ 1;
            ua = ua >> u_even;

            cc_unit u_lt_v = cc_unit_lt(ua, va) & 1;

            // if u < v, (u,v,f0,g0,f1,g1) = (v,u,f1,g1,f0,g0)
            CC_MAYBE_SWAP(u_lt_v & (u_even ^ 1), ua, va);
            CC_MAYBE_SWAP(u_lt_v & (u_even ^ 1), f0, f1);
            CC_MAYBE_SWAP(u_lt_v & (u_even ^ 1), g0, g1);

            // u = u - v / 2
            ua -= va & -(u_even ^ 1);
            ua = ua >> (u_even ^ 1);

            // (f0, g0) = (f0 - f1, g0 - g1)
            f0 -= f1 & -(u_even ^ 1);
            g0 -= g1 & -(u_even ^ 1);

            // Arithmetic right shift of signed f0,g0.
            f0 = (f0 & mask_msb) | (f0 >> 1);
            g0 = (g0 & mask_msb) | (g0 >> 1);
        }

        // u = |f0 * u + g0 * v| >> CCN_UNIT_HALF_BITS-1
        cc_unit neg_a = cczp_inv_update_ws(ws, n, tmp, u, f0, v, g0);
        // v = |f1 * u + g1 * v| >> CCN_UNIT_HALF_BITS-1
        cc_unit neg_b = cczp_inv_update_ws(ws, n, v, u, f1, v, g1);

        ccn_set(n, u, tmp);

        // if a was < 0, (f0,g0) = (-f0,-g0)
        CC_MUXU(f0, neg_a, -f0, f0);
        CC_MUXU(g0, neg_a, -g0, g0);

        // if b was < 0, (f1,g1) = (-f1,-g1)
        CC_MUXU(f1, neg_b, -f1, f1);
        CC_MUXU(g1, neg_b, -g1, g1);

        // a = |f0 * a + g0 * b| >> CCN_UNIT_HALF_BITS-1 (mod p)
        cczp_inv_update_redc_ws(ws, zp, tmp, a, f0, b, g0);
        // b = |f1 * a + g1 * b| >> CCN_UNIT_HALF_BITS-1 (mod p)
        cczp_inv_update_redc_ws(ws, zp, b, a, f1, b, g1);

        ccn_set(n, a, tmp);
    }

    cc_assert(ccn_is_zero(n, u));

    int rv;

    if (ccn_is_one(n, v)) {
        rv = CCERR_OK;
        cczp_to_ws(ws, zp, r, b);
    } else {
        rv = CCERR_PARAMETER;
        ccn_clear(n, r);
    }

    CC_FREE_BP_WS(ws, bp);

    return rv;
}

CC_WORKSPACE_OVERRIDE(cczp_inv_ws, cczp_inv_default_ws)

int cczp_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    return CCZP_FUNCS_GET(zp, cczp_inv)(ws, zp, r, x);
}

int cczp_inv(cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_INV_WORKSPACE_N(cczp_n(zp)));
    int rv = cczp_inv_ws(ws, zp, r, x);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
