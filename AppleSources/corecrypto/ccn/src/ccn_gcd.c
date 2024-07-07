/* Copyright (c) (2010-2012,2015,2017-2022) Apple Inc. All rights reserved.
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
#include "cc_workspaces.h"
#include "cc_unit_internal.h"

#define msb(_x_) ((cc_unit)(_x_) >> (CCN_UNIT_BITS - 1))
#define mask_msb (CC_UNIT_C(1) << (CCN_UNIT_BITS - 1))

#define mask_hi (CCN_UNIT_MASK << (CCN_UNIT_HALF_BITS - 1))
#define mask_lo (CCN_UNIT_LOWER_HALF_MASK >> 1)

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
static void ccn_gcd_update_ws(cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *u, cc_unit f, const cc_unit *v, cc_unit g)
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

    // u = |u|
    ccn_cond_neg(n + 1, msb(t0[n]), t0, t0);
    cc_assert((t0[0] & mask_lo) == 0);

    // u = u >> CCN_UNIT_HALF_BITS-1
    ccn_shift_right(n + 1, t0, t0, CCN_UNIT_HALF_BITS - 1);
    cc_assert(t0[n] == 0);
    ccn_set(n, r, t0);

    CC_FREE_BP_WS(ws, bp);
}

size_t ccn_gcd_ws(cc_ws_t ws, cc_size rn, cc_unit *r, cc_size sn, const cc_unit *s, cc_size tn, const cc_unit *t)
{
    assert(rn >= sn && rn >= tn);

    // Each step reduces at least one of u,v by at least a factor of two.
    // Worst case, we need at most the combined bit width of u,v for at
    // least one of them to be zero.
    size_t iterations = ccn_bitsof_n(sn + tn);

    CC_DECL_BP_WS(ws, bp);

    cc_size n = rn;
    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    ccn_setn(rn, u, sn, s);
    ccn_setn(rn, v, tn, t);

    cc_size k = 0;

    for (size_t i = 0; i < cc_ceiling(iterations, CCN_UNIT_HALF_BITS - 1); i++) {
        cc_unit ua, va;

        // Compute word-size approximations of u and v.
        approximate(rn, u, &ua, v, &va);

#if CORECRYPTO_DEBUG
        {
            // abits = max(len(u), len(v), 2k)
            size_t abits = CC_MAX(ccn_bitlen(rn, u), ccn_bitlen(rn, v));
            abits = CC_MAX(abits, CCN_UNIT_BITS);

            // Check the approximation of u against the computed value.
            ccn_shift_right_multi(rn, tmp, u, abits - CCN_UNIT_BITS);
            cc_assert(ua == ((tmp[0] & mask_hi) | (u[0] & mask_lo)));

            // Check the approximation of v against the computed value.
            ccn_shift_right_multi(rn, tmp, v, abits - CCN_UNIT_BITS);
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
            cc_unit both_odd = ua & va & 1;
            cc_unit v_lt_u = cc_unit_lt(va, ua) & 1;
            cc_unit v_ge_u = v_lt_u ^ 1;

            // Set u := u - v, if both are odd and v < u.
            ua -= va & -(both_odd & v_lt_u);
            f0 -= f1 & -(both_odd & v_lt_u);
            g0 -= g1 & -(both_odd & v_lt_u);

            // Set v := v - u, if both are odd and v >= u.
            va -= ua & -(both_odd & v_ge_u);
            f1 -= f0 & -(both_odd & v_ge_u);
            g1 -= g0 & -(both_odd & v_ge_u);

            // At least one of u,v is now even.
            cc_assert((ua & va & 1) == 0);

            // With u,v both even, add a factor of two to the final result.
            k += 1 ^ ((ua | va) & 1);

            cc_unit u_even = (ua & 1) ^ 1;
            cc_unit v_even = (va & 1) ^ 1;

            // Halve u,f0,g0 if u is even.
            ua = ua >> u_even;
            // Arithmetic right shift of signed f0,g0.
            f0 = (f0 & mask_msb) | (f0 >> u_even);
            g0 = (g0 & mask_msb) | (g0 >> u_even);

            // Halve v,f1,g1 if v is even.
            va = va >> v_even;
            // Arithmetic right shift of signed f1,g1.
            f1 = (f1 & mask_msb) | (f1 >> v_even);
            g1 = (g1 & mask_msb) | (g1 >> v_even);
        }

        // u = |f0 * u + g0 * v| >> CCN_UNIT_HALF_BITS-1
        ccn_gcd_update_ws(ws, rn, tmp, u, f0, v, g0);
        // v = |f1 * u + g1 * v| >> CCN_UNIT_HALF_BITS-1
        ccn_gcd_update_ws(ws, rn, v, u, f1, v, g1);

        ccn_set(rn, u, tmp);
    }

    // One of u,v should be zero now.
    cc_assert(ccn_is_zero(rn, u) || ccn_is_zero(rn, v));

    for (size_t i = 0; i < rn; i++) {
        r[i] = u[i] | v[i];
    }

    CC_FREE_BP_WS(ws, bp);

    return k;
}
