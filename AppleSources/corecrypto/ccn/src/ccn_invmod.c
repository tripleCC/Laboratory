/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
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

int ccn_invmod_ws(cc_ws_t ws, cc_size n, cc_unit *r, cc_size xn, const cc_unit *x, const cc_unit *m)
{
    if (xn > n) {
        ccn_clear(n, r);
        return CCERR_PARAMETER;
    }

    // Inverse of zero doesn't exist.
    if (ccn_is_zero(xn, x)) {
        ccn_clear(n, r);
        return CCERR_PARAMETER;
    }

    // m must be >= 2.
    if (ccn_is_zero_or_one(n, m)) {
        ccn_clear(n, r);
        return CCERR_PARAMETER;
    }

    // No inverse when both are even.
    if (((x[0] | m[0]) & 1) == 0) {
        ccn_clear(n, r);
        return CCERR_PARAMETER;
    }

    // Each step reduces at least one of u,v by at least a factor of two.
    // Worst case, we need at most the combined bit width of u,v for at
    // least one of them to be zero.
    size_t iterations = ccn_bitsof_n(xn + n);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *v = CC_ALLOC_WS(ws, n);

    ccn_setn(n, u, xn, x);
    ccn_set(n, v, m);

    cc_unit *a = CC_ALLOC_WS(ws, n);
    cc_unit *b = CC_ALLOC_WS(ws, n);
    cc_unit *c = CC_ALLOC_WS(ws, n);
    cc_unit *d = CC_ALLOC_WS(ws, n);

    ccn_seti(n, a, 1);
    ccn_clear(n, b);
    ccn_clear(n, c);
    ccn_seti(n, d, 1);

    cc_unit *tmp1 = CC_ALLOC_WS(ws, n);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, n);

    // The invariants here are:
    //   u = A * x - B * m
    //   v = D * m - C * x

    for (size_t i = 0; i < iterations; i++) {
        uint8_t both_odd = u[0] & v[0] & 1;

        // Set v := v - u, if both are odd and v >= u.
        cc_unit v_lt_u = ccn_subn(n, tmp1, v, xn, u);
        ccn_mux(n, both_odd & (v_lt_u ^ 1), v, tmp1, v);

        // Set u := u - v, if both are odd and v < u.
        ccn_sub_ws(ws, xn, tmp1, u, v);
        ccn_mux(xn, both_odd & v_lt_u, u, tmp1, u);

        // A := A + C or C := A + C
        cc_unit carry = ccn_add_ws(ws, n, tmp1, a, c);
        cc_unit borrow = ccn_sub_ws(ws, n, tmp2, tmp1, m);
        ccn_mux(n, borrow & (carry ^ 1), tmp1, tmp1, tmp2);
        ccn_mux(n, both_odd & v_lt_u, a, tmp1, a);
        ccn_mux(n, both_odd & (v_lt_u ^ 1), c, tmp1, c);

        // B := B + D or D := B + D
        ccn_add_ws(ws, xn, tmp1, b, d);
        ccn_sub_ws(ws, xn, tmp2, tmp1, x);
        ccn_mux(xn, borrow & (carry ^ 1), tmp1, tmp1, tmp2);
        ccn_mux(xn, both_odd & v_lt_u, b, tmp1, b);
        ccn_mux(xn, both_odd & (v_lt_u ^ 1), d, tmp1, d);

        // Exactly one of u,v is now even.
        cc_assert((u[0] ^ v[0]) & 1);

        cc_unit u_even = (u[0] & 1) ^ 1;
        cc_unit v_even = (v[0] & 1) ^ 1;

        cc_unit ab_odd = (a[0] | b[0]) & 1;
        cc_unit cd_odd = (c[0] | d[0]) & 1;

        // Halve u if even and adjust coefficients A and B.
        ccn_cond_shift_right(xn, u_even, u, u, 1);

        cc_unit ca = ccn_cond_add(n, u_even & ab_odd, a, a, m);
        ccn_cond_shift_right_carry(n, u_even, a, a, 1, ca);

        cc_unit cb = ccn_cond_add(xn, u_even & ab_odd, b, b, x);
        ccn_cond_shift_right_carry(xn, u_even, b, b, 1, cb);

        // Halve v if even and adjust coefficients C and D.
        ccn_cond_shift_right(n, v_even, v, v, 1);

        cc_unit cc = ccn_cond_add(n, v_even & cd_odd, c, c, m);
        ccn_cond_shift_right_carry(n, v_even, c, c, 1, cc);

        cc_unit cd = ccn_cond_add(xn, v_even & cd_odd, d, d, x);
        ccn_cond_shift_right_carry(xn, v_even, d, d, 1, cd);
    }

    // v should be zero now.
    cc_assert(ccn_is_zero(n, v));

    int rv;

    // gcd(x,m)=1 => we have an inverse.
    if (ccn_is_one(n, u)) {
        ccn_set(n, r, a);
        rv = CCERR_OK;
    } else {
        ccn_clear(n, r);
        rv = CCERR_PARAMETER;
    }

    CC_FREE_BP_WS(ws, bp);
    return rv;
}
