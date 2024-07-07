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

/*! @function ccn_mul_lo
 @abstract Computes x * y (mod 2^wn).

 @param n   Length of r,x,y as a number of cc_units.
 @param r   The product r.
 @param x   The multiplier x.
 @param y   The multiplicand y.
 */
CC_NONNULL_ALL
static void ccn_mul_lo(cc_size n, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_assert(r != x && r != y);

    ccn_clear(n, r);

    for (cc_size i = 0; i < n; i++) {
        (void)ccn_addmul1(n - i, r + i, y, x[i]);
    }
}

CC_NONNULL_ALL
void ccn_div_exact_ws(cc_ws_t ws, cc_size n, cc_unit *q, const cc_unit *a, const cc_unit *d)
{
    cc_assert(!ccn_is_zero(n, d));

    CC_DECL_BP_WS(ws, bp);
    cc_unit *dd = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    // Shift d until gcd(d, 2^wn) = 1.
    size_t s = ccn_trailing_zeros(n, d);
    ccn_shift_right_multi(n, dd, d, s);
    cc_assert(dd[0] & 1);

    // Will hold c := 1/d (mod 2^wn).
    cc_unit *c = CC_ALLOC_WS(ws, n);
    ccn_clear(n, c);

    // Initial precision 'k' of 1/d is one unit.
    c[0] = ccn_invert(dd[0]);
    cc_size k = 1;

    // nr = ceil(log2(n)).
    cc_size nr = CCN_UNIT_BITS - cc_clz_nonzero((cc_unit)n);

    // Compute the inverse of d (mod 2^wn) to at least half-precision.
    // After the loop, c := 1/d (mod 2^(w*ceil(n/2))).
    //
    // Every iteration computes:
    //   c1 := umul_lo(−c0, umul_lo(d1, c0) + umul_hi(d0, c0))
    //
    // Where c0 is the known k-word value of 'c', d0 the lower and d1 the
    // higher k words of 'd' (where d is truncated to 2*k). The result c1
    // is the next k-word value of 'c' that together with the known
    // value c0 forms the new 2k-word c0 for the next round.
    for (cc_size i = nr - 1; i >= 1; i--) {
        ccn_mul_ws(ws, k, t, dd, c);
        ccn_mul_lo(k, t, dd + k, c);
        (void)ccn_add_ws(ws, k, t, t, t + k);
        ccn_neg(k, t + k, c);
        ccn_mul_lo(k, c + k, t + k, t);

        // k := ceil(n / 2^i)
        k = (n + (1 << i) - 1) >> i;
    }

    // 'k' is the final precision of 'c', where k >= n/2.
    ccn_clear(n, t);

    // q := a * c (mod 2^wk)
    ccn_mul_lo(k, t, a, c);

    // q := q + c * (a - d * q) (mod 2^wn)
    ccn_mul_lo(n, q, dd, t);
    (void)ccn_sub_ws(ws, n, dd, a, q);
    ccn_mul_lo(n, q, c, dd);
    (void)ccn_add_ws(ws, n, q, q, t);

    // Adjust result after the initial shift.
    ccn_shift_right_multi(n, q, q, s);

    CC_FREE_BP_WS(ws, bp);
}
