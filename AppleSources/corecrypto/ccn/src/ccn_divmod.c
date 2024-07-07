/* Copyright (c) (2012,2015,2021,2022) Apple Inc. All rights reserved.
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

#if CC_DUNIT_SUPPORTED

CC_INLINE cc_unit _is_lt(cc_unit x, cc_unit y)
{
    return ((cc_dunit)x - y) >> (CCN_UNIT_BITS * 2 - 1);
}

CC_INLINE cc_unit _mul_hi(cc_unit x, cc_unit y)
{
    return ((cc_dunit)x * y) >> CCN_UNIT_BITS;
}

static cc_unit _bquot(cc_unit d)
{
    // Divisor is normalized.
    cc_assert(d >> (CCN_UNIT_BITS - 1));

    // We replace 2^2w, which takes up three words, by 2^2w - d,
    // which takes only two words, by simply negating d mod 2^2w.
    // We'll add one back to the quotient later.
    cc_dunit y = -(cc_dunit)d;

    // Align d and y.
    cc_dunit dd = (cc_dunit)d << CCN_UNIT_BITS;
    cc_dunit q = 0;

    for (size_t i = 0; i <= CCN_UNIT_BITS; i++) {
        cc_dunit t = y - dd;
        // MSB is set if y < d.
        cc_dunit lt = t >> (CCN_UNIT_BITS * 2 - 1);
        // if (y >= d) y -= d
        CC_MUXU(y, lt, y, t);
        // q = (q << 1) |= (y >= d)
        q = (q << 1) | (1 ^ lt);

        dd >>= 1;
    }

    // Invariant.
    cc_assert((q >> CCN_UNIT_BITS) == 1);

    // Now, q = 2^w + x. We subtract 2^w by discarding the upper word.
    // q + 2 = ⌊(2^2w - d) / d⌋ + 2 = ⌊2^2w / d⌋ + 1 = ⌈2^2w / d⌉.

    // This assumes d > 2^(w-1) and d does not divide 2^2w, otherwise
    // the result will be discarded by compute_v().

    return (cc_unit)q + 2;
}

// Need double-word support to check division.
#define _dword(x1, x0) (((cc_dunit)x1 << CCN_UNIT_BITS) | x0)
#define _assert_dword_div(x) cc_assert(x)

#else

CC_INLINE cc_unit _is_lt(cc_unit x, cc_unit y)
{
    cc_unit r;
    return ccn_sub_ws(NULL, 1, &r, &x, &y);
}

CC_INLINE cc_unit _mul_hi(cc_unit x, cc_unit y)
{
    cc_unit tmp[2];
    ccn_mul(1, tmp, &x, &y);
    return tmp[1];
}

static cc_unit _bquot(cc_unit d)
{
    // Divisor is normalized.
    cc_assert(d >> (CCN_UNIT_BITS - 1));

    // We replace 2^2w, which takes up three words, by 2^2w - d,
    // which takes only two words, by simply negating d mod 2^2w.
    // We'll add one back to the quotient later.
    cc_unit y[2] = { -d, CCN_UNIT_MASK };

    // Align d and y.
    cc_unit dd[2] = { 0, d };
    cc_unit q[2] = { 0, 0 };
    cc_unit t[2];

    for (size_t i = 0; i <= CCN_UNIT_BITS; i++) {
        // if (y >= d) y -= d
        cc_unit lt = ccn_sub_ws(NULL, 2, t, y, dd);
        ccn_mux(2, lt, y, y, t);
        // q = (q << 1) |= (y >= d)
        ccn_shift_left(2, q, q, 1);
        ccn_set_bit(q, 0, 1 ^ lt);
        // d >>= 1
        ccn_shift_right(2, dd, dd, 1);
    }

    // Invariant.
    cc_assert(q[1] == 1);

    // Now, q = 2^w + x. We subtract 2^w by discarding the upper word.
    // q + 2 = ⌊(2^2w - d) / d⌋ + 2 = ⌊2^2w / d⌋ + 1 = ⌈2^2w / d⌉.

    // This assumes d > 2^(w-1) and d does not divide 2^2w, otherwise
    // the result will be discarded by compute_v().

    return q[0] + 2;
}

// No double-word support.
#define _dword(x1, x0)
#define _assert_dword_div(x)

#endif

// Computes the Barrett approximation to help with quotient selection.
// If d = 2^(w-1) it will return 2^w-1. Otherwise, ⌈2^2w / d⌉ - 2^w.
static cc_unit compute_v(cc_unit d)
{
    // The divisor is normalized, so 2^w > d >= 2^(w-1),
    // where d is the most significant word of the divisor.
    cc_assert(d >> (CCN_UNIT_BITS - 1));

    // if (d == 2^(w-1)) return 2^w-1
    cc_unit s;
    CC_HEAVISIDE_STEP(s, d ^ (CC_UNIT_C(1) << (CCN_UNIT_BITS - 1)));

    // Binary division to compute q := ⌈2^2w / d⌉ - 2^w.
    cc_unit q = _bquot(d);

    // Correctness check.
    _assert_dword_div(q == (cc_unit)((-(cc_dunit)d) / d) + 2);

    // 2^w-1 or ⌈2^2w / d⌉ - 2^w
    CC_MUXU(q, s, q, CCN_UNIT_MASK);
    return q;
}

// Selects a quotient q* that's never an underestimate of q, hence q* <= q + 2.
// At most two correction steps are required to recover the correct value of q.
static cc_unit select_quot(cc_unit a1, cc_unit a0, cc_unit d, cc_unit v)
{
    // add := (a0 < d) ? 1 : 2;
    cc_unit add = 2 - _is_lt(a0, d);

    // y1 := mul_hi(v, a1)
    cc_unit y1 = _mul_hi(v, a1);

    cc_unit q = y1 + a1 + add;

    // if (q < a1) q := 2^w-1
    cc_unit q_lt_a1 = _is_lt(q, a1);
    CC_MUXU(q, q_lt_a1, CCN_UNIT_MASK, q);

    // Without access to the carry flag this isn't worth writing
    // with uint128_t support, or cc_dunit generally.
    cc_unit y[2];
    ccn_mul(1, y, &q, &d);

    // Now, q* <= q + 2. We need two correction steps, at most.
    cc_unit a[2] = { a0, a1 };

    // if a - (q*) * d < 0, subtract 2.
    q -= ccn_sub_ws(NULL, 2, y, a, y) << 1;

    // if a - (q* - 1) * d < 0, add 1.
    q += ccn_add1_ws(NULL, 2, y, y, d);

    // Correctness check.
    _assert_dword_div(q == CC_MIN_EVAL(_dword(a1, a0) / d, CCN_UNIT_MASK));

    return q;
}

/**
 * This is an implementation of a naive, restoring division algorithm with
 * an optimized quotient selection step.
 *
 * Quotient selection requires computing 'a1a0 / d' in every loop iteration,
 * where 'a1a0' is the most significant double-word of the remainder and 'd'
 * is the most significant word of the divisor.
 *
 * We can't rely on variable-time division instructions, so instead we'll
 * use a modified Barrett division algorithm to compute the quotient. With
 * the Barrett approximation computed outside of the loop, the quotient
 * selection inside the loop can implemented very efficiently.
 *
 * The algorithm has been written such that it only requires scratch space
 * dependent on the size of the divisor (cc_size n). This adds practically
 * no overhead but simplifies workspace size computation.
 */
void ccn_divmod_ws(cc_ws_t ws, cc_size na, const cc_unit *a, cc_size nq, cc_unit *q, cc_size n, cc_unit *r, const cc_unit *d)
{
    cc_assert(nq <= na && n <= na);
    cc_assert(!ccn_is_zero(n, d));
    cc_size nr = n;

    // This reveals the unit length of the divisor but we assume the length
    // of the modulus to be known. This is necessary to pass existing tests.
    n = ccn_n(n, d);

    // Difference in length (units) between the dividend and divisor.
    // The inner loop below will run exactly 'm + 1' times.
    cc_size m = na - n;

    CC_DECL_BP_WS(ws, bp);

    cc_unit *td = CC_ALLOC_WS(ws, n + 1);
    cc_unit *ta = CC_ALLOC_WS(ws, n + 1);
    cc_unit *tt = CC_ALLOC_WS(ws, n + 1);
    td[n] = 0;

    // Divisor needs to be normalized.
    size_t s = cc_clz_nonzero(d[n - 1]);
    ccn_shift_left(n, td, d, s);

    // si := (s > 0) ? w-s : 0
    size_t si = -s & (CCN_UNIT_BITS - 1);

    // sm := (s > 0) ? 2^w-1 : 0
    cc_unit sm;
    CC_HEAVISIDE_STEP(sm, (cc_unit)s);
    sm = -sm;

    // Shift the dividend if the divisor was adjusted.
    ccn_setn(n + 1, ta, n, &a[m]);
    ccn_shift_left(n + 1, ta, ta, s);

    // Barrett approximation.
    cc_unit v = compute_v(td[n - 1]);

    for (cc_size i = m; i <= m; i -= 1) {
        // Set the shifted value for 'ta[0]'.
        // We do this every iteration so we don't have to allocate space for
        // 'na' units but instead require a scratch space of size 'nd + 1'.
        ta[0] = a[i] << s;
        if (i > 0) {
            ta[0] |= (a[i - 1] & sm) >> si;
        }

        // Select the quotient.
        cc_unit qi = select_quot(ta[n], ta[n - 1], td[n - 1], v);

        // a := a - q_i * d * (2^w)^i
        tt[n] = ccn_mul1(n, tt, td, qi);
        cc_unit b = ccn_sub_ws(ws, n + 1, ta, ta, tt);
        qi -= b;

        // Might need to add 'd' back once.
        b -= ccn_cond_add(n + 1, b, ta, ta, td);

        // Might need to add 'd' back twice.
        (void)ccn_cond_add(n + 1, b, ta, ta, td);

        // Update quotient.
        if (q && i < nq) {
            q[i] = qi - b;
        }

        // Invariant.
        cc_assert(ta[n] == 0);

        // For the next round, set 'a := a << w'. The least significant unit of
        // 'ta' will be filled with the shifted value at the top of the loop.
        if (i > 0) {
            cc_memmove(&ta[1], ta, ccn_sizeof_n(n));
        }
    }

    // Zero upper units of q, if needed.
    if (q && nq > m + 1) {
        ccn_clear(nq - (m + 1), &q[m + 1]);
    }

    if (r) {
        ccn_shift_right(n, ta, ta, s);
        ccn_setn(nr, r, n, ta);
    }

    CC_FREE_BP_WS(ws, bp);
}

int ccn_divmod(cc_size na, const cc_unit *a, cc_size nq, cc_unit *q, cc_size n, cc_unit *r, const cc_unit *d)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCN_DIVMOD_WORKSPACE_N(n));
    ccn_divmod_ws(ws, na, a, nq, q, n, r, d);
    CC_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
