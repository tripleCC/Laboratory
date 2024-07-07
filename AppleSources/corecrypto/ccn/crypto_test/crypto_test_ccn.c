/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include "crypto_test_ccn.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include "cc_unit_internal.h"
#include "ccn_internal.h"
#include "cc_memory.h"
#include <corecrypto/cc.h>
#include "cczp_internal.h"
#include "cc_workspaces.h"

static void test_ccn_sqr(void)
{
    ccnBuffer input = hexStringToCcn("FFFFFFFFffffffffFFFFFFFFffffffffFFFFFFFFffffffff");
    cc_size n = input->len;
    cc_unit square_result[n * 2];
    cc_unit mult_result[n * 2];

    CC_DECL_WORKSPACE_TEST(ws);
    ccn_sqr_ws(ws, n, square_result, input->units);
    ccn_mul_ws(ws, n, mult_result, input->units, input->units);
    CC_FREE_WORKSPACE(ws);

    ok_ccn_cmp(n, square_result, mult_result, "ccn_sqr_ws() failed");

    free(input);
}

#define CCN_READ_WRITE_TEST_N 3
#define CCN_READ_WRITE_TEST_BYTES ccn_sizeof_n(CCN_READ_WRITE_TEST_N)
static void test_ccn_write_test(size_t size)
{
    cc_assert(size<=CCN_READ_WRITE_TEST_BYTES);
    cc_unit t [CCN_READ_WRITE_TEST_N];
    uint8_t t_bytes[size+1+CCN_UNIT_SIZE];
    uint8_t expected_t_bytes[size+2+CCN_UNIT_SIZE];

    size_t MSByte_index = sizeof(expected_t_bytes)-size-1;
    size_t LSByte_index = sizeof(expected_t_bytes)-2;

    // Set a big integer with the given size
    ccn_clear(CCN_READ_WRITE_TEST_N,t);
    cc_clear(sizeof(expected_t_bytes),expected_t_bytes);
    if (size>0) {
        ccn_set_bit(t, 0, 1);
        ccn_set_bit(t, size*8-1, 1);
        expected_t_bytes[LSByte_index]=0x01;
        expected_t_bytes[MSByte_index]|=0x80;
    }
    if (size>1) {
        ccn_set_bit(t, 9, 1);
        expected_t_bytes[LSByte_index-1]|=0x02;
    }

    // Test ccn_write_uint, which supports truncation
    if(size>0) {
        ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes);
        ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size-1, "Size %zu: Truncated output",size);
    }
    ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size,t_bytes);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);

    ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Extra output",size);

    // Test ccn_write_uint_padded, which supports truncation and padding
    if(size>0) {
        is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes), 0, "Size %zu: return value",size);
        ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size-1, "Size %zu: Truncated output",size);
    }
    is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size,t_bytes), 0, "Size %zu: Truncated output",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);

    is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes), 1, "Size %zu: return value",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1], size+1, "Size %zu: Extra output",size);

    is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+CCN_UNIT_SIZE,t_bytes), CCN_UNIT_SIZE, "Size %zu: return value",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);

    is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+1+CCN_UNIT_SIZE,t_bytes), 1+CCN_UNIT_SIZE, "Size %zu: return value",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1-CCN_UNIT_SIZE], size+1, "Size %d: Extra output",size);

    // Test ccn_write_uint_padded_ct, which supports padding, but not truncation
    if(size>0) {
        is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes), CCERR_PARAMETER, "Size %zu: return value",size);
    }
    is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size,t_bytes), 0, "Size %zu: return value",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);

    is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes), 1, "Size %zu: return value",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1], size+1, "Size %zu: Extra output",size);

    is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+CCN_UNIT_SIZE,t_bytes), CCN_UNIT_SIZE, "Size %zu: return value",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);

    is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+1+CCN_UNIT_SIZE,t_bytes), 1+CCN_UNIT_SIZE, "Size %zu: return value",size);
    ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);
}

static void test_ccn_read_test(size_t size)
{
    cc_assert(size<=CCN_READ_WRITE_TEST_BYTES);
    cc_unit expected_t [CCN_READ_WRITE_TEST_N];
    cc_unit t [CCN_READ_WRITE_TEST_N];
    uint8_t t_bytes[CCN_READ_WRITE_TEST_BYTES];

    // Set a big integer with the given size
    size_t MSByte_index = sizeof(t_bytes)-size;
    size_t LSByte_index = sizeof(t_bytes)-1;
    ccn_clear(CCN_READ_WRITE_TEST_N,expected_t);
    cc_clear(sizeof(t_bytes),t_bytes);
    if (size>0) {
        ccn_set_bit(expected_t, 0, 1);
        ccn_set_bit(expected_t, size*8-1, 1);
        t_bytes[LSByte_index]=0x01;
        t_bytes[MSByte_index]|=0x80;
    }
    if (size>1) {
        ccn_set_bit(expected_t, 9, 1);
        t_bytes[LSByte_index-1]|=0x02;
    }

    is(ccn_read_uint(CCN_READ_WRITE_TEST_N,t,CCN_READ_WRITE_TEST_BYTES,t_bytes),0,"Size %zu: Return value",size);
    ok_ccn_cmp(CCN_READ_WRITE_TEST_N, t, expected_t, "Size %zu: Exact size",size);

    if (size>0) {
        is(ccn_read_uint(ccn_nof_size(size)-1,t,size,&t_bytes[MSByte_index]),CCERR_PARAMETER,"Size %zu: Overflow protection",size);
    }
}

#define num_of_tests_ccn_read_write 620 // Keep track of number of tests below so we can add to total testplan count
static void test_ccn_read_write(void)
{
    for (size_t i=0;i<=CCN_READ_WRITE_TEST_BYTES;i++) {
        test_ccn_read_test(i);
        test_ccn_write_test(i);
    }
}

static int test_ccn_div(cc_ws_t ws, size_t modulus_bits, size_t modulus_real_bits, size_t divisor_bits)
{
    if (modulus_real_bits > modulus_bits) {
        modulus_real_bits = modulus_bits;
    }

    // create divisor
    cc_size nd = ccn_nof(modulus_bits);
    cc_unit d[nd];
    cc_unit r[nd];
    ccn_zero(nd, d);
    ccn_random_bits(modulus_real_bits, d, global_test_rng);

    // Skip division by zero.
    if (ccn_is_zero(nd, d)) {
        return 0;
    }

    // create random dividend
    cc_size na = CC_MAX(nd, ccn_nof(divisor_bits));
    cc_unit a[na];
    ccn_zero(na, a);
    cc_unit q[na];
    ccn_random_bits(divisor_bits, a, global_test_rng);

    ccn_divmod_ws(ws, na, a, na, q, nd, r, d);

    cc_unit dd[na], m[na * 2];
    ccn_setn(na, dd, nd, d);
    ccn_mul(na, m, q, dd);
    (void)ccn_addn(na, m, m, nd, r);

    return ccn_cmp(na, m, a);
}

static void test_ccn_addn(void)
{
    ccnBuffer s = hexStringToCcn("FFFFFFFFffffffffFFFFFFFFffffffffFFFFFFFFffffffff");
    ccnBuffer t = hexStringToCcn("00000000000000000000000000000001");
    cc_size n = s->len;
    cc_unit r[n];

    cc_unit cr = ccn_add(t->len, r, s->units, t->units);
    ok(cr == 1, "ccn_add carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");

    cr = ccn_addn(n, r, s->units, t->len, t->units);
    ok(cr == 1, "ccn_addn KAT");
    ok(ccn_is_zero(n, r), "ccn_addn KAT");

    cr = ccn_addn(t->len, r, s->units, t->len, t->units);
    ok(cr == 1, "ccn_addn carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");

    cr = ccn_add1(0, r, r, 7);
    ok(cr == 7, "ccn_add1 carry KAT");

    cr = ccn_addn(n, r, s->units, n, s->units);
    ok(cr == 1, "ccn_addn carry KAT");

    free(s);
    free(t);
}

const struct rshift_test_vector {
    const char *r;
    const char *x;
    const char *k;
} rshift_test_vectors[] = {
#include "../test_vectors/shift_right.kat"
};

const size_t rshift_test_vectors_num = CC_ARRAY_LEN(rshift_test_vectors);

static int test_ccn_shift_right(void)
{
    for (unsigned i = 0; i < rshift_test_vectors_num; i++) {
        const struct rshift_test_vector *test = &rshift_test_vectors[i];

        ccnBuffer r = hexStringToCcn(test->r);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer k = hexStringToCcn(test->k);

        cc_size n = x->len;
        cc_unit r2[n];

        ccn_shift_right_multi(n, r2, x->units, (size_t)k->units[0]);
        ok_ccn_cmp(r->len, r->units, r2, "r = x >> %llu", k->units[0]);

        if (k->units[0] < CCN_UNIT_BITS) {
            ccn_cond_shift_right(n, 1, r2, x->units, (size_t)k->units[0]);
            ok_ccn_cmp(r->len, r->units, r2, "r = x >> %llu", k->units[0]);
        } else {
            ok(true, "easier to calculate the test count that way");
        }

        free(r);
        free(x);
        free(k);
    }

    return 0;
}

const struct lshift_test_vector {
    const char *r;
    const char *x;
    const char *k;
} lshift_test_vectors[] = {
#include "../test_vectors/shift_left.kat"
};

const size_t lshift_test_vectors_num = CC_ARRAY_LEN(lshift_test_vectors);

static int test_ccn_shift_left(void)
{
    for (unsigned i = 0; i < lshift_test_vectors_num; i++) {
        const struct lshift_test_vector *test = &lshift_test_vectors[i];

        ccnBuffer r = hexStringToCcn(test->r);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer k = hexStringToCcn(test->k);

        cc_size n = r->len;
        cc_unit r2[n], x2[n];
        ccn_setn(n, x2, x->len, x->units);

        ccn_shift_left_multi(n, r2, x2, (size_t)k->units[0]);
        ok_ccn_cmp(n, r->units, r2, "r = x << %llu", k->units[0]);

        free(r);
        free(x);
        free(k);
    }

    return 0;
}

static void test_ccn_sub1(void)
{
    cc_size n = 1;
    cc_unit r[n];
    cc_unit s[n];

    ccnBuffer t1 = hexStringToCcn("00000000000000000000000000000001");
    ccnBuffer t2 = hexStringToCcn("ffffffffffffffffffffffffffffffff");
    ccnBuffer t3 = hexStringToCcn("00000001000000000000000000000001");

    cc_unit borrow = ccn_sub1(0, r, s, 7);
    is(borrow, (cc_unit)7, "ccn_sub1 with zero length scalar failed");

    borrow = ccn_sub1(t1->len, t1->units, t1->units, 1);
    is(borrow, 0, "ccn_sub1 shouldn't borrow");
    ok(ccn_is_zero(t1->len, t1->units), "t1 should be 0");

    borrow = ccn_sub1(t1->len, t1->units, t1->units, 1);
    is(borrow, 1, "ccn_sub1 should borrow");
    ok_ccn_cmp(t1->len, t1->units, t2->units, "t1 should be -1");

    borrow = ccn_sub1(t2->len, t2->units, t2->units, ~CC_UNIT_C(0));
    is(borrow, 0, "ccn_sub1 shouldn't borrow");

    borrow = ccn_sub1(t3->len, t3->units, t3->units, 1);
    is(borrow, 0, "ccn_sub1 shouldn't borrow");
    ok(!ccn_is_zero(t3->len, t3->units), "t3 shouldn't be 0");

    borrow = ccn_subn(t3->len, t3->units, t3->units, t2->len, t2->units);
    is(borrow, 1, "ccn_subn should borrow");

    free(t1);
    free(t2);
    free(t3);
}

static void test_ccn_cmp_zerolen(void)
{
    cc_size n = 0;
    cc_unit r[1];
    cc_unit s[1];

    is(ccn_cmp(n, r, s), 0, "ccn_cmp with size zero should return zero");
}

static void test_ccn_bitlen(void)
{
    cc_unit z[5] = {0, 0, 0, 0, 0};
    is(ccn_bitlen(5, z), 0, "ccn_bitlen() returned wrong result");
    is(ccn_bitlen(0, z), 0, "ccn_bitlen() returned wrong result");

    cc_unit a[5] = {0, 0, 1, 0, 0};
    is(ccn_bitlen(5, a), 2 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit b[5] = {1, 0, 1, 0, 0};
    is(ccn_bitlen(5, b), 2 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit c[5] = {1, 0, 1, 0, 1};
    is(ccn_bitlen(5, c), 4 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit d[5] = {1, 0, 0, 0, 0};
    is(ccn_bitlen(5, d), 1, "ccn_bitlen() returned wrong result");
}

static void test_ccn_abs(void)
{
    cc_unit a[1] = {5};
    cc_unit b[1] = {4};
    cc_unit r[1];

    is(ccn_abs(1, r, a, b), 0, "ccn_abs() returned wrong result");
    ok(ccn_is_one(1, r), "ccn_abs() computed wrong result");

    is(ccn_abs(1, r, a, a), 0, "ccn_abs() returned wrong result");
    ok(ccn_is_zero(1, r), "ccn_abs() computed wrong result");

    is(ccn_abs(1, r, b, a), 1, "ccn_abs() returned wrong result");
    ok(ccn_is_one(1, r), "ccn_abs() computed wrong result");
}

static void test_ccn_cmpn(void)
{
    cc_unit a[4] = { 1, 2, 0, 0 };
    cc_unit b[4] = { 1, 2, 0, 3 };

    // ns == nt
    is(ccn_cmpn(0, a, 0, b), 0, "{} == {}");
    is(ccn_cmpn(1, a, 1, b), 0, "{1} == {1}");
    is(ccn_cmpn(2, a, 2, b), 0, "{1,2} == {1,2}");
    is(ccn_cmpn(3, a, 3, b), 0, "{1,2,0} == {1,2,0}");
    is(ccn_cmpn(4, a, 4, b), -1, "{1,2,0,0} < {1,2,0,3}");
    is(ccn_cmpn(4, b, 4, a), 1, "{1,2,0,3} > {1,2,0,0}");

    // ns > nt
    is(ccn_cmpn(4, a, 3, b), 0, "{1,2,0,0} == {1,2,0}");
    is(ccn_cmpn(4, a, 2, b), 0, "{1,2,0,0} == {1,2}");
    is(ccn_cmpn(3, a, 2, b), 0, "{1,2,0} == {1,2}");
    is(ccn_cmpn(4, a, 1, b), 1, "{1,2,0,0} > {1}");
    is(ccn_cmpn(3, a, 1, b), 1, "{1,2,0} > {1}");
    is(ccn_cmpn(2, a, 1, b), 1, "{1,2} > {1}");
    is(ccn_cmpn(1, a, 0, b), 1, "{1} > {}");

    // ns < nt
    is(ccn_cmpn(3, b, 4, a), 0, "{1,2,0} == {1,2,0,0}");
    is(ccn_cmpn(2, b, 4, a), 0, "{1,2} == {1,2,0,0}");
    is(ccn_cmpn(2, b, 3, a), 0, "{1,2} == {1,2,0}");
    is(ccn_cmpn(1, b, 4, a), -1, "{1} < {1,2,0,0}");
    is(ccn_cmpn(1, b, 3, a), -1, "{1} < {1,2,0}");
    is(ccn_cmpn(1, b, 2, a), -1, "{1} < {1,2}");
    is(ccn_cmpn(0, b, 1, a), -1, "{} < {1}");
}

const struct gcd_test_vector {
    const char *gcd;
    const char *a;
    const char *b;
    const char *lcm;
} gcd_test_vectors[] = {
#include "../test_vectors/gcd_lcm.kat"
};

const size_t gcd_test_vectors_num = CC_ARRAY_LEN(gcd_test_vectors);

static int test_ccn_gcd(void)
{
    for (unsigned i = 0; i < gcd_test_vectors_num; i++) {
        const struct gcd_test_vector *test = &gcd_test_vectors[i];

        ccnBuffer gcd = hexStringToCcn(test->gcd);
        ccnBuffer a = hexStringToCcn(test->a);
        ccnBuffer b = hexStringToCcn(test->b);
        ccnBuffer lcm = hexStringToCcn(test->lcm);

        cc_size n = CC_MAX(a->len, b->len);
        cc_unit r[2 * n], an[n], bn[n];

        CC_DECL_WORKSPACE_TEST(ws);

        size_t k = ccn_gcd_ws(ws, n, r, a->len, a->units, b->len, b->units);
        ccn_shift_left_multi(n, r, r, k);
        ok_ccn_cmp(gcd->len, gcd->units, r, "r = gcd(a, b)");

        if (ccn_is_zero(n, r)) {
            ok(true, "hard to predict the test count otherwise");
        } else {
            ccn_setn(n, an, a->len, a->units);
            ccn_setn(n, bn, b->len, b->units);

            ccn_lcm_ws(ws, n, r, an, bn);
            ok_ccn_cmp(lcm->len, lcm->units, r, "r = lcm(a, b)");
        }

        CC_FREE_WORKSPACE(ws);

        free(gcd);
        free(a);
        free(b);
        free(lcm);
    }

    return 0;
}

static int test_ccn_div_exact(void)
{
    cc_size n = ccn_nof(256);
    cc_unit a[n * 2], b[n * 2], c[n * 2], r[n * 2];
    ccn_clear(n * 2, a);
    ccn_clear(n * 2, b);

    CC_DECL_WORKSPACE_TEST(ws);

    for (size_t i = 0; i < 2000; i++) {
        ccn_random(n, a, global_test_rng);
        ccn_random(n, b, global_test_rng);
        ccn_mul(n, c, a, b);

        ccn_div_exact_ws(ws, n * 2, r, c, b);
        is(ccn_cmpn(n, a, n * 2, r), 0, "(a * b) / b == a");
    }

    // x / x == 1
    ccn_div_exact_ws(ws, n, a, a, a);
    ok(ccn_is_one(n * 2, a), "x / x == 1");

    // x / 1 == x
    ccn_div_exact_ws(ws, n, a, b, a);
    ok_ccn_cmp(n, a, b, "x / 1 == x");

    CC_FREE_WORKSPACE(ws);
    return 0;
}

static int test_ccn_div_2n(void)
{
    cc_size n = 2;
    cc_unit q[n], r[n], a[n], d[n];

    ccn_seti(n, a, 0x51);
    ccn_seti(n, d, 0x10);

    CC_DECL_WORKSPACE_TEST(ws);
    ccn_divmod_ws(ws, n, a, n, q, n, r, d);
    CC_FREE_WORKSPACE(ws);

    is(ccn_n(n, q), 1, "wrong quotient");
    is(q[0], 0x05, "wrong quotient");
    is(ccn_n(n, r), 1, "wrong remainder");
    is(r[0], 0x01, "wrong remainder");

    return 0;
}

const struct invmod_test_vector {
    const char *inv;
    const char *x;
    const char *m;
    int rv;
} invmod_test_vectors[] = {
#include "../test_vectors/invmod.kat"
};

const size_t invmod_test_vectors_num = CC_ARRAY_LEN(invmod_test_vectors);

static void test_ccn_invmod(void)
{
    for (unsigned i = 0; i < invmod_test_vectors_num; i++) {
        const struct invmod_test_vector *test = &invmod_test_vectors[i];

        ccnBuffer inv = hexStringToCcn(test->inv);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer m = hexStringToCcn(test->m);

        cc_size n = m->len;
        cc_unit r[n];

        CC_DECL_WORKSPACE_TEST(ws);

        int rv = ccn_invmod_ws(ws, n, r, x->len, x->units, m->units);
        is(rv, test->rv, "unexpected ccn_invmod_ws() result");
        ok_ccn_cmp(inv->len, inv->units, r, "r = ccn_invmod_ws(x, m)");

        // Test cczp_inv().
        if ((m->units[0] & 1) && ccn_cmpn(m->len, m->units, x->len, x->units) > 0) {
            cczp_decl_n(n, zp);
            CCZP_N(zp) = n;

            ccn_set(n, CCZP_PRIME(zp), m->units);
            is(cczp_init_ws(ws, zp), CCERR_OK, "cczp_init() failed");

            cc_unit xn[n];
            ccn_setn(n, xn, x->len, x->units);

            int rv = cczp_inv_ws(ws, zp, r, xn);
            is(rv, test->rv, "unexpected cczp_inv() result");
            ok_ccn_cmp(inv->len, inv->units, r, "r = cczp_inv(x, m)");
        } else {
            ok(true, "always increase test count");
            ok(true, "always increase test count");
            ok(true, "always increase test count");
        }

        CC_FREE_WORKSPACE(ws);

        free(inv);
        free(x);
        free(m);
    }
}

static void test_ccn_divmod(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // Check that d / d = 1.
    cc_unit a1[5] = { 0, 1, 2, 3, 4 };
    cc_unit d1[5] = { 0, 1, 2, 3, 4 };
    cc_unit q1[5], r1[5];

    ccn_divmod_ws(ws, 5, a1, 5, q1, 5, r1, d1);
    ok(ccn_is_one(5, q1), "quotient should be one");
    ok(ccn_is_zero(5, r1), "remainder should be zero");

    // Check a / d with a < d.
    cc_unit a2[5] = { 0, 1, 2, 3, 3 };
    cc_unit d2[5] = { 0, 1, 2, 3, 4 };
    cc_unit q2[5], r2[5];

    ccn_divmod_ws(ws, 5, a2, 5, q2, 5, r2, d2);
    ok(ccn_is_zero(5, q2), "quotient should be zero");
    ok_ccn_cmp(5, a2, r2, "remainder should be equal to a");

    // Check divisors with leading zeros.
    cc_unit a3[5] = { 0, 1, 2, 3, 4 };
    cc_unit d3[5] = { 0, 1, 2, 0, 0 };
    cc_unit q3[5], r3[5], m3[5 * 2];

    ccn_divmod_ws(ws, 5, a3, 5, q3, 5, r3, d3);
    ccn_mul(5, m3, q3, d3);
    (void)ccn_add_ws(ws, 5, m3, m3, r3);
    ok_ccn_cmp(5, a3, m3, "quotient and remainder are correct");
    is(ccn_cmp(5, r3, d3), -1, "r3 < d3");

    // Check divisors that don't need to be normalized.
    // Normalized means the MSB is set to 1.
    cc_unit a4[5] = { 0, 1, 2, 3, 4 };
    cc_unit d4[5] = { 0, 1, 2, CCN_UNIT_MASK, 0 };
    cc_unit q4[5], r4[5], m4[5 * 2];

    ccn_divmod_ws(ws, 5, a4, 5, q4, 5, r4, d4);
    ccn_mul(5, m4, q4, d4);
    (void)ccn_add_ws(ws, 5, m4, m4, r4);
    ok_ccn_cmp(5, a4, m4, "quotient and remainder are correct");
    is(ccn_cmp(5, r4, d4), -1, "r4 < d4");

    // Check a / d with a << d.
    cc_unit a5[5] = { 7, 0, 0, 0, 0 };
    cc_unit d5[5] = { 0, 1, 2, 3, 4 };
    cc_unit q5[5], r5[5];

    ccn_divmod_ws(ws, 5, a5, 5, q5, 5, r5, d5);
    ok(ccn_is_zero(5, q5), "quotient should be zero");
    ok_ccn_cmp(5, a5, r5, "remainder should be equal to a");

    // Check divisors with a Barrett approximation of CCN_UNIT_MASK.
    cc_unit a6[5] = { 0, 1, 2, 3, 4 };
    cc_unit d6[5] = { 0, 1, 2, CC_UNIT_C(1) << (CCN_UNIT_BITS - 1), 0 };
    cc_unit q6[5], r6[5], m6[5 * 2];

    ccn_divmod_ws(ws, 5, a6, 5, q6, 5, r6, d6);
    ccn_mul(5, m6, q6, d6);
    (void)ccn_add_ws(ws, 5, m6, m6, r6);
    ok_ccn_cmp(5, a6, m6, "quotient and remainder are correct");
    is(ccn_cmp(5, r6, d6), -1, "r6 < d6");

    // Check small quotient sizes.
    cc_unit q7;
    ccn_divmod_ws(ws, 5, a6, 1, &q7, 5, r6, d6);
    is(q7, q6[0], "first word of the quotient is correct");

    // Test a few small divisors.
    cc_unit a8[5] = { 0, 1, 2, 3, 4 };
    cc_unit d8[5] = { 0, 0, 0, 0, 0 };
    cc_unit q8[5], r8[2], m8[2 * 5];

    for (int i = 1; i <= 50; i += 1) {
        d8[0] = (cc_unit)i;
        ccn_divmod_ws(ws, 5, a8, 5, q8, 2, r8, d8);
        ccn_mul(5, m8, q8, d8);
        (void)ccn_addn(5, m8, m8, 2, r8);
        ok_ccn_cmp(5, a8, m8, "quotient and remainder are correct");
        is(ccn_cmpn(2, r8, 5, d8), -1, "r8 < d8");
    }

    // Check one as the divisor.
    cc_unit a9[5] = { 0, 1, 2, 3, 4 };
    cc_unit d9[5] = { 1, 0, 0, 0, 0 };
    cc_unit q9[5], r9[5], m9[5 * 2];

    ccn_divmod_ws(ws, 5, a9, 5, q9, 5, r9, d9);
    ccn_mul(5, m9, q9, d9);
    (void)ccn_add_ws(ws, 5, m9, m9, r9);
    ok_ccn_cmp(5, a9, m9, "quotient and remainder are correct");
    is(ccn_cmp(5, r9, d9), -1, "r9 < d9");

    CC_FREE_WORKSPACE(ws);
}

static void test_ccn_divmod_random(void)
{
    size_t modulus_bits = 653;
    size_t modulus_real_bits = 457;
    size_t divisor_bits = 1985;

    CC_DECL_WORKSPACE_TEST(ws);

    for (int i = 0; i < 25000; i++) {
        modulus_bits = cc_rand_unit() % 753 + 30;
        modulus_real_bits = modulus_bits / (cc_rand_unit() % 4 + 1) + cc_rand_unit() % 5;

        divisor_bits = modulus_bits * (cc_rand_unit() % 4 + 1) + cc_rand_unit() % 7;
        int rc = test_ccn_div(ws, modulus_bits, modulus_real_bits, divisor_bits);
        is(rc, 0, "test_ccn_div() division results doesn't verify");

        divisor_bits = modulus_bits / (cc_rand_unit() % 3 + 1) + cc_rand_unit() % 7;
        rc = test_ccn_div(ws, modulus_bits, modulus_real_bits, divisor_bits);
        is(rc, 0, "test_ccn_div() division results doesn't verify");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccn_muln(void) {
    CC_DECL_WORKSPACE_TEST(ws);

    // times 1
    {    
        ccnBuffer t1 = hexStringToCcn("1");
        ccnBuffer t2 = hexStringToCcn("ffffffffffffffffffffffffffffffff");
        ccnBuffer r = mallocCcnBuffer(ccn_sizeof_n(t1->len + t2->len));

        ccn_muln(t1->len, r->units, t1->units, t2->len, t2->units);
        ok(ccnAreEqual(r, t2), "ccn_muln s=1");

        ccn_muln(t2->len, r->units, t2->units, t1->len, t1->units);
        ok(ccnAreEqual(r, t2), "ccn_muln v=1");

        free(t1);
        free(t2);
        free(r);
    }
    // different-length multiplicands
    {
        ccnBuffer t1 = hexStringToCcn("aaaabbbbccccddddeeeeffff99998888");
        ccnBuffer t2 = hexStringToCcn("7777666655554444");
        ccnBuffer expected = hexStringToCcn("4fa4f6e5d0369752e5d4c3b269d02ea5e024753112346420");
        ccnBuffer r = mallocCcnBuffer(ccn_sizeof_n(t1->len + t2->len));

        ccn_muln(t1->len, r->units, t1->units, t2->len, t2->units);
        ok(ccnAreEqual(r, expected), "ccn_muln aaaabbbbccccddddeeeeffff99998888 * 7777666655554444");

        ccn_muln(t2->len, r->units, t2->units, t1->len, t1->units);
        ok(ccnAreEqual(r, expected), "ccn_muln 7777666655554444 * aaaabbbbccccddddeeeeffff99998888");

        free(t1);
        free(t2);
        free(expected);
        free(r);
    }
    // t1 == t2
    {
        ccnBuffer t1 = hexStringToCcn("aaaabbbbccccddddeeeeffff99998888");
        ccnBuffer expected = hexStringToCcn("71c733334b17fdb98f5c4443c16bf6e51234369ce26ad159f6e5d0370b60c840");
        ccnBuffer r = mallocCcnBuffer(ccn_sizeof_n(2 * t1->len));
        ccn_muln(t1->len, r->units, t1->units, t1->len, t1->units);
        ok(ccnAreEqual(r, expected), "ccn_muln aaaabbbbccccddddeeeeffff99998888 * aaaabbbbccccddddeeeeffff99998888");

        free(t1);
        free(expected);
        free(r);
    }
    

    CC_FREE_WORKSPACE(ws);
}

static void test_ccn_rshift_arith(void)
{
    // Make sure arithmetic right shift is in place
    for (int i = 0; i < 200; i++) {
        cc_unit v = cc_rand_unit();
        ok(cc_unit_msb(v) == (ccn_bit(&v, CCN_UNIT_BITS - 1) ? ~(cc_unit)0 : 0), "ccop_msb() produces incorrect result");
    }
}

int ccn_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int num_tests = 0;
    num_tests += 8;                            // ccn_addn
    num_tests += 9;                            // ccn_sub1
    num_tests += 1;                            // ccn_sqr
    num_tests += 6;                            // ccn_bitlen
    num_tests += 6;                            // ccn_abs
    num_tests += 20;                           // ccn_cmpn
    num_tests += 2002;                         // ccn_div_exact
    num_tests += 4;                            // ccn_div_2n
    num_tests += gcd_test_vectors_num * 2;     // ccn_gcd
    num_tests += invmod_test_vectors_num * 5;  // ccn_invmod
    num_tests += 15 + 2 * 50;                  // ccn_divmod
    num_tests += 25000 * 2;                    // ccn_divmod_random
    num_tests += 5;                            // ccn_muln
    num_tests += 1;                            // test_ccn_cmp_zerolen
    num_tests += num_of_tests_ccn_read_write;  // test_ccn_read_write
    num_tests += rshift_test_vectors_num * 2;  // ccn_shift_right
    num_tests += lshift_test_vectors_num;      // ccn_shift_left
    num_tests += 200;                          // test_ccn_rshift_arith
    plan_tests(num_tests);

    test_ccn_addn();
    test_ccn_sub1();
    test_ccn_sqr();
    test_ccn_bitlen();
    test_ccn_abs();
    test_ccn_cmpn();
    test_ccn_gcd();
    test_ccn_div_exact();
    test_ccn_div_2n();
    test_ccn_invmod();
    test_ccn_divmod();
    test_ccn_divmod_random();
    test_ccn_muln();

    test_ccn_cmp_zerolen();
    test_ccn_read_write();

    test_ccn_shift_right();
    test_ccn_shift_left();
    test_ccn_rshift_arith();

    return 0;
}
