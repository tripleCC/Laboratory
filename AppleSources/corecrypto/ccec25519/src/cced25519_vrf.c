/* Copyright (c) (2019-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec25519.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng.h>
#include "cc_memory.h"
#include "cced25519_internal.h"

/*
 * ISC License
 *
 * Copyright (c) 2013-2019
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

int ge_frombytes_vartime(ge_p3 *h, const unsigned char *s)
{
    fe u;
    fe v;
    fe v3;
    fe vxx;
    fe check;

    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);
    fe_mul(v, u, d);
    fe_sub(u, u, h->Z); /* u = y^2-1 */
    fe_add(v, v, h->Z); /* v = dy^2+1 */

    fe_sq(v3, v);
    fe_mul(v3, v3, v); /* v3 = v^3 */
    fe_sq(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u); /* x = uv^7 */

    fe_pow22523(h->X, h->X); /* x = (uv^7)^((q-5)/8) */
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u); /* x = uv^3(uv^7)^((q-5)/8) */

    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u); /* vx^2-u */
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u); /* vx^2+u */
        if (fe_isnonzero(check)) {
            return -1;
        }
        fe_mul(h->X, h->X, sqrtm1);
    }

    if (fe_isnegative(h->X) != (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }

    fe_mul(h->T, h->X, h->Y);
    return 0;
}

static const fe curve25519_A = {
    486662, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void
chi25519(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    int     i;

    fe_sq(t0, z);
    fe_mul(t1, t0, z);
    fe_sq(t0, t1);
    fe_sq(t2, t0);
    fe_sq(t2, t2);
    fe_mul(t2, t2, t0);
    fe_mul(t1, t2, z);
    fe_sq(t2, t1);

    for (i = 1; i < 5; i++) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 10; i++) {
        fe_sq(t2, t2);
    }
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 20; i++) {
        fe_sq(t3, t3);
    }
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 10; i++) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 50; i++) {
        fe_sq(t2, t2);
    }
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 100; i++) {
        fe_sq(t3, t3);
    }
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 50; i++) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 4; i++) {
        fe_sq(t1, t1);
    }
    fe_mul(out, t1, t0);
}

void
ge_from_uniform(unsigned char s[32], const unsigned char r[32])
{
    fe       e;
    fe       negx;
    fe       rr2;
    fe       x, x2, x3;
    ge_p3    p3;
    ge_p1p1  p1;
    ge_p2    p2;
    unsigned int  e_is_minus_1;
    unsigned char x_sign;

    cc_memcpy(s, r, 32);
    x_sign = s[31] & 0x80;
    s[31] &= 0x7f;

    fe_frombytes(rr2, s);

    /* elligator */
    fe_sq2(rr2, rr2);
    rr2[0]++;
    fe_invert(rr2, rr2);
    fe_mul(x, curve25519_A, rr2);
    fe_neg(x, x);

    fe_sq(x2, x);
    fe_mul(x3, x, x2);
    fe_add(e, x3, x);
    fe_mul(x2, x2, curve25519_A);
    fe_add(e, x2, e);

    chi25519(e, e);

    fe_tobytes(s, e);
    e_is_minus_1 = s[1] & 1;
    fe_neg(negx, x);
    fe_cmov(x, negx, e_is_minus_1);
    fe_0(x2);
    fe_cmov(x2, curve25519_A, e_is_minus_1);
    fe_sub(x, x, x2);

    /* yed = (x-1)/(x+1) */
    {
        fe one;
        fe x_plus_one;
        fe x_plus_one_inv;
        fe x_minus_one;
        fe yed;

        fe_1(one);
        fe_add(x_plus_one, x, one);
        fe_sub(x_minus_one, x, one);
        fe_invert(x_plus_one_inv, x_plus_one);
        fe_mul(yed, x_minus_one, x_plus_one_inv);
        fe_tobytes(s, yed);
    }

    /* recover x */
    s[31] |= x_sign;
    if (ge_frombytes_vartime(&p3, s) != 0) {
        cc_assert(0);
    }

    /* multiply by the cofactor */
    ge_p3_dbl(&p1, &p3);
    ge_p1p1_to_p2(&p2, &p1);
    ge_p2_dbl(&p1, &p2);
    ge_p1p1_to_p2(&p2, &p1);
    ge_p2_dbl(&p1, &p2);
    ge_p1p1_to_p3(&p3, &p1);

    ge_p3_tobytes(s, &p3);
}

static void
ge_cached_0(ge_cached *h)
{
    fe_1(h->YplusX);
    fe_1(h->YminusX);
    fe_1(h->Z);
    fe_0(h->T2d);
}

static unsigned char
equal(unsigned char b, unsigned char c)
{
    unsigned char x  = b ^ c; /* 0: yes; 1..255: no */
    uint32_t      y  = x;     /* 0: yes; 1..255: no */

    y -= 1;   /* 4294967295: yes; 0..254: no */
    y >>= 31; /* 1: yes; 0: no */

    return (unsigned char)y;
}

static unsigned char
negative(signed char b)
{
    /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
    uint64_t x = (uint64_t)b;

    x >>= 63; /* 1: yes; 0: no */

    return (unsigned char)x;
}

static void ge_cmov_cached(ge_cached *t, const ge_cached *u, unsigned char b)
{
    fe_cmov(t->YplusX, u->YplusX, b);
    fe_cmov(t->YminusX, u->YminusX, b);
    fe_cmov(t->Z, u->Z, b);
    fe_cmov(t->T2d, u->T2d, b);
}

static void
ge_select_cached(ge_cached *t, const ge_cached cached[8], const signed char b)
{
    ge_cached minust;
    const unsigned char bnegative = negative(b);
    const unsigned char babs      = (unsigned char)(b - (((-bnegative) & b) * ((signed char) 1 << 1)));

    ge_cached_0(t);
    ge_cmov_cached(t, &cached[0], equal(babs, 1));
    ge_cmov_cached(t, &cached[1], equal(babs, 2));
    ge_cmov_cached(t, &cached[2], equal(babs, 3));
    ge_cmov_cached(t, &cached[3], equal(babs, 4));
    ge_cmov_cached(t, &cached[4], equal(babs, 5));
    ge_cmov_cached(t, &cached[5], equal(babs, 6));
    ge_cmov_cached(t, &cached[6], equal(babs, 7));
    ge_cmov_cached(t, &cached[7], equal(babs, 8));
    fe_copy(minust.YplusX, t->YminusX);
    fe_copy(minust.YminusX, t->YplusX);
    fe_copy(minust.Z, t->Z);
    fe_neg(minust.T2d, t->T2d);
    ge_cmov_cached(t, &minust, bnegative);
}

/*
 h = a * p
 where a = a[0]+256*a[1]+...+256^31 a[31]

 Preconditions:
 a[31] <= 127

 p is public
 */
void
ge_scalarmult(ge_p3 *h, const unsigned char *a, const ge_p3 *p)
{
    signed char     e[64];
    signed char     carry;
    ge_p1p1    r;
    ge_p2      s;
    ge_p1p1    t2, t3, t4, t5, t6, t7, t8;
    ge_p3      p2, p3, p4, p5, p6, p7, p8;
    ge_cached  pi[8];
    ge_cached  t;
    int             i;

    ge_p3_to_cached(&pi[1 - 1], p);   /* p */

    ge_p3_dbl(&t2, p);
    ge_p1p1_to_p3(&p2, &t2);
    ge_p3_to_cached(&pi[2 - 1], &p2); /* 2p = 2*p */

    ge_add(&t3, p, &pi[2 - 1]);
    ge_p1p1_to_p3(&p3, &t3);
    ge_p3_to_cached(&pi[3 - 1], &p3); /* 3p = 2p+p */

    ge_p3_dbl(&t4, &p2);
    ge_p1p1_to_p3(&p4, &t4);
    ge_p3_to_cached(&pi[4 - 1], &p4); /* 4p = 2*2p */

    ge_add(&t5, p, &pi[4 - 1]);
    ge_p1p1_to_p3(&p5, &t5);
    ge_p3_to_cached(&pi[5 - 1], &p5); /* 5p = 4p+p */

    ge_p3_dbl(&t6, &p3);
    ge_p1p1_to_p3(&p6, &t6);
    ge_p3_to_cached(&pi[6 - 1], &p6); /* 6p = 2*3p */

    ge_add(&t7, p, &pi[6 - 1]);
    ge_p1p1_to_p3(&p7, &t7);
    ge_p3_to_cached(&pi[7 - 1], &p7); /* 7p = 6p+p */

    ge_p3_dbl(&t8, &p4);
    ge_p1p1_to_p3(&p8, &t8);
    ge_p3_to_cached(&pi[8 - 1], &p8); /* 8p = 2*4p */

    for (i = 0; i < 32; ++i) {
        e[2 * i + 0] = (a[i] >> 0) & 15;
        e[2 * i + 1] = (a[i] >> 4) & 15;
    }
    /* each e[i] is between 0 and 15 */
    /* e[63] is between 0 and 7 */

    carry = 0;
    for (i = 0; i < 63; ++i) {
        e[i] += carry;
        carry = e[i] + 8;
        carry >>= 4;
        e[i] -= carry * ((signed char) 1 << 4);
    }
    e[63] += carry;
    /* each e[i] is between -8 and 8 */

    ge_p3_0(h);

    for (i = 63; i != 0; i--) {
        ge_select_cached(&t, pi, e[i]);
        ge_add(&r, h, &t);

        ge_p1p1_to_p2(&s, &r);
        ge_p2_dbl(&r, &s);
        ge_p1p1_to_p2(&s, &r);
        ge_p2_dbl(&r, &s);
        ge_p1p1_to_p2(&s, &r);
        ge_p2_dbl(&r, &s);
        ge_p1p1_to_p2(&s, &r);
        ge_p2_dbl(&r, &s);

        ge_p1p1_to_p3(h, &r);  /* *16 */
    }
    ge_select_cached(&t, pi, e[i]);
    ge_add(&r, h, &t);

    ge_p1p1_to_p3(h, &r);
}

void
ge_scalarmult_cofactor(ge_p3 *point) {
    ge_p1p1 p1;
    ge_p2 p2;

    ge_p3_dbl(&p1, point);
    ge_p1p1_to_p2(&p2, &p1);
    ge_p2_dbl(&p1, &p2);
    ge_p1p1_to_p2(&p2, &p1);
    ge_p2_dbl(&p1, &p2);
    ge_p1p1_to_p3(point, &p1);
}

int
ge_has_small_order(const unsigned char s[32])
{
    static const unsigned char small_order_blocklist[][32] = {
        /* 0 (order 4) */
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 1 (order 1) */
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 2707385501144840649318225287225658788936804267575313519463743609750303402022
         (order 8) */
        { 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
            0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
            0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05 },
        /* 55188659117513257062467267217118295137698188065244968500265048394206261417927
         (order 8) */
        { 0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
            0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
            0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a },
        /* p-1 (order 2) */
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p (=0, order 4) */
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p+1 (=1, order 1) */
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    unsigned char c[7] = { 0 };
    unsigned int  k;
    size_t        i, j;

    for (j = 0; j < 31; j++) {
        for (i = 0; i < CC_ARRAY_LEN(small_order_blocklist); i++) {
            c[i] |= s[j] ^ small_order_blocklist[i][j];
        }
    }
    for (i = 0; i < CC_ARRAY_LEN(small_order_blocklist); i++) {
        c[i] |= (s[j] & 0x7f) ^ small_order_blocklist[i][j];
    }
    k = 0;
    for (i = 0; i < CC_ARRAY_LEN(small_order_blocklist); i++) {
        k |= (c[i] - 1);
    }
    return (int) ((k >> 8) & 1);
}
