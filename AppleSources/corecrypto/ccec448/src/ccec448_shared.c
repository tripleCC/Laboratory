/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccec_internal.h"
#include "ccec448_internal.h"

#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED

// (hi,lo) += (hi2,lo2) << 1
// r := lo and (hi,lo) >>= 64
#define CC_STORE_LO2(r, hi, lo, hi2, lo2) \
    do {                                  \
        lo += lo2 << 1;                   \
        hi += hi2 << 1;                   \
        lo2 = 0;                          \
        hi2 = 0;                          \
        CC_STORE_LO(r, hi, lo)            \
    } while (0);

/*! @function ccec448_redc_one
 @abstract Computes r := (c, x) (mod 2^448 - 2^224 - 1),
           where x is a 448-bit number (7 limbs) and c < 2^16.

 @discussion Ensures that r < 2^448. Might not be fully reduced.

 @param r   Reduced number.
 @param x   448-bit number to reduce.
 @param c   16-bit carry.
 */
CC_NONNULL_ALL
static void ccec448_redc_one(cc_unit *r, const cc_unit *x, cc_unit c)
{
    cc_unit t[CCN448_N];
    cc_dunit tmp;

    // Reduce once.
    CC_DUNIT_ADD(t[0], x[0], c, tmp)
    CC_DUNIT_ADC(t[1], x[1], 0, tmp)
    CC_DUNIT_ADC(t[2], x[2], 0, tmp)
    CC_DUNIT_ADC(t[3], x[3], (c << 32), tmp)
    CC_DUNIT_ADC(r[4], x[4], 0, tmp)
    CC_DUNIT_ADC(r[5], x[5], 0, tmp)
    CC_DUNIT_ADC(r[6], x[6], 0, tmp)

    c = tmp >> CCN_UNIT_BITS;

    // Reduce twice.
    CC_DUNIT_ADD(r[0], t[0], c, tmp)
    CC_DUNIT_ADC(r[1], t[1], 0, tmp)
    CC_DUNIT_ADC(r[2], t[2], 0, tmp)
    CC_DUNIT_ADC(r[3], t[3], (c << 32), tmp)
}

/*! @function ccec448_redc_full
 @abstract Computes r := x (mod 2^448 - 2^224 - 1),
           where x is a 896-bit number (14 limbs).

 @discussion Ensures that r < 2^448. Might not be fully reduced.

 @param r   Reduced number.
 @param x   896-bit number to reduce.
 */
CC_NONNULL_ALL
static void ccec448_redc_full(cc_unit *r, const cc_unit *x)
{
    cc_unit t[CCN448_N];
    cc_dunit tmp;

    CC_DUNIT_ADD(t[0], x[0], x[7], tmp)
    CC_DUNIT_ADC(t[1], x[1], x[8], tmp)
    CC_DUNIT_ADC(t[2], x[2], x[9], tmp)
    CC_DUNIT_ADC(t[3], x[3], x[10], tmp)
    CC_DUNIT_ADC(t[4], x[4], x[11], tmp)
    CC_DUNIT_ADC(t[5], x[5], x[12], tmp)
    CC_DUNIT_ADC(t[6], x[6], x[13], tmp)

    cc_unit c = tmp >> CCN_UNIT_BITS;

    CC_DUNIT_ADD(t[3], t[3], (x[10] & CCN_UNIT_UPPER_HALF_MASK), tmp)
    CC_DUNIT_ADC(t[4], t[4], x[11], tmp)
    CC_DUNIT_ADC(t[5], t[5], x[12], tmp)
    CC_DUNIT_ADC(t[6], t[6], x[13], tmp)

    c += (tmp >> CCN_UNIT_BITS);

    CC_DUNIT_ADD(t[0], t[0], (x[11] << 32) | (x[10] >> 32), tmp)
    CC_DUNIT_ADC(t[1], t[1], (x[12] << 32) | (x[11] >> 32), tmp)
    CC_DUNIT_ADC(t[2], t[2], (x[13] << 32) | (x[12] >> 32), tmp)
    CC_DUNIT_ADC(t[3], t[3],  (x[7] << 32) | (x[13] >> 32), tmp)
    CC_DUNIT_ADC(t[4], t[4],  (x[8] << 32) |  (x[7] >> 32), tmp)
    CC_DUNIT_ADC(t[5], t[5],  (x[9] << 32) |  (x[8] >> 32), tmp)
    CC_DUNIT_ADC(t[6], t[6], (x[10] << 32) |  (x[9] >> 32), tmp)

    ccec448_redc_one(r, t, c + (tmp >> CCN_UNIT_BITS));
}

void ccec448_add_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit t[CCN448_N];
    cc_dunit tmp = 0;

    // Add x and y.
    CC_DUNIT_ADC(t[0], x[0], y[0], tmp)
    CC_DUNIT_ADC(t[1], x[1], y[1], tmp)
    CC_DUNIT_ADC(t[2], x[2], y[2], tmp)
    CC_DUNIT_ADC(t[3], x[3], y[3], tmp)
    CC_DUNIT_ADC(t[4], x[4], y[4], tmp)
    CC_DUNIT_ADC(t[5], x[5], y[5], tmp)
    CC_DUNIT_ADC(t[6], x[6], y[6], tmp)

    ccec448_redc_one(r, t, tmp >> CCN_UNIT_BITS);
}

void ccec448_sub_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit t[CCN448_N];
    cc_dunit tmp;

    // Subtract y from x.
    CC_DUNIT_SUB(t[0], x[0], y[0], tmp)
    CC_DUNIT_SBC(t[1], x[1], y[1], tmp)
    CC_DUNIT_SBC(t[2], x[2], y[2], tmp)
    CC_DUNIT_SBC(t[3], x[3], y[3], tmp)
    CC_DUNIT_SBC(t[4], x[4], y[4], tmp)
    CC_DUNIT_SBC(t[5], x[5], y[5], tmp)
    CC_DUNIT_SBC(t[6], x[6], y[6], tmp)

    cc_unit b = tmp >> (2 * CCN_UNIT_BITS - 1);

    // Reduce once.
    CC_DUNIT_SUB(t[0], t[0], b, tmp)
    CC_DUNIT_SBC(t[1], t[1], 0, tmp)
    CC_DUNIT_SBC(t[2], t[2], 0, tmp)
    CC_DUNIT_SBC(t[3], t[3], (b << 32), tmp)
    CC_DUNIT_SBC(r[4], t[4], 0, tmp)
    CC_DUNIT_SBC(r[5], t[5], 0, tmp)
    CC_DUNIT_SBC(r[6], t[6], 0, tmp)

    b = tmp >> (2 * CCN_UNIT_BITS - 1);

    // Reduce twice.
    CC_DUNIT_SUB(r[0], t[0], b, tmp)
    CC_DUNIT_SBC(r[1], t[1], 0, tmp)
    CC_DUNIT_SBC(r[2], t[2], 0, tmp)
    CC_DUNIT_SBC(r[3], t[3], (b << 32), tmp)
}

void ccec448_mul_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit h[2 * CCN448_N];
    cc_dunit hi = 0;
    cc_dunit lo = 0;
    cc_dunit tmp;

    CC_DUNIT_MUL(x[0], y[0], hi, lo, tmp)

    CC_STORE_LO(h[0], hi, lo)

    CC_DUNIT_MUL(x[1], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[1], hi, lo, tmp)

    CC_STORE_LO(h[1], hi, lo)

    CC_DUNIT_MUL(x[2], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[2], hi, lo, tmp)

    CC_STORE_LO(h[2], hi, lo)

    CC_DUNIT_MUL(x[3], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[2], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[2], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[3], hi, lo, tmp)

    CC_STORE_LO(h[3], hi, lo)

    CC_DUNIT_MUL(x[4], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[2], y[2], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[3], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[4], hi, lo, tmp)

    CC_STORE_LO(h[4], hi, lo)

    CC_DUNIT_MUL(x[5], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[4], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[2], hi, lo, tmp)
    CC_DUNIT_MUL(x[2], y[3], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[4], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[5], hi, lo, tmp)

    CC_STORE_LO(h[5], hi, lo)

    CC_DUNIT_MUL(x[6], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[5], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[4], y[2], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[3], hi, lo, tmp)
    CC_DUNIT_MUL(x[2], y[4], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[5], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[6], hi, lo, tmp)

    CC_STORE_LO(h[6], hi, lo)

    CC_DUNIT_MUL(x[6], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[5], y[2], hi, lo, tmp)
    CC_DUNIT_MUL(x[4], y[3], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[4], hi, lo, tmp)
    CC_DUNIT_MUL(x[2], y[5], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[6], hi, lo, tmp)

    CC_STORE_LO(h[7], hi, lo)

    CC_DUNIT_MUL(x[6], y[2], hi, lo, tmp)
    CC_DUNIT_MUL(x[5], y[3], hi, lo, tmp)
    CC_DUNIT_MUL(x[4], y[4], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[5], hi, lo, tmp)
    CC_DUNIT_MUL(x[2], y[6], hi, lo, tmp)

    CC_STORE_LO(h[8], hi, lo)

    CC_DUNIT_MUL(x[6], y[3], hi, lo, tmp)
    CC_DUNIT_MUL(x[5], y[4], hi, lo, tmp)
    CC_DUNIT_MUL(x[4], y[5], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[6], hi, lo, tmp)

    CC_STORE_LO(h[9], hi, lo)

    CC_DUNIT_MUL(x[6], y[4], hi, lo, tmp)
    CC_DUNIT_MUL(x[5], y[5], hi, lo, tmp)
    CC_DUNIT_MUL(x[4], y[6], hi, lo, tmp)

    CC_STORE_LO(h[10], hi, lo)

    CC_DUNIT_MUL(x[6], y[5], hi, lo, tmp)
    CC_DUNIT_MUL(x[5], y[6], hi, lo, tmp)

    CC_STORE_LO(h[11], hi, lo)

    CC_DUNIT_MUL(x[6], y[6], hi, lo, tmp)

    CC_STORE_LO(h[12], hi, lo)
    h[13] = lo & CCN_UNIT_MASK;

    ccec448_redc_full(r, h);
}

void ccec448_sqr_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_unit h[2 * CCN448_N];
    cc_dunit hi = 0;
    cc_dunit lo = 0;
    cc_dunit hi2 = 0;
    cc_dunit lo2 = 0;
    cc_dunit tmp;

    CC_DUNIT_MUL(x[0], x[0], hi, lo, tmp)

    CC_STORE_LO(h[0], hi, lo)

    CC_DUNIT_MUL(x[1], x[0], hi2, lo2, tmp)

    CC_STORE_LO2(h[1], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[2], x[0], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[1], x[1], hi, lo, tmp)

    CC_STORE_LO2(h[2], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[3], x[0], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[2], x[1], hi2, lo2, tmp)

    CC_STORE_LO2(h[3], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[4], x[0], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[3], x[1], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[2], x[2], hi, lo, tmp)

    CC_STORE_LO2(h[4], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[5], x[0], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[4], x[1], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[3], x[2], hi2, lo2, tmp)

    CC_STORE_LO2(h[5], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[6], x[0], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[5], x[1], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[4], x[2], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[3], x[3], hi, lo, tmp)

    CC_STORE_LO2(h[6], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[6], x[1], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[5], x[2], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[4], x[3], hi2, lo2, tmp)

    CC_STORE_LO2(h[7], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[6], x[2], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[5], x[3], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[4], x[4], hi, lo, tmp)

    CC_STORE_LO2(h[8], hi, lo, hi2, lo2)

    CC_DUNIT_MUL(x[6], x[3], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[5], x[4], hi2, lo2, tmp)

    lo += lo2 << 1;
    hi += hi2 << 1;

    CC_STORE_LO(h[9], hi, lo)

    CC_DUNIT_MULI(x[6], x[4], hi, lo, tmp, 2)
    CC_DUNIT_MUL(x[5], x[5], hi, lo, tmp)

    CC_STORE_LO(h[10], hi, lo)

    CC_DUNIT_MULI(x[6], x[5], hi, lo, tmp, 2)

    CC_STORE_LO(h[11], hi, lo)

    CC_DUNIT_MUL(x[6], x[6], hi, lo, tmp)

    CC_STORE_LO(h[12], hi, lo)
    h[13] = lo & CCN_UNIT_MASK;

    ccec448_redc_full(r, h);
}

#define cczp_sqr_times_ws(_ws_, _zp_, _r_, _x_, _n_) \
    cczp_sqr_ws(_ws_, _zp_, _r_, _x_);               \
    for (unsigned i = 1; i < _n_; i++) {             \
        cczp_sqr_ws(_ws_, _zp_, _r_, _r_);           \
    }

int ccec448_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_unit t0[CCN448_N];
    cc_unit t1[CCN448_N];
    cc_unit t2[CCN448_N];

    // t0 := x^3
    cczp_sqr_ws(ws, zp, t0, x);
    cczp_mul_ws(ws, zp, t0, t0, x);

    // t0 := x^7
    cczp_sqr_ws(ws, zp, t0, t0);
    cczp_mul_ws(ws, zp, t0, t0, x);

    // t1 := x^3f
    cczp_sqr_times_ws(ws, zp, t1, t0, 3);
    cczp_mul_ws(ws, zp, t1, t1, t0);

    // t0 := x^0xfff
    cczp_sqr_times_ws(ws, zp, t0, t1, 6);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t0 := x^0x1fff
    cczp_sqr_ws(ws, zp, t0, t0);
    cczp_mul_ws(ws, zp, t0, t0, x);

    // t1 := x^0x3ffffff
    cczp_sqr_times_ws(ws, zp, t1, t0, 13);
    cczp_mul_ws(ws, zp, t1, t1, t0);

    // t1 := x^0x7ffffff
    cczp_sqr_ws(ws, zp, t1, t1);
    cczp_mul_ws(ws, zp, t1, t1, x);

    // t0 := x^0x3fffffffffffff
    cczp_sqr_times_ws(ws, zp, t0, t1, 27);
    cczp_mul_ws(ws, zp, t0, t0, t1);

    // t0 := x^0x7fffffffffffff
    cczp_sqr_ws(ws, zp, t0, t0);
    cczp_mul_ws(ws, zp, t0, t0, x);

    // t1 := x^0x3fffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t1, t0, 55);
    cczp_mul_ws(ws, zp, t1, t1, t0);

    // t1 := x^0x7fffffffffffffffffffffffffff
    cczp_sqr_ws(ws, zp, t1, t1);
    cczp_mul_ws(ws, zp, t1, t1, x);

    // t2 := x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t2, t1, 111);
    cczp_mul_ws(ws, zp, t2, t2, t1);

    // t1 := x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_ws(ws, zp, t1, t2);
    cczp_mul_ws(ws, zp, t1, t1, x);

    // t1 := x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_sqr_times_ws(ws, zp, t1, t1, 223);
    cczp_mul_ws(ws, zp, t1, t1, t2);

    // r := x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffd
    cczp_sqr_times_ws(ws, zp, t1, t1, 2);
    cczp_mul_ws(ws, zp, r, t1, x);

    return CCERR_OK;
}

void ccec448_from_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    const cc_unit *p = cczp_prime(zp);

    cc_unit t[CCN448_N];
    cc_dunit tmp = 0;

    CC_DUNIT_SBC(t[0], x[0], p[0], tmp)
    CC_DUNIT_SBC(t[1], x[1], p[1], tmp)
    CC_DUNIT_SBC(t[2], x[2], p[2], tmp)
    CC_DUNIT_SBC(t[3], x[3], p[3], tmp)
    CC_DUNIT_SBC(t[4], x[4], p[4], tmp)
    CC_DUNIT_SBC(t[5], x[5], p[5], tmp)
    CC_DUNIT_SBC(t[6], x[6], p[6], tmp)

    ccn_mux(CCN448_N, tmp >> (2 * CCN_UNIT_BITS - 1), r, x, t);
}

#endif // (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED

#if CCN_MULMOD_448_ASM

cc_unit ccn_addmod_p448(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_addmod_p448");
cc_unit ccn_submod_p448(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_submod_p448");

void ccn_mulmod_p448(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_mulmod_p448");
void ccn_sqrmod_p448(cc_unit *r, const cc_unit *a) __asm__("_ccn_sqrmod_p448");

void ccec448_add_asm(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_addmod_p448(r, x, y);
}

void ccec448_sub_asm(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_submod_p448(r, x, y);
}

void ccec448_mul_asm(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_mulmod_p448(r, x, y);
}

void ccec448_sqr_asm(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    ccn_sqrmod_p448(r, x);
}

#endif // CCN_MULMOD_448_ASM
