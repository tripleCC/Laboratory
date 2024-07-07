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
#include "ccec25519_internal.h"

void ccec25519_add_ws(cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit t[CCN256_N];
    cc_unit c = ccn_add_ws(ws, CCN256_N, t, x, y);
    c = ccn_add1_ws(ws, CCN256_N, r, t, 38 & -c);
    r[0] += 38 & -c;
}

void ccec25519_sub_ws(cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit t[CCN256_N];
    cc_unit b = ccn_sub_ws(ws, CCN256_N, t, x, y);
    b = ccn_sub1(CCN256_N, r, t, 38 & -b);
    r[0] -= 38 & -b;
}

/*! @function ccec25519_redc_ws
 @abstract Computes r := t (mod 2^256-38).

 @discussion Ensures that r < 2^256. Might not be fully reduced
             mod 2^256-38, but will always fit in 256 bits.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccec25519_redc_ws(cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    cc_unit c = ccn_addmul1(CCN256_N, t, &t[CCN256_N], 38);
    c = ccn_add1_ws(ws, CCN256_N, r, t, c * 38);
    r[0] += 38 & -c;
}

void ccec25519_mul_ws(cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit rbig[2 * CCN256_N];
    ccn_mul_ws(ws, CCN256_N, rbig, x, y);
    ccec25519_redc_ws(ws, zp, r, rbig);
}

void ccec25519_sqr_ws(cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_unit rbig[2 * CCN256_N];
    ccn_sqr_ws(ws, CCN256_N, rbig, x);
    ccec25519_redc_ws(ws, zp, r, rbig);
}

void ccec25519_mul121666_ws(cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_unit t[CCN256_N];
    cc_unit c = ccn_mul1(CCN256_N, t, x, 121666);
    c = ccn_add1_ws(ws, CCN256_N, r, t, 38 * c);
    r[0] += 38 & -c;
}

#define cczp_sqr_times_ws(_ws_, _zp_, _r_, _x_, _n_) \
    ccn_set(CCN256_N, _r_, _x_);                     \
    for (unsigned i = 0; i < _n_; i++) {             \
        cczp_sqr_ws(_ws_, _zp_, _r_, _r_);           \
    }

int ccec25519_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN256_N;
    CC_DECL_BP_WS(ws, bp);

    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    cc_unit *t2 = CC_ALLOC_WS(ws, n);

    // t1 := x^2
    cczp_sqr_ws(ws, zp, t1, x);

    // t0 := x^8
    cczp_sqr_times_ws(ws, zp, t0, t1, 2);

    // t2 := x^9
    cczp_mul_ws(ws, zp, t2, t0, x);

    // t1 := x^11
    cczp_mul_ws(ws, zp, t1, t2, t1);

    // t0 := x^22
    cczp_sqr_ws(ws, zp, t0, t1);

    // t2 := x^31
    cczp_mul_ws(ws, zp, t2, t0, t2);

    // t0 := x^0x3e0
    cczp_sqr_times_ws(ws, zp, t0, t2, 5);

    // t2 := x^0x3ff
    cczp_mul_ws(ws, zp, t2, t0, t2);

    // t0 := 0xffc00
    cczp_sqr_times_ws(ws, zp, t0, t2, 10);

    // c := x^0xfffff
    cczp_mul_ws(ws, zp, r, t0, t2);

    // t0 := x^0xfffff00000
    cczp_sqr_times_ws(ws, zp, t0, r, 20);

    // t0 := x^0xffffffffff
    cczp_mul_ws(ws, zp, t0, t0, r);

    // t0 := x^0x3fffffffffc00
    cczp_sqr_times_ws(ws, zp, t0, t0, 10);

    // t2 := x^0x3ffffffffffff
    cczp_mul_ws(ws, zp, t2, t0, t2);

    // t0 := x^0xffffffffffffc000000000000
    cczp_sqr_times_ws(ws, zp, t0, t2, 50);

    // c := x^0xfffffffffffffffffffffffff
    cczp_mul_ws(ws, zp, r, t0, t2);

    // t0 := x^0xfffffffffffffffffffffffff0000000000000000000000000
    cczp_sqr_times_ws(ws, zp, t0, r, 100);

    // t0 := x^0xffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_mul_ws(ws, zp, t0, t0, r);

    // t0 := x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffc000000000000
    cczp_sqr_times_ws(ws, zp, t0, t0, 50);

    // t0 := x^0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    cczp_mul_ws(ws, zp, t0, t0, t2);

    // t0 := x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0
    cczp_sqr_times_ws(ws, zp, t0, t0, 5);

    // r := x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    cczp_mul_ws(ws, zp, r, t0, t1);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

void ccec25519_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_unit t[CCN256_N];

    // Ensure t < 2*p.
    cc_unit c = ccn_bit(x, 255);
    c = ccn_add1_ws(ws, CCN256_N, r, x, 19 & -c);
    ccn_set_bit(r, 255, c);

    // Ensure r < p.
    cc_unit b = ccn_sub_ws(ws, CCN256_N, t, r, cczp_prime(zp));
    (void)ccn_sub1(CCN256_N, r, t, 19 & -b);
    ccn_set_bit(r, 255, 0);
}

CC_WORKSPACE_OVERRIDE(cczp_add_ws, ccec25519_add_ws)
CC_WORKSPACE_OVERRIDE(cczp_sub_ws, ccec25519_sub_ws)
CC_WORKSPACE_OVERRIDE(cczp_mul_ws, ccec25519_mul_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqr_ws, ccec25519_sqr_ws)
CC_WORKSPACE_OVERRIDE(cczp_inv_ws, ccec25519_inv_ws)
CC_WORKSPACE_OVERRIDE(cczp_from_ws, ccec25519_from_ws)

#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED

void ccec25519_add_opt_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit t[CCN256_N];
    cc_dunit tmp;

    // Add x and y.
    CC_DUNIT_ADD(t[0], x[0], y[0], tmp)
    CC_DUNIT_ADC(t[1], x[1], y[1], tmp)
    CC_DUNIT_ADC(t[2], x[2], y[2], tmp)
    CC_DUNIT_ADC(t[3], x[3], y[3], tmp)

    // Reduce once.
    CC_DUNIT_ADD(r[0], t[0], 38 & -(tmp >> CCN_UNIT_BITS), tmp)
    CC_DUNIT_ADC(r[1], t[1], 0, tmp)
    CC_DUNIT_ADC(r[2], t[2], 0, tmp)
    CC_DUNIT_ADC(r[3], t[3], 0, tmp)

    // Reduce twice.
    CC_DUNIT_ADD(r[0], r[0], 38 & -(tmp >> CCN_UNIT_BITS), tmp)
}

void ccec25519_sub_opt_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit t[CCN256_N];
    cc_dunit tmp;

    // Subtract y from x.
    CC_DUNIT_SUB(t[0], x[0], y[0], tmp)
    CC_DUNIT_SBC(t[1], x[1], y[1], tmp)
    CC_DUNIT_SBC(t[2], x[2], y[2], tmp)
    CC_DUNIT_SBC(t[3], x[3], y[3], tmp)

    // Reduce once.
    CC_DUNIT_SUB(r[0], t[0], 38 & -(tmp >> (2 * CCN_UNIT_BITS - 1)), tmp)
    CC_DUNIT_SBC(r[1], t[1], 0, tmp)
    CC_DUNIT_SBC(r[2], t[2], 0, tmp)
    CC_DUNIT_SBC(r[3], t[3], 0, tmp)

    // Reduce twice.
    CC_DUNIT_SUB(r[0], r[0], 38 & -(tmp >> (2 * CCN_UNIT_BITS - 1)), tmp)
}

void ccec25519_mul_opt_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_unit t[CCN256_N];
    cc_dunit hi = 0;
    cc_dunit lo = 0;
    cc_dunit hi2 = 0;
    cc_dunit lo2 = 0;
    cc_dunit tmp;

    CC_DUNIT_MUL(x[0], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[1], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[2], y[2], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[1], y[3], hi2, lo2, tmp)

    lo += lo2 * 38;
    hi += hi2 * 38;

    CC_STORE_LO(t[0], hi, lo)

    lo2 = 0;
    hi2 = 0;

    CC_DUNIT_MUL(x[1], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], y[2], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[2], y[3], hi2, lo2, tmp)

    lo += lo2 * 38;
    hi += hi2 * 38;

    CC_STORE_LO(t[1], hi, lo)

    CC_DUNIT_MUL(x[2], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[2], hi, lo, tmp)
    CC_DUNIT_MULI(x[3], y[3], hi, lo, tmp, 38)

    CC_STORE_LO(t[2], hi, lo)

    CC_DUNIT_MUL(x[3], y[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[2], y[1], hi, lo, tmp)
    CC_DUNIT_MUL(x[1], y[2], hi, lo, tmp)
    CC_DUNIT_MUL(x[0], y[3], hi, lo, tmp)

    t[3] = (cc_unit)lo;
    hi += lo >> CCN_UNIT_BITS;
    hi *= 38;

    // Reduce once.
    CC_DUNIT_ADD(r[0], t[0], hi & CCN_UNIT_MASK, tmp)
    CC_DUNIT_ADC(r[1], t[1], hi >> CCN_UNIT_BITS, tmp)
    CC_DUNIT_ADC(r[2], t[2], 0, tmp)
    CC_DUNIT_ADC(r[3], t[3], 0, tmp)

    // Reduce twice.
    CC_DUNIT_ADD(r[0], r[0], 38 & -(tmp >> CCN_UNIT_BITS), tmp)
}

void ccec25519_sqr_opt_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_unit t[CCN256_N];
    cc_dunit hi = 0;
    cc_dunit lo = 0;
    cc_dunit hi2 = 0;
    cc_dunit lo2 = 0;
    cc_dunit tmp;

    CC_DUNIT_MUL(x[0], x[0], hi, lo, tmp)
    CC_DUNIT_MUL(x[3], x[1], hi2, lo2, tmp)

    lo2 <<= 1;
    hi2 <<= 1;

    CC_DUNIT_MUL(x[2], x[2], hi2, lo2, tmp)

    lo += lo2 * 38;
    hi += hi2 * 38;

    CC_STORE_LO(t[0], hi, lo)

    lo2 = 0;
    hi2 = 0;

    CC_DUNIT_MULI(x[1], x[0], hi, lo, tmp, 2)
    CC_DUNIT_MULI(x[3], x[2], hi, lo, tmp, 76)

    CC_STORE_LO(t[1], hi, lo)

    CC_DUNIT_MULI(x[2], x[0], hi, lo, tmp, 2)
    CC_DUNIT_MUL(x[1], x[1], hi, lo, tmp)
    CC_DUNIT_MULI(x[3], x[3], hi, lo, tmp, 38)

    CC_STORE_LO(t[2], hi, lo)

    CC_DUNIT_MUL(x[3], x[0], hi2, lo2, tmp)
    CC_DUNIT_MUL(x[2], x[1], hi2, lo2, tmp)

    lo += lo2 << 1;
    hi += hi2 << 1;

    t[3] = (cc_unit)lo;
    hi += lo >> CCN_UNIT_BITS;
    hi *= 38;

    // Reduce once.
    CC_DUNIT_ADD(r[0], t[0], hi & CCN_UNIT_MASK, tmp)
    CC_DUNIT_ADC(r[1], t[1], hi >> CCN_UNIT_BITS, tmp)
    CC_DUNIT_ADC(r[2], t[2], 0, tmp)
    CC_DUNIT_ADC(r[3], t[3], 0, tmp)

    // Reduce twice.
    CC_DUNIT_ADD(r[0], r[0], 38 & -(tmp >> CCN_UNIT_BITS), tmp)
}

CC_WORKSPACE_OVERRIDE(cczp_add_ws, ccec25519_add_opt_ws)
CC_WORKSPACE_OVERRIDE(cczp_sub_ws, ccec25519_sub_opt_ws)
CC_WORKSPACE_OVERRIDE(cczp_mul_ws, ccec25519_mul_opt_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqr_ws, ccec25519_sqr_opt_ws)

#endif // (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED

#if CCN_MULMOD_25519_ASM

void ccn_addmod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_addmod_p25519");
void ccn_submod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_submod_p25519");
void ccn_mulmod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_mulmod_p25519");
void ccn_sqrmod_p25519(cc_unit *r, const cc_unit *a) __asm__("_ccn_sqrmod_p25519");

void ccec25519_add_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_addmod_p25519(r, x, y);
}

void ccec25519_sub_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_submod_p25519(r, x, y);
}

void ccec25519_mul_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_mulmod_p25519(r, x, y);
}

void ccec25519_sqr_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    ccn_sqrmod_p25519(r, x);
}

#endif // CCN_MULMOD_25519_ASM
