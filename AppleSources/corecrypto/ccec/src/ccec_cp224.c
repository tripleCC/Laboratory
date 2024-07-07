/* Copyright (c) (2010-2012,2014-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

// c1, the largest integer such that 2^c1 divides p - 1.
static const size_t SQRT_C1 = 96;

// c2 = (p - 1) / (2^c1)
// c3 = (c2 - 1) / 2
static const cc_unit SQRT_C3[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,7f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
};

// c2 = (p - 1) / (2^c1)
// c4 = 0xb (a non-square value in F)
// c5 = c4^c2 in F.
static const cc_unit SQRT_C5[CCN224_N] = {
#if CCN_UNIT_SIZE == 8
    CCN224_C(dc,58,4a,70,48,83,1b,2a,b4,0e,42,70,e8,ff,4d,ec,bd,bc,c8,60,04,ab,76,ab,3d,fe,35,12)
#else
    CCN224_C(dd,4f,6d,00,14,bb,49,f6,fc,ae,2c,30,99,6f,56,28,14,df,d3,a4,6a,c7,64,62,0a,f2,e8,1a)
#endif
};

/*! @function ccn_addmul1_p224
 @abstract Computes r += p224 * v.

 @param r  Result
 @param v  Limb to add

 @return Any carry bits.
 */
CC_NONNULL_ALL
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
static cc_unit ccn_addmul1_p224(cc_unit *r, CC_UNUSED cc_unit _v)
{
    cc_dunit tmp;
    cc_unit v = -r[0];

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0x0000000000000001
    tmp = (cc_dunit)r[0] + v;
    r[0] = 0;

    // * 0xffffffff00000000
    tmp = (cc_dunit)r[1] + (v1 << 32) + (tmp >> 64);
    r[1] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[2] + (((cc_dunit)v << 64) - v) + (tmp >> 64);
    r[2] = (cc_unit)tmp;

    // * 0x00000000ffffffff
    tmp = (cc_dunit)r[3] + v1 + (tmp >> 64);
    r[3] = (cc_unit)tmp;

    return (tmp >> 64);
}
#elif (CCN_UNIT_SIZE == 4)
static cc_unit ccn_addmul1_p224(cc_unit *r, CC_UNUSED cc_unit _v)
{
    cc_dunit tmp;
    cc_unit v = -r[0];

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0x00000001
    tmp = (cc_dunit)r[0] + v;
    r[0] = 0;

    // * 0x00000000
    tmp = (cc_dunit)r[1] + (tmp >> 32);
    r[1] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[2] + (tmp >> 32);
    r[2] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[3] + v1 + (tmp >> 32);
    r[3] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[4] + v1 + (tmp >> 32);
    r[4] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[5] + v1 + (tmp >> 32);
    r[5] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[6] + v1 + (tmp >> 32);
    r[6] = (cc_unit)tmp;

    return (tmp >> 32);
}
#else
static cc_unit ccn_addmul1_p224(cc_unit *r, cc_unit v)
{
    return ccn_addmul1(CCN224_N, r, ccec_cp_p(ccec_cp_224()), v);
}
#endif

/*! @function ccn_p224_redc_ws
 @abstract Computes r := t / R (mod p224) via Montgomery's REDC algorithm.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccn_p224_redc_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    // p' := p^(-1) mod R
    // m  := ((t mod R) * p') mod R
    // r  := (t + m * p) / R
    for (cc_size i = 0; i < CCN224_N; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
        t[i] = ccn_addmul1_p224(&t[i], -t[i]);
    }

    // Optional final reduction.
    cc_unit s = ccn_add_ws(ws, CCN224_N, &t[CCN224_N], &t[CCN224_N], t);
    s ^= ccn_sub_ws(ws, CCN224_N, t, &t[CCN224_N], cczp_prime(zp));
    ccn_mux(CCN224_N, s, r, &t[CCN224_N], t);
}

/*! @function ccn_p224_mul_ws
 @abstract Multiplies two 224-bit numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void ccn_p224_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_size n = CCN224_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, CCN224_N, rbig, x, y);
    ccn_p224_redc_ws(ws, zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p224_sqr_ws
 @abstract Squares a 224-bit number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void ccn_p224_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN224_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, CCN224_N, rbig, x);
    ccn_p224_redc_ws(ws, zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p224_sqrt_ws
 @abstract Computes r := x^(1/2) (mod p224) via constant-time Tonelli-Shanks.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Square root of x
 @param x   Quadratic residue
 */
int ccn_p224_sqrt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    return cczp_sqrt_tonelli_shanks_precomp_ws(ws, zp, r, x, SQRT_C1, SQRT_C3, SQRT_C5);
}

/*! @function ccn_p224_to_ws
 @abstract Computes r := x * R (mod p224) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
void ccn_p224_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cczp_mul_ws(ws, zp, r, x, cczp_r2(zp));
}

/*! @function ccn_p224_from_ws
 @abstract Computes r := x / R (mod p224) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p224_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN224_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_setn(2 * CCN224_N, rbig, CCN224_N, x);
    ccn_p224_redc_ws(ws, zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

CC_WORKSPACE_OVERRIDE(cczp_mul_ws, ccn_p224_mul_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqr_ws, ccn_p224_sqr_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqrt_ws, ccn_p224_sqrt_ws)
CC_WORKSPACE_OVERRIDE(cczp_to_ws, ccn_p224_to_ws)
CC_WORKSPACE_OVERRIDE(cczp_from_ws, ccn_p224_from_ws)

static const struct ccec_funcs ccec_224_funcs = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = ccn_p224_mul_ws,
    .cczp_sqr = ccn_p224_sqr_ws,
    .cczp_mod = cczp_mod_default_ws,
    .cczp_inv = cczp_inv_field_ws,
    .cczp_sqrt = ccn_p224_sqrt_ws,
    .cczp_to = ccn_p224_to_ws,
    .cczp_from = ccn_p224_from_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(224) ccec_cp224 =
{
    .hp = {
        .n = CCN224_N,
        .bitlen = 224,
        .funcs = (cczp_funcs_t)&ccec_224_funcs
    },
    .p = {
        CCN224_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,01)
    },
    .p0inv = (cc_unit)0xffffffffffffffff,
    .pr2 = {
#if CCN_UNIT_SIZE == 8
        CCN224_C(ff,ff,ff,ff,ff,ff,ff,fe,00,00,00,00,ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,00,00,00,01)
#else
        CCN224_C(00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,00,00,00,00,00,00,00,00,00,00,00,01)
#endif
    },
    .b = {
#if CCN_UNIT_SIZE == 8
        CCN224_C(7f,c0,2f,93,3d,ce,ba,98,c8,52,81,51,10,7a,c2,f3,cc,f0,13,10,e7,68,cd,f6,63,c0,59,cd)
#else
        CCN224_C(9c,3f,a6,33,7f,c0,2f,93,3d,ce,ba,98,c8,52,81,50,74,3b,1c,c0,cc,f0,13,10,e7,68,cd,f7)
#endif
    },
    .gx = {
        CCN224_C(b7,0e,0c,bd,6b,b4,bf,7f,32,13,90,b9,4a,03,c1,d3,56,c2,11,22,34,32,80,d6,11,5c,1d,21)
    },
    .gy = {
        CCN224_C(bd,37,63,88,b5,f7,23,fb,4c,22,df,e6,cd,43,75,a0,5a,07,47,64,44,d5,81,99,85,00,7e,34)
    },
    .hq = {
        .n = CCN224_N,
        .bitlen = 224,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN224_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,16,a2,e0,b8,f0,3e,13,dd,29,45,5c,5c,2a,3d)
    },
    .q0inv = (cc_unit)0xd6e242706a1fc2eb,
    .qr2 = {
#if CCN_UNIT_SIZE == 8
        CCN224_C(b1,e9,79,61,6a,d1,5f,7c,d9,71,48,56,ab,c8,ff,59,31,d6,3f,4b,29,94,7a,69,5f,51,7d,15)
#else
        CCN224_C(d4,ba,a4,cf,18,22,bc,47,b1,e9,79,61,6a,d0,9d,91,97,a5,45,52,6b,da,ae,6c,3a,d0,12,89)
#endif
    }
};

ccec_const_cp_t ccec_cp_224_c(void)
{
    return (ccec_const_cp_t)&ccec_cp224;
}

CC_WEAK_IF_SMALL_CODE
ccec_const_cp_t ccec_cp_224(void)
{
#if CCN_MULMOD_224_ASM
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
        return ccec_cp_224_asm();
#endif

#if !CCN_MULMOD_224_ASM || defined(__x86_64__)
    return ccec_cp_224_c();
#endif
}
