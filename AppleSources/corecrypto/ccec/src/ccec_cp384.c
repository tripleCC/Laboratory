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

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

/*! @function ccn_addmul1_p384
 @abstract Computes r += p384 * v.

 @param r  Result
 @param v  Limb to add

 @return Any carry bits.
 */
CC_NONNULL_ALL
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
static cc_unit ccn_addmul1_p384(cc_unit *r, CC_UNUSED cc_unit _v)
{
    cc_dunit tmp;
    cc_unit v = (r[0] << 32) + r[0];

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // v * 0xffffffffffffffff
    cc_dunit v2 = ((cc_dunit)v << 64) - v;

    // * 0x00000000ffffffff
    tmp = (cc_dunit)r[0] + v1;
    r[0] = 0;

    // * 0xffffffff00000000
    tmp = (cc_dunit)r[1] + (v1 << 32) + (tmp >> 64);
    r[1] = (cc_unit)tmp;

    // * 0xfffffffffffffffe
    tmp = (cc_dunit)r[2] + (v2 - v) + (tmp >> 64);
    r[2] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[3] + v2 + (tmp >> 64);
    r[3] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[4] + v2 + (tmp >> 64);
    r[4] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[5] + v2 + (tmp >> 64);
    r[5] = (cc_unit)tmp;

    return (tmp >> 64);
}
#elif (CCN_UNIT_SIZE == 4)
static cc_unit ccn_addmul1_p384(cc_unit *r, CC_UNUSED cc_unit _v)
{
    cc_dunit tmp;
    cc_unit v = r[0];

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // r[0] = r[0] + v * 0xffffffff
    //      = r[0] + (v << 32) - v
    //      = r[0] + (r[0] << 32) - r[0]
    //      = (r[0] << 32)

    // * 0x00000000
    tmp = (cc_dunit)r[1] + r[0];
    r[1] = (cc_unit)tmp;
    r[0] = 0;

    // * 0x00000000
    tmp = (cc_dunit)r[2] + (tmp >> 32);
    r[2] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[3] + v1 + (tmp >> 32);
    r[3] = (cc_unit)tmp;

    // * 0xfffffffe
    tmp = (cc_dunit)r[4] + (v1 - v) + (tmp >> 32);
    r[4] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[5] + v1 + (tmp >> 32);
    r[5] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[6] + v1 + (tmp >> 32);
    r[6] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[7] + v1 + (tmp >> 32);
    r[7] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[8] + v1 + (tmp >> 32);
    r[8] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[9] + v1 + (tmp >> 32);
    r[9] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[10] + v1 + (tmp >> 32);
    r[10] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[11] + v1 + (tmp >> 32);
    r[11] = (cc_unit)tmp;

    return (tmp >> 32);
}
#else
static cc_unit ccn_addmul1_p384(cc_unit *r, cc_unit v)
{
    return ccn_addmul1(CCN384_N, r, ccec_cp_p(ccec_cp_384()), v);
}
#endif

/*! @function ccn_p384_redc_ws
 @abstract Computes r := t / R (mod p384) via Montgomery's REDC algorithm.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccn_p384_redc_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    // p' := p^(-1) mod R
    // m  := ((t mod R) * p') mod R
    // r  := (t + m * p) / R
    for (cc_size i = 0; i < CCN384_N; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
#if (CCN_UNIT_SIZE == 8)
        t[i] = ccn_addmul1_p384(&t[i], t[i] + (t[i] << 32)); // * 0x100000001
#else
        t[i] = ccn_addmul1_p384(&t[i], t[i]);
#endif
    }

    // Optional final reduction.
    cc_unit s = ccn_add_ws(ws, CCN384_N, &t[CCN384_N], &t[CCN384_N], t);
    s ^= ccn_sub_ws(ws, CCN384_N, t, &t[CCN384_N], cczp_prime(zp));
    ccn_mux(CCN384_N, s, r, &t[CCN384_N], t);
}

/*! @function ccn_p384_mul_ws
 @abstract Multiplies two 384-bit numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void ccn_p384_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_size n = CCN384_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, CCN384_N, rbig, x, y);
    ccn_p384_redc_ws(ws, zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p384_sqr_ws
 @abstract Squares a 384-bit number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void ccn_p384_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN384_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, CCN384_N, rbig, x);
    ccn_p384_redc_ws(ws, zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p384_to_ws
 @abstract Computes r := x * R (mod p384) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
void ccn_p384_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cczp_mul_ws(ws, zp, r, x, cczp_r2(zp));
}

/*! @function ccn_p384_from_ws
 @abstract Computes r := x / R (mod p384) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p384_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN384_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_setn(2 * CCN384_N, rbig, CCN384_N, x);
    ccn_p384_redc_ws(ws, zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

CC_WORKSPACE_OVERRIDE(cczp_mul_ws, ccn_p384_mul_ws)
CC_WORKSPACE_OVERRIDE(cczp_sqr_ws, ccn_p384_sqr_ws)
CC_WORKSPACE_OVERRIDE(cczp_to_ws, ccn_p384_to_ws)
CC_WORKSPACE_OVERRIDE(cczp_from_ws, ccn_p384_from_ws)

static const struct ccec_funcs ccec_384_funcs_c = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = ccn_p384_mul_ws,
    .cczp_sqr = ccn_p384_sqr_ws,
    .cczp_mod = cczp_mod_default_ws,
    .cczp_inv = cczp_inv_field_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = ccn_p384_to_ws,
    .cczp_from = ccn_p384_from_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(384) ccec_cp384_c =
{
    .hp = {
        .n = CCN384_N,
        .bitlen = 384,
        .funcs = (cczp_funcs_t)&ccec_384_funcs_c
    },
    .p = {
        CCN384_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,ff,00,00,00,00,00,00,00,00,ff,ff,ff,ff)
    },
    .p0inv = (cc_unit)0x100000001,
    .pr2 = {
        CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,02,00,00,00,00,ff,ff,ff,fe,00,00,00,00,00,00,00,02,00,00,00,00,ff,ff,ff,fe,00,00,00,01)
    },
    .b = {
        CCN384_C(cd,08,11,4b,60,4f,bf,f9,b6,2b,21,f4,1f,02,20,94,e3,37,4b,ee,94,93,8a,e2,77,f2,20,9b,19,20,02,2e,f7,29,ad,d8,7a,4c,32,ec,08,11,88,71,9d,41,2d,cc)
    },
    .gx = {
        CCN384_C(aa,87,ca,22,be,8b,05,37,8e,b1,c7,1e,f3,20,ad,74,6e,1d,3b,62,8b,a7,9b,98,59,f7,41,e0,82,54,2a,38,55,02,f2,5d,bf,55,29,6c,3a,54,5e,38,72,76,0a,b7)
    },
    .gy = {
        CCN384_C(36,17,de,4a,96,26,2c,6f,5d,9e,98,bf,92,92,dc,29,f8,f4,1d,bd,28,9a,14,7c,e9,da,31,13,b5,f0,b8,c0,0a,60,b1,ce,1d,7e,81,9d,7a,43,1d,7c,90,ea,0e,5f)
    },
    .hq = {
        .n = CCN384_N,
        .bitlen = 384,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN384_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,c7,63,4d,81,f4,37,2d,df,58,1a,0d,b2,48,b0,a7,7a,ec,ec,19,6a,cc,c5,29,73)
    },
    .q0inv = (cc_unit)0x6ed46089e88fdc45,
    .qr2 = {
        CCN384_C(0c,84,ee,01,2b,39,bf,21,3f,b0,5b,7a,28,26,68,95,d4,0d,49,17,4a,ab,1c,c5,bc,3e,48,3a,fc,b8,29,47,ff,3d,81,e5,df,1a,a4,19,2d,31,9b,24,19,b4,09,a9)
    }
};

ccec_const_cp_t ccec_cp_384_c(void)
{
    return (ccec_const_cp_t)&ccec_cp384_c;
}

CC_WEAK_IF_SMALL_CODE
ccec_const_cp_t ccec_cp_384(void)
{
#if CCN_MULMOD_384_ASM
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
        return ccec_cp_384_asm();
#endif

#if !CCN_MULMOD_384_ASM || defined(__x86_64__)
    return ccec_cp_384_c();
#endif
}
