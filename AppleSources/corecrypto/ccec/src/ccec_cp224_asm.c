/* Copyright (c) (2021-2023) Apple Inc. All rights reserved.
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

CC_PURE cc_size CCN_P224_INV_ASM_WORKSPACE_N(cc_size n)
{
    return (3 * n);
}

CC_WORKSPACE_OVERRIDE(cczp_inv_ws, ccn_p224_inv_asm_ws)

#if CCN_MULMOD_224_ASM

void ccn_mulmod_p224(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_mulmod_p224");

static void ccn_p224_mul_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_mulmod_p224(r, x, y);
}

static void ccn_p224_sqr_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    ccn_mulmod_p224(r, x, x);
}

/*! @function ccn_p224_from_asm_ws
 @abstract Computes r := x / R (mod p224) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p224_from_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    const cc_unit one[CCN224_N] = { 1U };
    ccn_p224_mul_asm_ws(ws, zp, r, x, one);
}

#define ccn_p224_sqr_asm_times_ws(_ws_, _zp_, _x_, _n_) \
    for (unsigned i = 0; i < _n_; i++) {                \
        ccn_p224_sqr_asm_ws(_ws_, _zp_, _x_, _x_);      \
    }

/*
 * p224 - 2 = 0xfffffffffffffffffffffffffffffffeffffffffffffffffffffffff
 *
 * A straightforward square-multiply implementation will need 224S+223M.
 * cczp_power_fast() with a fixed 2-bit window needs roughly 224S+112M.
 *
 * By dividing the exponent into the windows
 *   0xffffffffffffffffffffffff, 0xfffffffe, 0xffffffffffffffffffffffff
 * we can get away with only 223S+14M.
 */
CC_NONNULL_ALL
static int ccn_p224_inv_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    int result = CCZP_INV_NO_INVERSE;
    cc_size n = CCN224_N;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    cc_unit *t2 = CC_ALLOC_WS(ws, n);

    // t0 := x^2
    ccn_p224_sqr_asm_ws(ws, zp, t0, x);

    // t1 := x^3
    ccn_p224_mul_asm_ws(ws, zp, t1, t0, x);

    // t0 := x^0xe
    ccn_p224_sqr_asm_times_ws(ws, zp, t1, 2);
    ccn_p224_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xf
    ccn_p224_mul_asm_ws(ws, zp, t1, t0, x);
    ccn_set(CCN224_N, t2, t1);

    // t0 := x^0xfe
    ccn_p224_sqr_asm_times_ws(ws, zp, t1, 4);
    ccn_p224_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xff
    ccn_p224_mul_asm_ws(ws, zp, t1, t0, x);

    // t0 := x^0xfffe
    ccn_p224_sqr_asm_times_ws(ws, zp, t1, 8);
    ccn_p224_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffff
    ccn_p224_mul_asm_ws(ws, zp, t1, t0, x);

    // t0 := x^0xfffffffe
    ccn_p224_sqr_asm_times_ws(ws, zp, t1, 16);
    ccn_p224_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffff
    ccn_p224_mul_asm_ws(ws, zp, t1, t0, x);
    ccn_set(CCN224_N, t2, t1);

    // t2 := x^0xffffffffffffffff
    ccn_p224_sqr_asm_times_ws(ws, zp, t2, 32);
    ccn_p224_mul_asm_ws(ws, zp, t2, t2, t1);

    // t2 := x^0xffffffffffffffffffffffff
    ccn_p224_sqr_asm_times_ws(ws, zp, t2, 32);
    ccn_p224_mul_asm_ws(ws, zp, t2, t2, t1);
    ccn_set(CCN224_N, t1, t2);

    // t2 := x^0xfffffffffffffffffffffffffffffffe
    ccn_p224_sqr_asm_times_ws(ws, zp, t2, 32);
    ccn_p224_mul_asm_ws(ws, zp, t2, t2, t0);

    // t1 := x^0xfffffffffffffffffffffffffffffffeffffffffffffffffffffffff
    ccn_p224_sqr_asm_times_ws(ws, zp, t2, 32 * 3);
    ccn_p224_mul_asm_ws(ws, zp, t1, t1, t2);

    // r*x = 1 (mod p)?
    ccn_p224_mul_asm_ws(ws, zp, t0, t1, x);
    ccn_p224_from_asm_ws(ws, zp, t0, t0);
    if (!ccn_is_one(n, t0)) {
        goto errOut;
    }

    ccn_set(CCN224_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static const struct ccec_funcs ccec_224_funcs_asm = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = ccn_p224_mul_asm_ws,
    .cczp_sqr = ccn_p224_sqr_asm_ws,
    .cczp_mod = cczp_mod_default_ws,
    .cczp_inv = ccn_p224_inv_asm_ws,
    .cczp_sqrt = ccn_p224_sqrt_ws,
    .cczp_to = ccn_p224_to_ws,
    .cczp_from = ccn_p224_from_asm_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(224) ccec_cp224_asm =
{
    .hp = {
        .n = CCN224_N,
        .bitlen = 224,
        .funcs = (cczp_funcs_t)&ccec_224_funcs_asm
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

ccec_const_cp_t ccec_cp_224_asm(void)
{
    return (ccec_const_cp_t)&ccec_cp224_asm;
}

#endif
