/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
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

CC_PURE cc_size CCN_P384_INV_ASM_WORKSPACE_N(cc_size n)
{
    return (3 * n);
}

CC_WORKSPACE_OVERRIDE(cczp_inv_ws, ccn_p384_inv_asm_ws)

#if CCN_MULMOD_384_ASM

void ccn_mulmod_p384(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_mulmod_p384");

static void ccn_p384_mul_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_mulmod_p384(r, x, y);
}

static void ccn_p384_sqr_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    ccn_mulmod_p384(r, x, x);
}

/*! @function ccn_p384_from_asm_ws
 @abstract Computes r := x / R (mod p384) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p384_from_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    const cc_unit one[CCN384_N] = { 1U };
    ccn_p384_mul_asm_ws(ws, zp, r, x, one);
}

#define ccn_p384_sqr_times_ws(_ws_, _zp_, _x_, _n_) \
    for (unsigned i = 0; i < _n_; i++) {            \
        ccn_p384_sqr_asm_ws(_ws_, _zp_, _x_, _x_);  \
    }

/*
 * p384 - 2 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd
 */
CC_NONNULL_ALL CC_WARN_RESULT
static int ccn_p384_inv_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    int result = CCZP_INV_NO_INVERSE;
    cc_size n = CCN384_N;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    cc_unit *t2 = CC_ALLOC_WS(ws, n);

    // t2 := x^2
    ccn_p384_sqr_asm_ws(ws, zp, t2, x);

    // t1 := x^3
    ccn_p384_mul_asm_ws(ws, zp, t1, t2, x);

    // t0 := x^0xd
    ccn_p384_sqr_times_ws(ws, zp, t1, 2);
    ccn_p384_mul_asm_ws(ws, zp, t0, t1, x);

    // t1 := x^0xf
    ccn_p384_mul_asm_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfd
    ccn_p384_sqr_times_ws(ws, zp, t1, 4);
    ccn_p384_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xff
    ccn_p384_mul_asm_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffd
    ccn_p384_sqr_times_ws(ws, zp, t1, 8);
    ccn_p384_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffff
    ccn_p384_mul_asm_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffffffd
    ccn_p384_sqr_times_ws(ws, zp, t1, 16);
    ccn_p384_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xfffffffe
    ccn_p384_mul_asm_ws(ws, zp, t1, t0, x);

    // t2 := x^0xffffffff
    ccn_p384_mul_asm_ws(ws, zp, t2, t1, x);

    // t2 := x^0xffffffff00000000
    ccn_p384_sqr_times_ws(ws, zp, t2, 32);

    // t1 := x^0xfffffffffffffffe
    ccn_p384_mul_asm_ws(ws, zp, t1, t2, t1);

    // t2 := x^0xffffffff0000000000000000fffffffd
    ccn_p384_sqr_times_ws(ws, zp, t2, 32 * 2);
    ccn_p384_mul_asm_ws(ws, zp, t2, t2, t0);

    // t0 := x^0xffffffffffffffff0000000000000000
    ccn_p384_mul_asm_ws(ws, zp, t0, t1, x);
    ccn_p384_sqr_times_ws(ws, zp, t0, 32 * 2);

    // t1 := x^0xfffffffffffffffffffffffffffffffe
    ccn_p384_mul_asm_ws(ws, zp, t1, t0, t1);

    // t0 := x^0xffffffffffffffffffffffffffffffff
    ccn_p384_mul_asm_ws(ws, zp, t0, t1, x);

    // t0 := x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
    ccn_p384_sqr_times_ws(ws, zp, t0, 32 * 4);
    ccn_p384_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd
    ccn_p384_sqr_times_ws(ws, zp, t0, 32 * 4);
    ccn_p384_mul_asm_ws(ws, zp, t1, t0, t2);

    // r*x = 1 (mod p)?
    ccn_p384_mul_asm_ws(ws, zp, t0, t1, x);
    ccn_p384_from_asm_ws(ws, zp, t0, t0);
    if (!ccn_is_one(n, t0)) {
        goto errOut;
    }

    ccn_set(CCN384_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static const struct ccec_funcs ccec_384_funcs_asm = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = ccn_p384_mul_asm_ws,
    .cczp_sqr = ccn_p384_sqr_asm_ws,
    .cczp_mod = cczp_mod_default_ws,
    .cczp_inv = ccn_p384_inv_asm_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = ccn_p384_to_ws,
    .cczp_from = ccn_p384_from_asm_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(384) ccec_cp384_asm =
{
    .hp = {
        .n = CCN384_N,
        .bitlen = 384,
        .funcs = (cczp_funcs_t)&ccec_384_funcs_asm
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

ccec_const_cp_t ccec_cp_384_asm(void)
{
    return (ccec_const_cp_t)&ccec_cp384_asm;
}

#endif
