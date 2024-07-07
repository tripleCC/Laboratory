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

CC_PURE cc_size CCN_P256_INV_ASM_WORKSPACE_N(cc_size n)
{
    return (3 * n);
}

CC_WORKSPACE_OVERRIDE(cczp_inv_ws, ccn_p256_inv_asm_ws)

#if CCN_MULMOD_256_ASM

void ccn_mulmod_p256(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_mulmod_p256");

static void ccn_p256_mul_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    ccn_mulmod_p256(r, x, y);
}

static void ccn_p256_sqr_asm_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    ccn_mulmod_p256(r, x, x);
}

/*! @function ccn_p256_from_asm_ws
 @abstract Computes r := x / R (mod p256) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p256_from_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    const cc_unit one[CCN256_N] = { 1U };
    ccn_p256_mul_asm_ws(ws, zp, r, x, one);
}

#define ccn_p256_sqr_asm_times_ws(_ws_, _zp_, _x_, _n_) \
    for (unsigned i = 0; i < _n_; i++) {                \
        ccn_p256_sqr_asm_ws(_ws_, _zp_, _x_, _x_);      \
    }

/*
 * p256 - 2 = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd
 *
 * A straightforward square-multiply implementation will need 256S+128M.
 * cczp_power_fast() with a fixed 2-bit window needs roughly 256S+128M as well.
 *
 * By dividing the exponent into the windows
 *   0xffffffff, 0x00000001, 0x000000000000000000000000ffffffff, 0xfffffffd
 * we can get away with only 255S+14M.
 */
CC_NONNULL_ALL
static int ccn_p256_inv_asm_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    int result = CCZP_INV_NO_INVERSE;
    cc_size n = CCN256_N;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    cc_unit *t2 = CC_ALLOC_WS(ws, n);

    // t2 := x^2
    ccn_p256_sqr_asm_ws(ws, zp, t2, x);

    // t1 := x^3
    ccn_p256_mul_asm_ws(ws, zp, t1, t2, x);

    // t0 := x^0xd
    ccn_p256_sqr_asm_times_ws(ws, zp, t1, 2);
    ccn_p256_mul_asm_ws(ws, zp, t0, t1, x);

    // t1 := x^0xf
    ccn_p256_mul_asm_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfd
    ccn_p256_sqr_asm_times_ws(ws, zp, t1, 4);
    ccn_p256_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xff
    ccn_p256_mul_asm_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffd
    ccn_p256_sqr_asm_times_ws(ws, zp, t1, 8);
    ccn_p256_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffff
    ccn_p256_mul_asm_ws(ws, zp, t1, t0, t2);

    // t0 := x^0xfffffffd
    ccn_p256_sqr_asm_times_ws(ws, zp, t1, 16);
    ccn_p256_mul_asm_ws(ws, zp, t0, t0, t1);

    // t1 := x^0xffffffff
    ccn_p256_mul_asm_ws(ws, zp, t1, t0, t2);
    ccn_set(CCN256_N, t2, t1);

    // t2 = x^0xffffffff00000001
    ccn_p256_sqr_asm_times_ws(ws, zp, t2, 32);
    ccn_p256_mul_asm_ws(ws, zp, t2, t2, x);

    // t2 = x^0xffffffff00000001000000000000000000000000ffffffff
    ccn_p256_sqr_asm_times_ws(ws, zp, t2, 32 * 4);
    ccn_p256_mul_asm_ws(ws, zp, t2, t2, t1);

    // t2 = x^0xffffffff00000001000000000000000000000000ffffffffffffffff
    ccn_p256_sqr_asm_times_ws(ws, zp, t2, 32);
    ccn_p256_mul_asm_ws(ws, zp, t2, t2, t1);

    // t1 = x^0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd
    ccn_p256_sqr_asm_times_ws(ws, zp, t2, 32);
    ccn_p256_mul_asm_ws(ws, zp, t1, t2, t0);

    // r*x = 1 (mod p)?
    ccn_p256_mul_asm_ws(ws, zp, t0, t1, x);
    ccn_p256_from_asm_ws(ws, zp, t0, t0);
    if (!ccn_is_one(n, t0)) {
        goto errOut;
    }

    ccn_set(CCN256_N, r, t1);
    result = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

static const struct ccec_funcs ccec_256_funcs_asm = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = ccn_p256_mul_asm_ws,
    .cczp_sqr = ccn_p256_sqr_asm_ws,
    .cczp_mod = cczp_mod_default_ws,
    .cczp_inv = ccn_p256_inv_asm_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = ccn_p256_to_ws,
    .cczp_from = ccn_p256_from_asm_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(256) ccec_cp256_asm =
{
    .hp = {
        .n = CCN256_N,
        .bitlen = 256,
        .funcs = (cczp_funcs_t)&ccec_256_funcs_asm
    },
    .p = {
        CCN256_C(ff,ff,ff,ff,00,00,00,01,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .p0inv = 1U,
    .pr2 = {
        CCN256_C(00,00,00,04,ff,ff,ff,fd,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,fb,ff,ff,ff,ff,00,00,00,00,00,00,00,03)
    },
    .b = {
        CCN256_C(dc,30,06,1d,04,87,48,34,e5,a2,20,ab,f7,21,2e,d6,ac,f0,05,cd,78,84,30,90,d8,9c,df,62,29,c4,bd,df)
    },
    .gx = {
        CCN256_C(6b,17,d1,f2,e1,2c,42,47,f8,bc,e6,e5,63,a4,40,f2,77,03,7d,81,2d,eb,33,a0,f4,a1,39,45,d8,98,c2,96)
    },
    .gy = {
        CCN256_C(4f,e3,42,e2,fe,1a,7f,9b,8e,e7,eb,4a,7c,0f,9e,16,2b,ce,33,57,6b,31,5e,ce,cb,b6,40,68,37,bf,51,f5)
    },
    .hq = {
        .n = CCN256_N,
        .bitlen = 256,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,51)
    },
    .q0inv = (cc_unit)0xccd1c8aaee00bc4f,
    .qr2 = {
        CCN256_C(66,e1,2d,94,f3,d9,56,20,28,45,b2,39,2b,6b,ec,59,46,99,79,9c,49,bd,6f,a6,83,24,4c,95,be,79,ee,a2)
    }
};

ccec_const_cp_t ccec_cp_256_asm(void)
{
    return (ccec_const_cp_t)&ccec_cp256_asm;
}

#endif
