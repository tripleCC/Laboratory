/* Copyright (c) (2021,2023) Apple Inc. All rights reserved.
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

static const struct ccec_funcs ccec_256_funcs_small = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = cczp_mul_default_ws,
    .cczp_sqr = cczp_sqr_default_ws,
    .cczp_mod = cczp_mod_default_ws,
    .cczp_inv = cczp_inv_field_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = cczp_to_default_ws,
    .cczp_from = cczp_from_default_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(256) ccec_cp256_small =
{
    .hp = {
        .n = CCN256_N,
        .bitlen = 256,
        .funcs = (cczp_funcs_t)&ccec_256_funcs_small
    },
    .p = {
        CCN256_C(ff,ff,ff,ff,00,00,00,01,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .p0inv = 1U,
    .pr2 = {
        CCN256_C(00,00,00,04,ff,ff,ff,fd,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,fb,ff,ff,ff,ff,00,00,00,00,00,00,00,03)
    },
    .b = {
        CCN256_C(5a,c6,35,d8,aa,3a,93,e7,b3,eb,bd,55,76,98,86,bc,65,1d,06,b0,cc,53,b0,f6,3b,ce,3c,3e,27,d2,60,4b)
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
        .funcs = (cczp_funcs_t)&ccec_256_funcs_small
    },
    .q = {
        CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,51)
    },
    .q0inv = (cc_unit)0xccd1c8aaee00bc4f,
    .qr2 = {
        CCN256_C(66,e1,2d,94,f3,d9,56,20,28,45,b2,39,2b,6b,ec,59,46,99,79,9c,49,bd,6f,a6,83,24,4c,95,be,79,ee,a2)
    }
};

ccec_const_cp_t ccec_cp_256_small(void)
{
    return (ccec_const_cp_t)(const struct cczp *)(const cc_unit*)&ccec_cp256_small;
}
