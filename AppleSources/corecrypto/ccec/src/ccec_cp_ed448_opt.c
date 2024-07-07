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

static const struct ccec_funcs ccec_ed448_funcs = {
    .cczp_add = ccec448_add_ws,
    .cczp_sub = ccec448_sub_ws,
    .cczp_mul = ccec448_mul_ws,
    .cczp_sqr = ccec448_sqr_ws,
    .cczp_inv = ccec448_inv_ws,
    .cczp_from = ccec448_from_ws,

    .cczp_mod = cczp_mod_default_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = cczp_to_default_ws,

    .ccec_projectify = ccec_projectify_homogeneous_ws,
    .ccec_affinify = ccec_affinify_homogeneous_ws,
    .ccec_full_add = cced448_full_add_ws,
    .ccec_mult = cced448_scalar_mult_ws
};

static const ccec_cp_decl(448) ccec_ed448_opt_params =
{
    .hp = {
        .n = CCN448_N,
        .bitlen = 448,
        .funcs = (cczp_funcs_t)&ccec_ed448_funcs
    },
    .p = {
        CCN448_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,
                 ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .p0inv = (cc_unit)1U,
    .pr2 = {
        CCN448_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,03,
                 00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02)
    },
    .gx = {
        CCN448_C(4f,19,70,c6,6b,ed,0d,ed,22,1d,15,a6,22,bf,36,da,9e,14,65,70,47,0f,17,67,ea,6d,e3,24,
                 a3,d3,a4,64,12,ae,1a,f7,2a,b6,65,11,43,3b,80,e1,8b,00,93,8e,26,26,a8,2b,c7,0c,c0,5e)
    },
    .gy = {
        CCN448_C(69,3f,46,71,6e,b6,bc,24,88,76,20,37,56,c9,c7,62,4b,ea,73,73,6c,a3,98,40,87,78,9c,1e,
                 05,a0,c2,d7,3a,d3,ff,1c,e6,7c,39,c4,fd,bd,13,2c,4e,d7,c8,ad,98,08,79,5b,f2,30,fa,14)
    },
    .hq = {
        .n = CCN448_N,
        .bitlen = 446,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN448_C(3f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,
                 7c,ca,23,e9,c4,4e,db,49,ae,d6,36,90,21,6c,c2,72,8d,c5,8f,55,23,78,c2,92,ab,58,44,f3)
    },
    .q0inv = (cc_unit)0x3bd440fae918bc5,
    .qr2 = {
        CCN448_C(34,02,a9,39,f8,23,b7,29,20,52,bc,b7,e4,d0,70,af,1a,9c,c1,4b,a3,c4,7c,44,ae,17,cf,72,
                 5e,e4,d8,38,0d,66,de,23,88,ea,18,59,7a,f3,2c,4b,c1,b1,95,d9,e3,53,92,57,04,9b,9b,60)
    }
};

ccec_const_cp_t ccec_cp_ed448_opt(void)
{
    return (ccec_const_cp_t)&ccec_ed448_opt_params;
}

#endif
