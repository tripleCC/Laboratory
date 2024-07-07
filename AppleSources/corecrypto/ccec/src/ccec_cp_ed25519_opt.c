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

#include "ccec25519_internal.h"

#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED

static const struct ccec_funcs ccec_ed25519_funcs = {
    .cczp_add = ccec25519_add_opt_ws,
    .cczp_sub = ccec25519_sub_opt_ws,
    .cczp_mul = ccec25519_mul_opt_ws,
    .cczp_sqr = ccec25519_sqr_opt_ws,
    .cczp_inv = ccec25519_inv_ws,
    .cczp_from = ccec25519_from_ws,

    .cczp_mod = cczp_mod_default_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = cczp_to_default_ws,

    .ccec_projectify = ccec_projectify_homogeneous_ws,
    .ccec_affinify = ccec_affinify_homogeneous_ws,
    .ccec_full_add = cced25519_full_add_ws,
    .ccec_mult = cced25519_scalar_mult_ws
};

static const ccec_cp_decl(255) ccec_cp25519_opt_params =
{
    .hp = {
        .n = CCN256_N,
        .bitlen = 255,
        .funcs = (cczp_funcs_t)&ccec_ed25519_funcs
    },
    .p = {
        CCN256_C(7f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ed)
    },
    .p0inv = (cc_unit)0x86bca1af286bca1b,
    .pr2 = {
        CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,05,a4)
    },
    .gx = {
        CCN256_C(21,69,36,d3,cd,6e,53,fe,c0,a4,e2,31,fd,d6,dc,5c,69,2c,c7,60,95,25,a7,b2,c9,56,2d,60,8f,25,d5,1a)
    },
    .gy = {
        CCN256_C(66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,58)
    },
    .hq = {
        .n = CCN256_N,
        .bitlen = 253,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN256_C(10,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,14,de,f9,de,a2,f7,9c,d6,58,12,63,1a,5c,f5,d3,ed)
    },
    .q0inv = (cc_unit)0xd2b51da312547e1b,
    .qr2 = {
        CCN256_C(03,99,41,1b,7c,30,9a,3d,ce,ec,73,d2,17,f5,be,65,d0,0e,1b,a7,68,85,93,47,a4,06,11,e3,44,9c,0f,01)
    }
};

ccec_const_cp_t ccec_cp_ed25519_opt(void)
{
    return (ccec_const_cp_t)&ccec_cp25519_opt_params;
}

#endif
