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

#include "ccec448_internal.h"

static const struct ccec_funcs ccec_x448_funcs = {
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

static const ccec_cp_decl(448) ccec_x448_c_params =
{
    .hp = {
        .n = CCN448_N,
        .bitlen = 448,
        .funcs = (cczp_funcs_t)&ccec_x448_funcs
    },
    .p = {
        CCN448_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,
                 ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .p0inv = (cc_unit)1U,
    .pr2 = {
        CCN448_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,03,
                 00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02)
    }
};

ccec_const_cp_t ccec_cp_x448_c(void)
{
    return (ccec_const_cp_t)&ccec_x448_c_params;
}

ccec_const_cp_t ccec_cp_x448(void)
{
#if CCN_MULMOD_448_ASM
    return ccec_cp_x448_asm();
#elif (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    return ccec_cp_x448_opt();
#else
    return ccec_cp_x448_c();
#endif
}
