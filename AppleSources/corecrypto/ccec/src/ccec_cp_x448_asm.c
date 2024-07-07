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

#if CCN_MULMOD_448_ASM

static const struct ccec_funcs ccec_x448_funcs = {
    .cczp_add = ccec448_add_asm,
    .cczp_sub = ccec448_sub_asm,
    .cczp_mul = ccec448_mul_asm,
    .cczp_sqr = ccec448_sqr_asm,
    .cczp_inv = ccec448_inv_ws,
    .cczp_from = ccec448_from_ws,

    .cczp_mod = cczp_mod_default_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = cczp_to_default_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(448) ccec_x448_asm_params =
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

ccec_const_cp_t ccec_cp_x448_asm(void)
{
    return (ccec_const_cp_t)&ccec_x448_asm_params;
}

#endif
