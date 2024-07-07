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

static const struct ccec_funcs ccec_x25519_funcs = {
    .cczp_add = ccec25519_add_ws,
    .cczp_sub = ccec25519_sub_ws,
    .cczp_mul = ccec25519_mul_ws,
    .cczp_sqr = ccec25519_sqr_ws,
    .cczp_inv = ccec25519_inv_ws,
    .cczp_from = ccec25519_from_ws,

    .cczp_mod = cczp_mod_default_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = cczp_to_default_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(255) ccec_cp25519_c_params =
{
    .hp = {
        .n = CCN256_N,
        .bitlen = 255,
        .funcs = (cczp_funcs_t)&ccec_x25519_funcs
    },
    .p = {
        CCN256_C(7f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ed)
    },
    .p0inv = (cc_unit)0x86bca1af286bca1b,
    .pr2 = {
        CCN256_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,05,a4)
    }
};

ccec_const_cp_t ccec_cp_x25519_c(void)
{
    return (ccec_const_cp_t)&ccec_cp25519_c_params;
}

ccec_const_cp_t ccec_cp_x25519(void)
{
#if CCN_MULMOD_25519_ASM
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
        return ccec_cp_x25519_asm();
#endif

#if !CCN_MULMOD_25519_ASM || defined(__x86_64__)
 #if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    return ccec_cp_x25519_opt();
 #else
    return ccec_cp_x25519_c();
 #endif
#endif
}
