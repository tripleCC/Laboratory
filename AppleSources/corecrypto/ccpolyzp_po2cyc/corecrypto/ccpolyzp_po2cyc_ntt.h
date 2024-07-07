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

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_NTT_H_
#define _CORECRYPTO_CCPOLYZP_PO2CYC_NTT_H_

#include <corecrypto/cc_config.h>
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_scalar.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Returns whether or not the prime modulus and degree are suitable for use in the NTT
/// @param modulus The modulus; must be prime
/// @param degree The number of coefficients in the polynomial
CC_INLINE CC_NONNULL_ALL bool is_ntt_modulus_and_degree(ccrns_int modulus, uint32_t degree)
{
    bool is_valid_degree = ccpolyzp_po2cyc_ctx_is_valid_degree(degree);
    return is_valid_degree && (modulus % (2 * (ccrns_int)degree) == 1);
}

/// @brief Returns the root of unity powers for a given modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store w^bit_reverse(i) mod modulus, where w is a 2N'th root of unity mod modulus
/// E.g. instead of storing [w^0, w^1, w^2, w^3], we store [w^0, w^2, w^1, w^3]
CC_NONNULL_ALL CC_INLINE cc_unit *ccpolyzp_po2cyc_ctx_rou_powers(ccpolyzp_po2cyc_ctx_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_t cur_ctx = ccpolyzp_po2cyc_ctx_idx(ctx, idx);
    cc_unit *cczp_moduli = (cc_unit *)CCPOLYZP_PO2CYC_CTX_CCZP_MODULI(cur_ctx);
    cc_unit *rous = cczp_moduli + cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);
    return rous;
}

/// @brief Returns the root of unity powers for a given modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store w^bit_reverse(i) mod modulus, where w is a 2N'th root of unity mod modulus
/// E.g. instead of storing [w^0, w^1, w^2, w^3], we store [w^0, w^2, w^1, w^3]
CC_NONNULL_ALL CC_INLINE const cc_unit *ccpolyzp_po2cyc_ctx_rou_powers_const(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_const_t cur_ctx = ccpolyzp_po2cyc_ctx_idx_const(ctx, idx);
    const cc_unit *cczp_moduli = (const cc_unit *)CCPOLYZP_PO2CYC_CTX_CCZP_MODULI_CONST(cur_ctx);
    const cc_unit *rous = cczp_moduli + cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);
    return rous;
}

/// @brief Returns the 2*N'th root of unity used in the NTT for the idx'th modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
CC_NONNULL_ALL ccrns_int ccpolyzp_po2cyc_ctx_rou(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t idx);

/// @brief Returns the moduli for multiplication by the root of unity powers for a given modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store the modulus for multiplication by w^bit_reverse(i) mod modulus, where w is a 2N'th root of unity
/// mod modulus. E.g. instead of storing [w^0, w^1, w^2, w^3], we store [w^0, w^2, w^1, w^3]
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_t ccpolyzp_po2cyc_ctx_rou_powers_mul_modulus(ccpolyzp_po2cyc_ctx_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    cc_unit *units = ccpolyzp_po2cyc_ctx_rou_powers(ctx, idx);
    units += ctx->dims.degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return (ccrns_mul_modulus_t)units;
}

/// @brief Returns the moduli for multiplication by the root of unity powers for a given modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store the modulus for multiplication by w^bit_reverse(i) mod modulus, where w is a 2N'th root of unity
/// mod modulus. E.g. instead of storing [w^0, w^1, w^2, w^3], we store [w^0, w^2, w^1, w^3]
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_const_t
ccpolyzp_po2cyc_ctx_rou_powers_mul_modulus_const(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    const cc_unit *units = ccpolyzp_po2cyc_ctx_rou_powers_const(ctx, idx);
    units += ctx->dims.degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return (ccrns_mul_modulus_const_t)units;
}

/// @brief Returns the inverse root of unity powers for a given modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store the inverse root of unity powers in a manner for sequential access in the inverse NTT
CC_NONNULL_ALL CC_INLINE const cc_unit *ccpolyzp_po2cyc_ctx_inv_rou_powers_const(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    const cc_unit *inv_rous = (const cc_unit *)ccpolyzp_po2cyc_ctx_rou_powers_mul_modulus_const(ctx, idx);
    inv_rous += ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(ctx->dims.degree) * ccrns_mul_modulus_nof_n();
    return inv_rous;
}

/// @brief Returns the inverse root of unity powers for a given modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store the inverse root of unity powers in a manner for sequential access in the inverse NTT
CC_NONNULL_ALL CC_INLINE cc_unit *ccpolyzp_po2cyc_ctx_inv_rou_powers(ccpolyzp_po2cyc_ctx_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    cc_unit *inv_rous = (cc_unit *)ccpolyzp_po2cyc_ctx_rou_powers_mul_modulus(ctx, idx);
    inv_rous += ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(ctx->dims.degree) * ccrns_mul_modulus_nof_n();
    return inv_rous;
}

/// @brief Returns the inverse 2*N'th root of unity used in the NTT for the idx'th modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
CC_NONNULL_ALL CC_INLINE ccrns_int ccpolyzp_po2cyc_ctx_inv_rou(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    // Root of unity stored at index 1
    const cc_unit *inv_rou_units = ccpolyzp_po2cyc_ctx_inv_rou_powers_const(ctx, idx) + CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return ccpolyzp_po2cyc_units_to_rns_int(inv_rou_units);
}

/// @brief Returns the moduli for multiplication by the inverse root of unity powers for a given modulus
/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store the modulus for multiplication by inverse root of unity powers in a manner for sequential access
/// in the inverse NTT
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_t ccpolyzp_po2cyc_ctx_inv_rou_powers_mul_modulus(ccpolyzp_po2cyc_ctx_t ctx,
                                                                                            uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    cc_unit *units = (cc_unit *)ccpolyzp_po2cyc_ctx_inv_rou_powers(ctx, idx);
    units += ctx->dims.degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return (ccrns_mul_modulus_t)units;
}

/// @param ctx The polynomial context
/// @param idx The RNS index; must be less than ctx->dims.nmoduli
/// @details out[i] will store the modulus for multiplication by inverse root of unity powers in a manner for sequential access
/// in the inverse NTT
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_const_t
ccpolyzp_po2cyc_ctx_inv_rou_powers_mul_modulus_const(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    const cc_unit *units = (const cc_unit *)ccpolyzp_po2cyc_ctx_inv_rou_powers_const(ctx, idx);
    units += ctx->dims.degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return (ccrns_mul_modulus_const_t)units;
}

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_NTT_H_ */
