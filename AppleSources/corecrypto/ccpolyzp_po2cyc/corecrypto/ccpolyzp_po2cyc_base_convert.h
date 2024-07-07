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

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_BASE_CONVERT_H_
#define _CORECRYPTO_CCPOLYZP_PO2CYC_BASE_CONVERT_H_

#include "ccpolyzp_po2cyc_internal.h"

/// @brief Stores pre-computed values for approximate base conversion from an input RNS base q = q_0 * ... * q_{L-1} to an output
/// RNS base t = t_0 * ... * t_{M-1}. The input base and output bases may be of differing lengths, with L > M and L < M both
/// possible. The input and output bases may share moduli, i.e., q_i = t_j is possible.
/// @warning The input and output RNS bases are considered public, so implementations may be variable-time w.r.t. these bases
struct ccpolyzp_po2cyc_base_convert {
    // Input RNS basis q = q_0 * ... * q_{L-1}
    ccpolyzp_po2cyc_ctx_const_t input_ctx;
    // Output RNS basis t_0, ..., t_{M-1}
    ccpolyzp_po2cyc_ctx_const_t output_ctx;
    struct ccrns_mul_modulus q_mod_t0;                             // Multiplication by q % t_0, mod t_0
    cc_unit gamma_mod_t[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];         // gamma % t_0
    cc_unit gamma_inv_mod_t[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];     // gamma^{-1} % t_0
    cc_unit neg_inv_q_mod_t[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];     // -(q % t_0)^{-1} % t_0
    cc_unit neg_inv_q_mod_gamma[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]; // -(q % gamma)^{-1} % gamma
    struct ccrns_mul_modulus inv_q_last_mod_t;                     // (q_{L-1} % t_0)^{-1} % t_0
    // Let (q / q_i) denote the punctured product prod_{j=0; j != i}^{L-1} q_j.
    // Storage for
    // 1) mul_modulus for punctured products, with multiplicand (q / q_i) % t_j, modulus t_j,
    //    with 0 <= i < M, 0 <= j < L, stored at index i * L + j.
    // 2) mul_modulus for inverse punctured products, with multiplicand (q / q_i)^{-1} % q_i, modulus q_i, for 0 <= i < L
    // 3) (t_0 * gamma) % q_i for 0 <= i < L, stored as L ccrns_ints
    // 4) mul_modulus with multiplicand q_{L-1} % q_i, modulus q_i, for 0 <= i < L - 1
    // 5) mul_modulus with multiplicand (q_{L-1} % q_i)^{-1}, modulus q_i, for 0 <= i < L - 1
    cc_unit data[];
};
typedef struct ccpolyzp_po2cyc_base_convert *ccpolyzp_po2cyc_base_convert_t;
typedef const struct ccpolyzp_po2cyc_base_convert *ccpolyzp_po2cyc_base_convert_const_t;

/// gamma helps to correct base conversion error; must be co-prime to t and q and
/// chosen as large as possible to minimize error. Gamma doesn't need to be NTT-friendly, so
/// we choose a non-NTT-friendly gamma to avoid generating NTT-precomputation.
#define CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA ((1ULL << 61) - 1)

/// @brief Returns the modulus for multiplication by the punctured product (q / q_{input_rns_idx}) % t_{output_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
/// @param output_rns_idx Must be in [0, noutput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_t ccpolyzp_po2cyc_base_convert_punc_prod(ccpolyzp_po2cyc_base_convert_t base_cvt,
                                                                                    uint32_t input_rns_idx,
                                                                                    uint32_t output_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    cc_assert(output_rns_idx < base_cvt->output_ctx->dims.nmoduli);
    cc_unit *punc_prods = base_cvt->data;
    punc_prods += (base_cvt->input_ctx->dims.nmoduli * output_rns_idx + input_rns_idx) * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_t)punc_prods;
}

/// @brief Returns the modulus for multiplication by the punctured product (q / q_{input_rns_idx}) % t_{output_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
/// @param output_rns_idx Must be in [0, noutput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_const_t
ccpolyzp_po2cyc_base_convert_punc_prod_const(ccpolyzp_po2cyc_base_convert_const_t base_cvt,
                                             uint32_t input_rns_idx,
                                             uint32_t output_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    cc_assert(output_rns_idx < base_cvt->output_ctx->dims.nmoduli);
    const cc_unit *punc_prods = base_cvt->data;
    punc_prods += (base_cvt->input_ctx->dims.nmoduli * output_rns_idx + input_rns_idx) * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_const_t)punc_prods;
}

/// @brief Returns the modulus for multiplication by the inverse punctured product (q_{input_rns_idx} / q)^{-1} %
/// q_{input_rns_idx} mod q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_t ccpolyzp_po2cyc_base_convert_inv_punc_prod(ccpolyzp_po2cyc_base_convert_t base_cvt,
                                                                                        uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    cc_unit *units = (cc_unit *)ccpolyzp_po2cyc_base_convert_punc_prod(base_cvt, 0, 0);
    units += (base_cvt->input_ctx->dims.nmoduli * base_cvt->output_ctx->dims.nmoduli) * ccrns_mul_modulus_nof_n();
    units += input_rns_idx * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_t)units;
}

/// @brief Returns the modulus for multiplication by the inverse punctured product (q_{input_rns_idx} / q)^{-1} %
/// q_{input_rns_idx} mod q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_const_t
ccpolyzp_po2cyc_base_convert_inv_punc_prod_const(ccpolyzp_po2cyc_base_convert_const_t base_cvt, uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    const cc_unit *units = (const cc_unit *)ccpolyzp_po2cyc_base_convert_punc_prod_const(base_cvt, 0, 0);
    units += (base_cvt->input_ctx->dims.nmoduli * base_cvt->output_ctx->dims.nmoduli) * ccrns_mul_modulus_nof_n();
    units += input_rns_idx * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_const_t)units;
}

/// @brief Returns (t_0 * gamma) % q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_int *ccpolyzp_po2cyc_base_convert_t0_gamma_mod_qi(ccpolyzp_po2cyc_base_convert_t base_cvt,
                                                                                 uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    cc_unit *units = (cc_unit *)ccpolyzp_po2cyc_base_convert_inv_punc_prod(base_cvt, 0);
    units += base_cvt->input_ctx->dims.nmoduli * ccrns_mul_modulus_nof_n();
    units += input_rns_idx * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return (ccrns_int *)units;
}

/// @brief Returns (t_0 * gamma) % q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL const ccrns_int *
ccpolyzp_po2cyc_base_convert_t0_gamma_mod_qi_const(ccpolyzp_po2cyc_base_convert_const_t base_cvt, uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    const cc_unit *units = (const cc_unit *)ccpolyzp_po2cyc_base_convert_inv_punc_prod_const(base_cvt, 0);
    units += base_cvt->input_ctx->dims.nmoduli * ccrns_mul_modulus_nof_n();
    units += input_rns_idx * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return (const ccrns_int *)units;
}

/// @brief Returns q_{L-1} % q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_t ccpolyzp_po2cyc_base_convert_q_last_mod_qi(ccpolyzp_po2cyc_base_convert_t base_cvt,
                                                                                        uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    cc_unit *units = (cc_unit *)ccpolyzp_po2cyc_base_convert_t0_gamma_mod_qi(base_cvt, 0);
    units += base_cvt->input_ctx->dims.nmoduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    units += input_rns_idx * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_t)units;
}

/// @brief Returns q_{L-1} % q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_const_t
ccpolyzp_po2cyc_base_convert_q_last_mod_qi_const(ccpolyzp_po2cyc_base_convert_const_t base_cvt, uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    const cc_unit *units = (const cc_unit *)ccpolyzp_po2cyc_base_convert_t0_gamma_mod_qi_const(base_cvt, 0);
    units += base_cvt->input_ctx->dims.nmoduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    units += input_rns_idx * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_const_t)units;
}

/// @brief Returns q_{L-1}^{-1} % q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_t
ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi(ccpolyzp_po2cyc_base_convert_t base_cvt, uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    cc_unit *units = (cc_unit *)ccpolyzp_po2cyc_base_convert_q_last_mod_qi(base_cvt, 0);
    units += (base_cvt->input_ctx->dims.nmoduli - 1) * ccrns_mul_modulus_nof_n();
    units += input_rns_idx * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_t)units;
}

/// @brief Returns q_{L-1}^{-1} % q_{input_rns_idx}
/// @param base_cvt Base converter
/// @param input_rns_idx Must be in [0, ninput_moduli - 1]
CC_INLINE CC_NONNULL_ALL ccrns_mul_modulus_const_t
ccpolyzp_po2cyc_base_convert_inv_q_last_mod_qi_const(ccpolyzp_po2cyc_base_convert_const_t base_cvt, uint32_t input_rns_idx)
{
    cc_assert(input_rns_idx < base_cvt->input_ctx->dims.nmoduli);
    const cc_unit *units = (const cc_unit *)ccpolyzp_po2cyc_base_convert_q_last_mod_qi_const(base_cvt, 0);
    units += (base_cvt->input_ctx->dims.nmoduli - 1) * ccrns_mul_modulus_nof_n();
    units += input_rns_idx * ccrns_mul_modulus_nof_n();
    return (ccrns_mul_modulus_const_t)units;
}

/// @brief Returns the number of cc_units required to store ccpolyzp_po2cyc_base_convert
/// @param ninput_moduli Number of moduli in the input RNS base; must be > 0
/// @param noutput_moduli Number of moduli in the output RNS base; must be > 0
CC_INLINE cc_size ccpolyzp_po2cyc_base_convert_nof_n(uint32_t ninput_moduli, uint32_t noutput_moduli)
{
    cc_assert(ninput_moduli > 0);
    cc_assert(noutput_moduli > 0);
    // struct storage, rounded up to nearest number of cc_units
    cc_size rv = cc_ceiling(sizeof_struct_ccpolyzp_po2cyc_base_convert(), sizeof_cc_unit());

    rv += ninput_moduli * noutput_moduli * ccrns_mul_modulus_nof_n(); // punctured products
    rv += ninput_moduli * ccrns_mul_modulus_nof_n();                  // inverse punctured products mul modulus
    rv += ninput_moduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;           // (t_0 * gamma) % q_i
    rv += (ninput_moduli - 1) * ccrns_mul_modulus_nof_n();            // (q_{L-1} % q_i)
    rv += (ninput_moduli - 1) * ccrns_mul_modulus_nof_n();            // (q_{L-1} % q_i)^-1
    return rv;
}

/// @brief Allocates memory for a ccpolyzp_po2cyc_base_convert_t
/// @param ws Workspace to allocate memory from
/// @param ninput_moduli The number of moduli in the input RNS basis
/// @param noutput_moduli The number of moduli in the output RNS basis
/// @return The allocated memory
#define CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS(ws, ninput_moduli, noutput_moduli) \
    (ccpolyzp_po2cyc_base_convert_t) CC_ALLOC_WS(ws, ccpolyzp_po2cyc_base_convert_nof_n((ninput_moduli), (noutput_moduli)))

/// @brief Initializes a base converter
/// @param ws Workspace
/// @param base_cvt The base converter to initialize; should be allocated using CCPOLYZP_PO2CYC_BASE_CONVERT_ALLOC_WS
/// @param input_ctx The context for the input RNS basis
/// @param output_ctx The context for the output RNS basis
/// @return CCERR_OK if base converter is successfully initialized
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_base_convert_init_ws(cc_ws_t ws,
                                                                       ccpolyzp_po2cyc_base_convert_t base_cvt,
                                                                       ccpolyzp_po2cyc_ctx_const_t input_ctx,
                                                                       ccpolyzp_po2cyc_ctx_const_t output_ctx);

/// @brief Performs approximate base conversion from x to r
/// @param ws Workspace
/// @param r The output polynomial; must have context matching the base converter's output context
/// @param x The input polynomial; must have context matching the base converter's input context
/// @param base_cvt The base converter to perform the base conversion
/// @return CCERR_OK if base conversion is successful
/// @details Each coefficient r_coeff of r will store an approximate value of the corresponding coefficient x_coeff in x. Instead
/// of computing r_coeff := x_coeff % t, this computes r_coeff: (x + alpha_x * q) % t for some integer x_alpha in [0, L - 1].
/// r and x may not overlap
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_base_convert_poly_ws(cc_ws_t ws,
                                                                       ccpolyzp_po2cyc_coeff_t r,
                                                                       ccpolyzp_po2cyc_coeff_const_t x,
                                                                       ccpolyzp_po2cyc_base_convert_const_t base_cvt);

/// @brief Performs exact base conversion from x to r
/// @param ws Workspace
/// @param r The output polynomial; must have single-modulus context matching the base converter's output context chain context
/// with one modulus
/// @param x The input polynomial; must have context matching the base converter's input context, and not overlap with x
/// @param base_cvt The base converter to perform the base conversion
/// @return CCERR_OK if base conversion is successful
/// @details Each coefficient r_coeff of r will store the corresponding coefficient x_coeff % t for x_coeff in x.
/// More precisely, let input coefficient `x` in `[-q/2, q/2)`, represented using integers in `[0, q)`, and denoted by `[x]_q`.
/// Then, the output is `[x]_t` in `[-t/2, t/2)`, represented by integers in `[0, t)`.
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_base_convert_exact_poly_ws(cc_ws_t ws,
                                                                             ccpolyzp_po2cyc_coeff_t r,
                                                                             ccpolyzp_po2cyc_coeff_const_t x,
                                                                             ccpolyzp_po2cyc_base_convert_const_t base_cvt);

/// @brief Performs coefficient-wise division and rounding
/// @param ws Workspace
/// @param r The output polynomial; must have single modulus, t
/// @param x The input polynmomial; must have context matching base_cvt's input context
/// @param base_cvt The base converter; must have output context [t, CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA] for
/// t != CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA
/// @return CCERR_OK if successful
/// @details r := round(t / q * x) % t
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_base_convert_divide_and_round_ws(cc_ws_t ws,
                                                                                   ccpolyzp_po2cyc_coeff_t r,
                                                                                   ccpolyzp_po2cyc_coeff_const_t x,
                                                                                   ccpolyzp_po2cyc_base_convert_const_t base_cvt);

/// @brief Performs coefficient-wise division and rounding by the last modulus in the chain
/// @param ws Workspace
/// @param r The polynomial
/// @param base_cvt The base converter; must have input context r->context and output context t
/// CCPOLYZP_PO2CYC_BASE_CONVERT_GAMMA
/// @return CCERR_OK if successful
CC_NONNULL_ALL CC_WARN_RESULT int
ccpolyzp_po2cyc_base_convert_mod_t_divide_and_round_q_last_ws(cc_ws_t ws,
                                                              ccpolyzp_po2cyc_eval_t r,
                                                              ccpolyzp_po2cyc_base_convert_const_t base_cvt);

/// @brief Computes `scale * q_last^{-1} mod t_0`
/// @param scale Scale
/// @param base_cvt The base converter
/// @returns  `scale * q_last^{-1} mod t_0`
CC_NONNULL_ALL CC_INLINE ccrns_int
ccpolyzp_po2cyc_base_convert_scale_inv_q_last_mod_t(ccrns_int scale, ccpolyzp_po2cyc_base_convert_const_t base_cvt)
{
    return ccpolyzp_po2cyc_scalar_shoup_mul_mod(scale, &base_cvt->inv_q_last_mod_t);
}

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_BASE_CONVERT_H_ */
