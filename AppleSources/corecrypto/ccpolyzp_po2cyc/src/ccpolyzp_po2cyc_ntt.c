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

#include "ccpolyzp_po2cyc_ntt.h"
#include "ccpolyzp_po2cyc_scalar.h"
#include "ccpolyzp_po2cyc_debug.h"

/// @brief Computes the lazy radix-2 butterfly
/// @param x Butterfly input/output; in [0, 4p - 1]
/// @param y Butterfly input/output; in [0, 4p - 1]
/// @param p The modulus with multiplicand root of unity power w
/// @details Computes x_out <- (x_in + w * y_in) mod p, y_out <- (x_in - w * y_in) mod p
CC_NONNULL_ALL static void fwd_butterfly_radix2(cc_unit *x, cc_unit *y, const cc_unit *w, ccrns_modulus_const_t p)
{
    ccrns_int x_int = ccpolyzp_po2cyc_units_to_rns_int(x);
    ccrns_int y_int = ccpolyzp_po2cyc_units_to_rns_int(y);
    cc_assert(x_int < p->value << 2 && y_int < p->value << 2);

    x_int = ccpolyzp_po2cyc_scalar_cond_sub(x_int, p->value << 1);
    ccrns_int w_int = ccpolyzp_po2cyc_units_to_rns_int(w);
    ccrns_int w_times_y = ccpolyzp_po2cyc_scalar_mul_mod_lazy(w_int, y_int, p);
    y_int = x_int + (p->value << 1) - w_times_y;
    x_int += w_times_y;

    cc_assert(x_int < p->value << 2 && y_int < p->value << 2);
    ccpolyzp_po2cyc_rns_int_to_units(x, x_int);
    ccpolyzp_po2cyc_rns_int_to_units(y, y_int);
}

/// @brief Computes the lazy radix-2 butterfly
/// @param x Butterfly input/output; in [0, 4p - 1]
/// @param y Butterfly input/output; in [0, 4p - 1]
/// @param p The modulus with multiplicand root of unity power w
/// @details Computes x_out <- (x_in + w * y_in) mod p, y_out <- (x_in - w * y_in) mod p
CC_NONNULL_ALL static void fwd_butterfly_radix2_shoup(cc_unit *x, cc_unit *y, ccrns_mul_modulus_const_t p)
{
    ccrns_int x_int = ccpolyzp_po2cyc_units_to_rns_int(x);
    ccrns_int y_int = ccpolyzp_po2cyc_units_to_rns_int(y);
    cc_assert(x_int < p->modulus << 2 && y_int < p->modulus << 2);

    x_int = ccpolyzp_po2cyc_scalar_cond_sub(x_int, p->modulus << 1);
    ccrns_int w_times_y = ccpolyzp_po2cyc_scalar_shoup_mul_mod_lazy(y_int, p);
    y_int = x_int + (p->modulus << 1) - w_times_y;
    x_int += w_times_y;

    cc_assert(x_int < p->modulus << 2 && y_int < p->modulus << 2);
    ccpolyzp_po2cyc_rns_int_to_units(x, x_int);
    ccpolyzp_po2cyc_rns_int_to_units(y, y_int);
}

int ccpolyzp_po2cyc_fwd_ntt(ccpolyzp_po2cyc_coeff_t poly)
{
    ccpolyzp_po2cyc_ctx_const_t ctx = poly->context;
    uint32_t n = ctx->dims.degree;
    cc_require_or_return(ctx->ntt_friendly && n > 2, CCERR_PARAMETER);

    for (uint32_t rns_idx = 0; rns_idx < ctx->dims.nmoduli; ++rns_idx) {
        ccrns_modulus_const_t modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx, rns_idx);
        ccrns_modulus_const_t rns_modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx, rns_idx);
        // Intermediate value from lazy NTT may overflow to 4 * modulus
        cc_require_or_return(rns_modulus->value < (1ULL << 62), CCERR_PARAMETER);

        const cc_unit *rou_powers = ccpolyzp_po2cyc_ctx_rou_powers_const(ctx, rns_idx);
        ccrns_mul_modulus_const_t rou_powers_mul_modulus = ccpolyzp_po2cyc_ctx_rou_powers_mul_modulus_const(ctx, rns_idx);

        cc_unit *x = CCPOLYZP_PO2CYC_DATA(poly, rns_idx, 0);
        for (uint32_t m = 1, t = n >> 1; m < n; m <<= 1, t >>= 1) {
            for (uint32_t i = 0; i < m; ++i) {
                uint32_t rou_idx = (m + i) * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                uint32_t j1 = 2 * i * t;
                if (rou_idx < ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(n)) {
                    ccrns_mul_modulus_const_t rou_mul_modulus = &rou_powers_mul_modulus[rou_idx];
                    for (uint32_t j = j1; j < j1 + t; ++j) {
                        cc_unit *x_butterfly = x + j * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        cc_unit *y_butterfly = x + (j + t) * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        fwd_butterfly_radix2_shoup(x_butterfly, y_butterfly, rou_mul_modulus);
                    }
                } else {
                    const cc_unit *rou = &rou_powers[rou_idx];
                    for (uint32_t j = j1; j < j1 + t; ++j) {
                        cc_unit *x_butterfly = x + j * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        cc_unit *y_butterfly = x + (j + t) * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        fwd_butterfly_radix2(x_butterfly, y_butterfly, rou, modulus);
                    }
                }
            }
        }
        // Reduce from [0, 4p - 1] to [0, p - 1]
        for (uint32_t i = 0; i < n; ++i) {
            ccrns_int x_int = ccpolyzp_po2cyc_units_to_rns_int(x);
            cc_assert(x_int < rns_modulus->value << 2);
            x_int = ccpolyzp_po2cyc_scalar_cond_sub(x_int, rns_modulus->value << 1);
            x_int = ccpolyzp_po2cyc_scalar_cond_sub(x_int, rns_modulus->value);
            cc_assert(x_int < rns_modulus->value);
            ccpolyzp_po2cyc_rns_int_to_units(x, x_int);
            x += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        }
    }
    return CCERR_OK;
}

/// @brief Computes the lazy radix-2 butterfly
/// @param x Butterfly input/output; in [0, 2p - 1]
/// @param y Butterfly input/output; in [0, 2p - 1]
/// @param w The inverse root of unity power
/// @param p The modulus
/// @details Computes x_out <- x_in + y_in mod p, y_out <- w * (x_in - y_in) mod p
CC_NONNULL_ALL static void inv_butterfly_radix2(cc_unit *x, cc_unit *y, const cc_unit *w, ccrns_modulus_const_t p)
{
    ccrns_int x_int = ccpolyzp_po2cyc_units_to_rns_int(x);
    ccrns_int y_int = ccpolyzp_po2cyc_units_to_rns_int(y);
    ccrns_int w_int = ccpolyzp_po2cyc_units_to_rns_int(w);
    cc_assert(x_int < p->value << 1 && y_int < p->value << 1);

    ccrns_int t = x_int + (p->value << 1) - y_int;
    x_int = ccpolyzp_po2cyc_scalar_add_mod(x_int, y_int, p->value << 1);
    y_int = ccpolyzp_po2cyc_scalar_mul_mod_lazy(t, w_int, p);

    cc_assert(x_int < p->value << 1 && y_int < p->value << 1);
    ccpolyzp_po2cyc_rns_int_to_units(x, x_int);
    ccpolyzp_po2cyc_rns_int_to_units(y, y_int);
}

/// @brief Computes the lazy radix-2 butterfly
/// @param x Butterfly input/output; in [0, 2p - 1]
/// @param y Butterfly input/output; in [0, 2p - 1]
/// @param p The modulus with multiplicand inverse root of unity power w
/// @details Computes x_out <- x_in + y_in mod p, y_out <- w * (x_in - y_in) mod p
CC_NONNULL_ALL static void inv_butterfly_radix2_shoup(cc_unit *x, cc_unit *y, ccrns_mul_modulus_const_t p)
{
    ccrns_int x_int = ccpolyzp_po2cyc_units_to_rns_int(x);
    ccrns_int y_int = ccpolyzp_po2cyc_units_to_rns_int(y);
    cc_assert(x_int < p->modulus << 1 && y_int < p->modulus << 1);

    ccrns_int t = x_int + (p->modulus << 1) - y_int;
    x_int = ccpolyzp_po2cyc_scalar_add_mod(x_int, y_int, p->modulus << 1);
    y_int = ccpolyzp_po2cyc_scalar_shoup_mul_mod_lazy(t, p);

    cc_assert(x_int < p->modulus << 1 && y_int < p->modulus << 1);
    ccpolyzp_po2cyc_rns_int_to_units(x, x_int);
    ccpolyzp_po2cyc_rns_int_to_units(y, y_int);
}

int ccpolyzp_po2cyc_inv_ntt(ccpolyzp_po2cyc_eval_t poly)
{
    ccpolyzp_po2cyc_ctx_const_t ctx = poly->context;
    uint32_t n = ctx->dims.degree;
    cc_require_or_return(ctx->ntt_friendly && n > 2, CCERR_PARAMETER);

    for (uint32_t rns_idx = 0; rns_idx < ctx->dims.nmoduli; ++rns_idx) {
        ccrns_modulus_const_t modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(ctx, rns_idx);
        // Intermediate value from lazy NTT may overflow to 2 * modulus
        cc_require_or_return(modulus->value < (1ULL << 63), CCERR_PARAMETER);

        const cc_unit *inv_rou_powers = ccpolyzp_po2cyc_ctx_inv_rou_powers_const(ctx, rns_idx);
        ccrns_mul_modulus_const_t inv_rou_powers_mul_modulus = ccpolyzp_po2cyc_ctx_inv_rou_powers_mul_modulus_const(ctx, rns_idx);
        uint32_t root_idx = 1;

        cc_unit *x = CCPOLYZP_PO2CYC_DATA(poly, rns_idx, 0);
        for (uint32_t m = n >> 1, t = 1; m > 1; m >>= 1, t <<= 1) {
            for (uint32_t i = 0; i < m; ++i, root_idx++) {
                uint32_t j1 = 2 * i * t;
                if (root_idx >= n - ccpolyzp_po2cyc_inv_ntt_mul_modulus_rou_npowers(n)) {
                    ccrns_mul_modulus_const_t inv_rou_mul_modulus = &inv_rou_powers_mul_modulus[n - root_idx - 1];
                    for (uint32_t j = j1; j < j1 + t; ++j) {
                        cc_unit *x_butterfly = x + j * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        cc_unit *y_butterfly = x + (j + t) * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        inv_butterfly_radix2_shoup(x_butterfly, y_butterfly, inv_rou_mul_modulus);
                    }
                } else {
                    const cc_unit *inv_rou_pow = &inv_rou_powers[root_idx * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
                    for (uint32_t j = j1; j < j1 + t; ++j) {
                        cc_unit *x_butterfly = x + j * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        cc_unit *y_butterfly = x + (j + t) * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                        inv_butterfly_radix2(x_butterfly, y_butterfly, inv_rou_pow, modulus);
                    }
                }
            }
        }

        // Fuse multiplication by n^{-1} with last iteration
        cc_unit *y = CCPOLYZP_PO2CYC_DATA(poly, rns_idx, n >> 1);
        ccrns_mul_modulus_const_t n_inv_w_n2 = ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const(ctx, rns_idx);
        ccrns_mul_modulus_const_t n_inv = ccpolyzp_po2cyc_ctx_inv_degree_const(ctx, rns_idx);
        for (uint32_t j = 0; j < n / 2; ++j) {
            // x_out <- n^{-1} (x_in + y_in) mod modulus
            // y_out <- n^{-1} * w (x_in - y_in) mod modulus
            ccrns_int x_int = ccpolyzp_po2cyc_units_to_rns_int(x);
            ccrns_int y_int = ccpolyzp_po2cyc_units_to_rns_int(y);

            ccrns_int tx = ccpolyzp_po2cyc_scalar_add_mod(x_int, y_int, modulus->value << 1);
            ccrns_int ty = x_int + (modulus->value << 1) - y_int;

            x_int = ccpolyzp_po2cyc_scalar_shoup_mul_mod(tx, n_inv);
            y_int = ccpolyzp_po2cyc_scalar_shoup_mul_mod(ty, n_inv_w_n2);
            ccpolyzp_po2cyc_rns_int_to_units(x, x_int);
            ccpolyzp_po2cyc_rns_int_to_units(y, y_int);

            x += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
            y += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        }
    }
    return CCERR_OK;
}
