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

#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_scalar.h"
#include <corecrypto/cczp.h>

cc_size CCPOLYZP_PO2CYC_WORKSPACE_N(cc_size degree, cc_size nmoduli)
{
    struct ccpolyzp_po2cyc_dims dims = { .degree = (uint32_t)degree, .nmoduli = (uint32_t)nmoduli };
    return ccpolyzp_po2cyc_nof_n(&dims);
}

int ccpolyzp_po2cyc_init(ccpolyzp_po2cyc_t x, ccpolyzp_po2cyc_ctx_const_t context, const ccrns_int *coefficients)
{
    ccpolyzp_po2cyc_coeff_t poly = (ccpolyzp_po2cyc_coeff_t)x;
    poly->context = context;

    cc_unit *x_data = CCPOLYZP_PO2CYC_DATA(x, 0, 0);
    for (uint32_t data_idx = 0; data_idx < poly->context->dims.nmoduli * poly->context->dims.degree; ++data_idx) {
        ccpolyzp_po2cyc_rns_int_to_units(x_data, *coefficients++);
        x_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    }
    return CCERR_OK;
}

void ccpolyzp_po2cyc_init_zero(ccpolyzp_po2cyc_t x, ccpolyzp_po2cyc_ctx_const_t context)
{
    ccpolyzp_po2cyc_coeff_t poly = (ccpolyzp_po2cyc_coeff_t)x;
    poly->context = context;
    cc_size n_units = CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * poly->context->dims.nmoduli * poly->context->dims.degree;
    cc_unit *x_data = CCPOLYZP_PO2CYC_DATA(x, 0, 0);
    ccn_clear(n_units, x_data);
}

int ccpolyzp_po2cyc_modulus_to_cczp_ws(cc_ws_t ws, cczp_t cczp_modulus, ccrns_int modulus)
{
    int rv = CCERR_OK;
    CCZP_N(cczp_modulus) = CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    // Avoid assumptions about endianness on 32-bit architectures
    ccrns_int modulus_bytes;
    cc_store64_be(modulus, (uint8_t *)&modulus_bytes);

    // store and read modulus as big endian
    rv = ccn_read_uint(
        CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, CCZP_PRIME(cczp_modulus), sizeof(modulus_bytes), (uint8_t *)&modulus_bytes);
    cc_require_or_return(rv == CCERR_OK, rv);
    cc_require_or_return((rv = cczp_init_ws(ws, cczp_modulus)) == CCERR_OK, rv);
    return rv;
}

bool ccpolyzp_po2cyc_coeff_eq(ccpolyzp_po2cyc_coeff_const_t x, ccpolyzp_po2cyc_coeff_const_t y)
{
    if (!ccpolyzp_po2cyc_ctx_eq(x->context, y->context)) {
        return false;
    }

    for (uint32_t rns_idx = 0; rns_idx < x->context->dims.nmoduli; ++rns_idx) {
        for (uint32_t coeff_idx = 0; coeff_idx < x->context->dims.degree; ++coeff_idx) {
            ccrns_int x_coeff = ccpolyzp_po2cyc_coeff_data_int(x, rns_idx, coeff_idx);
            ccrns_int y_coeff = ccpolyzp_po2cyc_coeff_data_int(y, rns_idx, coeff_idx);
            if (x_coeff != y_coeff) {
                return false;
            }
        }
    }
    return true;
}

void ccpolyzp_po2cyc_eval_negate(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x)
{
    ccpolyzp_po2cyc_coeff_negate((ccpolyzp_po2cyc_coeff_t)r, (ccpolyzp_po2cyc_coeff_const_t)x);
}

void ccpolyzp_po2cyc_coeff_negate(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x)
{
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, x->context));
    uint32_t degree = x->context->dims.degree;
    uint32_t nmoduli = x->context->dims.nmoduli;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
        cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, 0);
        const cc_unit *x_data = CCPOLYZP_PO2CYC_DATA_CONST(x, rns_idx, 0);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            {
                ccrns_int x_coeff = ccpolyzp_po2cyc_units_to_rns_int(x_data);
                ccrns_int result = ccpolyzp_po2cyc_scalar_negate_mod(x_coeff, modulus);
                ccpolyzp_po2cyc_rns_int_to_units(r_data, result);

                x_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                r_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
            }
        }
    }
}

void ccpolyzp_po2cyc_eval_add(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, ccpolyzp_po2cyc_eval_const_t y)
{
    ccpolyzp_po2cyc_coeff_add((ccpolyzp_po2cyc_coeff_t)r, (ccpolyzp_po2cyc_coeff_const_t)x, (ccpolyzp_po2cyc_coeff_const_t)y);
}

void ccpolyzp_po2cyc_coeff_add(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x, ccpolyzp_po2cyc_coeff_const_t y)
{
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, x->context));
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, y->context));
    uint32_t degree = x->context->dims.degree;
    uint32_t nmoduli = x->context->dims.nmoduli;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
        cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, 0);
        const cc_unit *x_data = CCPOLYZP_PO2CYC_DATA_CONST(x, rns_idx, 0);
        const cc_unit *y_data = CCPOLYZP_PO2CYC_DATA_CONST(y, rns_idx, 0);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            {
                ccrns_int x_coeff = ccpolyzp_po2cyc_units_to_rns_int(x_data);
                ccrns_int y_coeff = ccpolyzp_po2cyc_units_to_rns_int(y_data);
                ccrns_int result = ccpolyzp_po2cyc_scalar_add_mod(x_coeff, y_coeff, modulus);
                ccpolyzp_po2cyc_rns_int_to_units(r_data, result);

                r_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                x_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                y_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
            }
        }
    }
}

void ccpolyzp_po2cyc_eval_sub(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, ccpolyzp_po2cyc_eval_const_t y)
{
    ccpolyzp_po2cyc_coeff_sub((ccpolyzp_po2cyc_coeff_t)r, (ccpolyzp_po2cyc_coeff_const_t)x, (ccpolyzp_po2cyc_coeff_const_t)y);
}

void ccpolyzp_po2cyc_coeff_sub(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x, ccpolyzp_po2cyc_coeff_const_t y)
{
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, x->context));
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, y->context));
    uint32_t degree = x->context->dims.degree;
    uint32_t nmoduli = x->context->dims.nmoduli;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
        cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, 0);
        const cc_unit *x_data = CCPOLYZP_PO2CYC_DATA_CONST(x, rns_idx, 0);
        const cc_unit *y_data = CCPOLYZP_PO2CYC_DATA_CONST(y, rns_idx, 0);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            {
                ccrns_int x_coeff = ccpolyzp_po2cyc_units_to_rns_int(x_data);
                ccrns_int y_coeff = ccpolyzp_po2cyc_units_to_rns_int(y_data);
                ccrns_int result = ccpolyzp_po2cyc_scalar_sub_mod(x_coeff, y_coeff, modulus);
                ccpolyzp_po2cyc_rns_int_to_units(r_data, result);

                r_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                x_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
                y_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
            }
        }
    }
}

void ccpolyzp_po2cyc_eval_mul(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, ccpolyzp_po2cyc_eval_const_t y)
{
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, x->context));
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, y->context));
    uint32_t degree = x->context->dims.degree;
    uint32_t nmoduli = x->context->dims.nmoduli;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_modulus_const_t modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(x->context, rns_idx);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            ccrns_int x_coeff = ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)x, rns_idx, coeff_idx);
            ccrns_int y_coeff = ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)y, rns_idx, coeff_idx);

            ccrns_int r_int = ccpolyzp_po2cyc_scalar_mul_mod(x_coeff, y_coeff, modulus);
            cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, coeff_idx);
            ccpolyzp_po2cyc_rns_int_to_units(r_data, r_int);
        }
    }
}

void ccpolyzp_po2cyc_eval_scalar_mul_ws(cc_ws_t ws, ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, const ccrns_int *y)
{
    ccpolyzp_po2cyc_coeff_scalar_mul_ws(ws, (ccpolyzp_po2cyc_coeff_t)r, (ccpolyzp_po2cyc_coeff_const_t)x, y);
}

void ccpolyzp_po2cyc_coeff_scalar_mul_ws(cc_ws_t ws,
                                         ccpolyzp_po2cyc_coeff_t r,
                                         ccpolyzp_po2cyc_coeff_const_t x,
                                         const ccrns_int *y)
{
    cc_assert(ccpolyzp_po2cyc_ctx_eq(r->context, x->context));
    uint32_t degree = x->context->dims.degree;
    uint32_t nmoduli = x->context->dims.nmoduli;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
        struct ccrns_mul_modulus mul_modulus;
        // Avoid using `ccrns_mul_modulus_init_var_time_ws`, since `y[rns_idx]` may be private
        (void)ccrns_mul_modulus_init_ws(ws, &mul_modulus, modulus, y[rns_idx]);

        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            ccrns_int x_coeff = ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)x, rns_idx, coeff_idx);
            ccrns_int r_int = ccpolyzp_po2cyc_scalar_shoup_mul_mod(x_coeff, &mul_modulus);
            cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, coeff_idx);
            ccpolyzp_po2cyc_rns_int_to_units(r_data, r_int);
        }
    }
}

int ccpolyzp_po2cyc_divide_and_round_q_last_ws(cc_ws_t ws, ccpolyzp_po2cyc_coeff_t x)
{
    int rv = CCERR_OK;
    cc_require_or_return(x->context->next != NULL, CCERR_PARAMETER);
    uint32_t degree = x->context->dims.degree;
    uint32_t nmoduli = x->context->dims.nmoduli;
    cc_require_or_return(nmoduli > 1, CCERR_PARAMETER);

    cczp_const_t q_last_zp = ccpolyzp_po2cyc_ctx_cczp_modulus_const(x->context, nmoduli - 1);
    const cc_unit *q_last_units = CCZP_PRIME(q_last_zp);

    cc_unit q_last_div_2[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_shift_right(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_last_div_2, q_last_units, 1);

    // Adds (q_last - 1) /2 to change from flooring to rounding
    {
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            cc_unit *q_last_coeff_data = CCPOLYZP_PO2CYC_DATA(x, nmoduli - 1, coeff_idx);
            cczp_add_ws(ws, q_last_zp, q_last_coeff_data, q_last_coeff_data, q_last_div_2);
        }
    }

    for (uint32_t rns_idx = 0; rns_idx < nmoduli - 1; ++rns_idx) {
        cczp_const_t q_i_zp = ccpolyzp_po2cyc_ctx_cczp_modulus_const(x->context, rns_idx);

        cc_unit q_last_div_2_mod_qi[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        cczp_modn_ws(ws, q_i_zp, q_last_div_2_mod_qi, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_last_div_2);

        // Compute q_last^{-1} mod q_i
        cc_unit inv_q_last_mod_q_i[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        cczp_modn_ws(ws, q_i_zp, inv_q_last_mod_q_i, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_last_units);
        cc_require_or_return((rv = cczp_inv_field_ws(ws, q_i_zp, inv_q_last_mod_q_i, inv_q_last_mod_q_i)) == CCERR_OK, rv);

        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            cc_unit *q_i_coeff_data = CCPOLYZP_PO2CYC_DATA(x, rns_idx, coeff_idx);
            cc_unit *q_last_coeff_data = CCPOLYZP_PO2CYC_DATA(x, nmoduli - 1, coeff_idx);

            // tmp = (x mod q_last - q_last / 2) mod q_i
            cc_unit tmp[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
            cczp_modn_ws(ws, q_i_zp, tmp, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_last_coeff_data);
            cczp_sub_ws(ws, q_i_zp, tmp, tmp, q_last_div_2_mod_qi);

            // ((x mod q_i) - (x mod q_last) + (q_last/2 mod q_i)) mod q_i
            // = (x - x mod q_last + q_last/2) mod q_i
            cczp_sub_ws(ws, q_i_zp, q_i_coeff_data, q_i_coeff_data, tmp);

            // x mod q_i <- q_last^{-1} * (x - x mod q_last + q_last/2) mod q_i
            cczp_mul_ws(ws, q_i_zp, q_i_coeff_data, q_i_coeff_data, inv_q_last_mod_q_i);
        }
    }
    // Clear memory from q_last
    cc_clear(sizeof(ccrns_int) * degree, CCPOLYZP_PO2CYC_DATA(x, nmoduli - 1, 0));

    x->context = x->context->next;
    return CCERR_OK;
}
