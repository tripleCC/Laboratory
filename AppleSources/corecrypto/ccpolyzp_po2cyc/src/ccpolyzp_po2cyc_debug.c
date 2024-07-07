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

#include "ccpolyzp_po2cyc_debug.h"

void ccpolyzp_po2cyc_ctx_lprint(ccpolyzp_po2cyc_ctx_const_t context, const char *cc_cstring label)
{
    if (label) {
        cc_printf("%s ", label);
    }
    cc_printf("n=%" PRIu32 ", nmoduli=%" PRIu32 ", q=[", context->dims.degree, context->dims.nmoduli);
    for (uint32_t rns_idx = 0; rns_idx < context->dims.nmoduli; ++rns_idx) {
        ccrns_int cc_modulus = ccpolyzp_po2cyc_ctx_int_modulus(context, rns_idx);
        cc_printf("%" PRIu64 ", ", cc_modulus);
    }
    cc_printf("]\n");
}

/// Prints the polynomials context and coefficients
static void ccpolyzp_po2cyc_print_data(ccpolyzp_po2cyc_const_t x)
{
    ccpolyzp_po2cyc_coeff_const_t poly = (ccpolyzp_po2cyc_coeff_const_t)x;
    struct ccpolyzp_po2cyc_dims dims = poly->context->dims;
    ccpolyzp_po2cyc_ctx_lprint(poly->context, NULL);
    cc_printf("\tcoeffs=[\n");
    for (uint32_t rns_idx = 0; rns_idx < dims.nmoduli; ++rns_idx) {
        for (uint32_t coeff_idx = 0; coeff_idx < dims.degree; ++coeff_idx) {
            ccrns_int coeff = ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)poly, rns_idx, coeff_idx);
            cc_printf("%" PRIu64 ", ", coeff);
        }
        if (rns_idx != dims.nmoduli - 1) {
            cc_printf("\n");
        }
    }
    cc_printf("]\n");
}

void ccpolyzp_po2cyc_coeff_lprint(ccpolyzp_po2cyc_coeff_const_t x, const char *cc_cstring label)
{
    if (x->context == NULL) {
        cc_printf("Invalid polynomial; missing context\n");
        return;
    }
    if (label) {
        cc_printf("%s ", label);
    }
    cc_printf("polyzp(format=Coeff, ");
    ccpolyzp_po2cyc_print_data((ccpolyzp_po2cyc_const_t)x);
    cc_printf(")\n");
}

void ccpolyzp_po2cyc_eval_lprint(ccpolyzp_po2cyc_eval_const_t x, const char *cc_cstring label)
{
    if (x->context == NULL) {
        cc_printf("Invalid polynomial; missing context\n");
        return;
    }
    if (label) {
        cc_printf("%s ", label);
    }
    cc_printf("polyzp(format=Eval, ");
    ccpolyzp_po2cyc_print_data((ccpolyzp_po2cyc_const_t)x);
    cc_printf(")\n");
}

bool ccpolyzp_po2cyc_coeff_has_valid_data(ccpolyzp_po2cyc_coeff_const_t x)
{
    ccpolyzp_po2cyc_dims_const_t dims = &x->context->dims;
    for (uint32_t rns_idx = 0; rns_idx < dims->nmoduli; ++rns_idx) {
        ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
        for (uint32_t coeff_idx = 0; coeff_idx < dims->degree; ++coeff_idx) {
            ccrns_int coeff = ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)x, rns_idx, coeff_idx);
            if (coeff >= modulus) {
                return false;
            }
        }
    }
    return true;
}
