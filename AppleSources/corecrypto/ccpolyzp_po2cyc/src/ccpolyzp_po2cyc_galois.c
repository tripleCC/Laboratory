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

#include "ccpolyzp_po2cyc_galois.h"
#include "ccpolyzp_po2cyc_scalar.h"

/// @brief Iterator for the Galois transformation f(x) -> f(x^{galois_elt}) on polynomials in coefficient format
/// The iterator steps over powers of x: x^0, x^1, x^2, ..., x^{N-1} and computes the powers of the transformed x:
/// x^{0 * galois_elt}, x^{1 * galois_elt}, x^{2 * galois_elt}, ..., x^{(N-1) * galois_elt}
struct galois_coeff_iterator {
    uint32_t degree;          // Polynomial degree, N
    uint32_t log2_degree;     // log2(N)
    uint32_t mod_degree_mask; // N - 1; used for fast reduction mod N
    uint32_t galois_elt;      // Galois element
    uint32_t iter_index;      // Current power of x in f(x)
    uint32_t raw_out_index;   // Internal helper index
    uint32_t out_index;       // Index of x^{iter_idx * galois_elt} in f(x^{galois_elt})
};
typedef struct galois_coeff_iterator *galois_coeff_iterator_t;
typedef const struct galois_coeff_iterator *galois_coeff_iterator_const_t;

/// @brief Initializes a Galois coefficient iterator
/// @param galois_coeff_iter The Galois coefficient iterator to initialize
/// @param degree The degree N of the polynomial
/// @param galois_elt The Galois element for the transformation; must be odd in [3, 2 * N - 1]
/// @return CCERR_OK if successful
CC_WARN_RESULT static int
galois_coeff_iterator_init(galois_coeff_iterator_t galois_coeff_iter, uint32_t degree, uint32_t galois_elt)
{
    cc_require_or_return(is_valid_galois_element_and_degree(galois_elt, degree), CCERR_PARAMETER);
    galois_coeff_iter->degree = degree;
    galois_coeff_iter->log2_degree = ccpolyzp_po2cyc_log2_uint32(degree);
    galois_coeff_iter->mod_degree_mask = degree - 1;
    galois_coeff_iter->galois_elt = galois_elt;
    galois_coeff_iter->iter_index = 0;
    galois_coeff_iter->raw_out_index = 0;
    galois_coeff_iter->out_index = 0; // x^{0 * galois_elt} = x^0

    return CCERR_OK;
}

/// @brief Increments the Galois coefficient iterator by one step
/// @param next Will store the output index
/// @param negate Whether or not the output should be negated
/// @param galois_coeff_iter The Galois coefficient iterator
/// @return CCERR_OK if successful
CC_WARN_RESULT static int galois_coeff_iterator_next(uint32_t *next, bool *negate, galois_coeff_iterator_t galois_coeff_iter)
{
    cc_require_or_return(galois_coeff_iter->iter_index < galois_coeff_iter->degree, CCERR_PARAMETER);
    // negate = true iff raw_out_index % 2N in [N, 2N - 1], since x^(2N*k + N) = -1 in R_q for any k >= 0
    *negate = (bool)((galois_coeff_iter->raw_out_index >> galois_coeff_iter->log2_degree) & 1);
    *next = galois_coeff_iter->out_index;
    // x^{iter_idx} -> x^{raw_out_idx} = x^{iter_idx * galois_elt}
    galois_coeff_iter->raw_out_index += galois_coeff_iter->galois_elt;
    // Reduce using x^N == -1
    galois_coeff_iter->out_index = galois_coeff_iter->raw_out_index & galois_coeff_iter->mod_degree_mask;
    galois_coeff_iter->iter_index++;

    return CCERR_OK;
}

int ccpolyzp_po2cyc_coeff_apply_galois(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x, uint32_t galois_elt)
{
    int rv = CCERR_OK;
    cc_require_or_return(r != x, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(r->context, x->context), CCERR_PARAMETER);
    uint32_t degree = x->context->dims.degree;
    cc_require_or_return(is_valid_galois_element_and_degree(galois_elt, degree), CCERR_PARAMETER);

    uint32_t nmoduli = x->context->dims.nmoduli;
    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
        const cc_unit *x_data = CCPOLYZP_PO2CYC_DATA_CONST(x, rns_idx, 0);

        struct galois_coeff_iterator galois_coeff_iter;
        cc_require((rv = galois_coeff_iterator_init(&galois_coeff_iter, degree, galois_elt)) == CCERR_OK, errOut);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            uint32_t out_idx;
            bool negate;
            cc_require((rv = galois_coeff_iterator_next(&out_idx, &negate, &galois_coeff_iter)) == CCERR_OK, errOut);
            cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, out_idx);
            ccrns_int x_int = ccpolyzp_po2cyc_units_to_rns_int(x_data);
            ccrns_int neg_x_int = ccpolyzp_po2cyc_scalar_negate_mod(x_int, modulus);

            ccrns_int r_int;
            CC_MUXU(r_int, (ccrns_int)negate, neg_x_int, x_int);

            ccpolyzp_po2cyc_rns_int_to_units(r_data, r_int);
            x_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        }
    }

errOut:
    return rv;
}

/// @brief Iterator for Galois transformation on polynomials in evaluation format
struct galois_eval_iterator {
    uint32_t degree;          // polynomial degree, N
    uint32_t log2_degree;     // log2(N)
    uint32_t mod_degree_mask; // N - 1; used for fast reduction mod N
    uint32_t galois_elt;      // Galois element 
    uint32_t iter_index;      // Current power of x in f(x)
};
typedef struct galois_eval_iterator *galois_eval_iterator_t;
typedef const struct galois_eval_iterator *galois_eval_iterator_const_t;

/// @brief Initializes a Galois evaluation iterator
/// @param galois_eval_iter The Galois evaluation iterator to initialize
/// @param degree The degree N of the polynomial
/// @param galois_elt The Galois element for the transformation; must be odd in [3, 2 * N - 1]
/// @return CCERR_OK if successful
CC_WARN_RESULT static int galois_eval_iterator_init(galois_eval_iterator_t galois_eval_iter, uint32_t degree, uint32_t galois_elt)
{
    cc_require_or_return(is_valid_galois_element_and_degree(galois_elt, degree), CCERR_PARAMETER);
    galois_eval_iter->degree = degree;
    galois_eval_iter->log2_degree = ccpolyzp_po2cyc_log2_uint32(degree);
    galois_eval_iter->mod_degree_mask = degree - 1;
    galois_eval_iter->galois_elt = galois_elt;
    galois_eval_iter->iter_index = 0;

    return CCERR_OK;
}

/// @brief Increments the Galois evaluation iterator by one step
/// @param galois_eval_iter The Galois evaluation iterator
/// @return  CCERR_OK if successful
CC_WARN_RESULT static int galois_eval_iterator_next(uint32_t *next, galois_eval_iterator_t galois_eval_iter)
{
    cc_require_or_return(galois_eval_iter->iter_index < galois_eval_iter->degree, CCERR_PARAMETER);
    uint32_t reverse_degree =
        ccpolyzp_po2cyc_reverse_bits(galois_eval_iter->iter_index + galois_eval_iter->degree, galois_eval_iter->log2_degree + 1);

    uint64_t index_raw = ((uint64_t)galois_eval_iter->galois_elt * (uint64_t)reverse_degree) >> 1;
    index_raw &= (uint64_t)(galois_eval_iter->mod_degree_mask);
    galois_eval_iter->iter_index++;
    *next = ccpolyzp_po2cyc_reverse_bits((uint32_t)index_raw, galois_eval_iter->log2_degree);
    return CCERR_OK;
}

int ccpolyzp_po2cyc_eval_apply_galois(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, uint32_t galois_elt)
{
    int rv = CCERR_OK;
    cc_require_or_return(r != x, CCERR_PARAMETER);
    cc_require_or_return(ccpolyzp_po2cyc_ctx_eq(r->context, x->context), CCERR_PARAMETER);
    uint32_t degree = x->context->dims.degree;
    cc_require_or_return(is_valid_galois_element_and_degree(galois_elt, degree), CCERR_PARAMETER);

    uint32_t nmoduli = x->context->dims.nmoduli;
    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        cc_unit *r_data = CCPOLYZP_PO2CYC_DATA(r, rns_idx, 0);
        struct galois_eval_iterator galois_eval_iter;
        cc_require((rv = galois_eval_iterator_init(&galois_eval_iter, degree, galois_elt)) == CCERR_OK, errOut);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            uint32_t out_idx;
            cc_require((rv = galois_eval_iterator_next(&out_idx, &galois_eval_iter)) == CCERR_OK, errOut);
            const cc_unit *x_data = CCPOLYZP_PO2CYC_DATA_CONST(x, rns_idx, out_idx);
            ccn_set(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, r_data, x_data);
            r_data += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        }
    }

errOut:
    return rv;
}
