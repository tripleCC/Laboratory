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

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_INTERNAL_H_
#define _CORECRYPTO_CCPOLYZP_PO2CYC_INTERNAL_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccn.h>
#include "cc_memory.h"
#include "cc_workspaces.h"
#include "cczp_internal.h"
#include "ccpolyzp_po2cyc_scalar.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// Stores the pre-computed values for doing efficient calculations on polynomials in
/// R_q = Z_q(X)^N / (X^N + 1) for N a power of two and q a (possibly) multi-word integer.
/// q is represented in residue number system (RNS) form using the Chinese remainder theorem (CRT)
/// and ordered co-prime moduli q = q_0 * q_1 * ... * q_{L-1}, with each q_i < CCPOLYZP_PO2CYC_MAX_MODULUS
/// Note, the moduli are "ordered", meaning order matters, but not sorted.
/// That is, q_{i+1} > q_i is possible, and sometimes desired.
/// The context should be considered public, so functions may not be constant-time with respect to the degree `N` or the moduli
/// `q_i`.
///
/// Functions returning cc_unit* are suitable for use with cczp operations. Functions returning ccrns_int are suitable for
/// printing / debugging. On 32-bit architectures, the two representations may not be the same.
struct ccpolyzp_po2cyc_ctx {
    /// Dimensions of the polynomial
    struct ccpolyzp_po2cyc_dims {
        uint32_t degree;  /// N
        uint32_t nmoduli; /// L
    } dims;
    /// Whether or not all moduli are NTT-friendly, i.e. satisfy q_i = 1 mod 2 N
    bool ntt_friendly;
    struct ccrns_modulus ccrns_q_last; /// Pre-computed values for q_L
    /// For NTT-friendly context, pre-computation for multiplication with N^{-1} * w^{-N/2} mod q_last where w is a root of unity
    struct ccrns_mul_modulus inv_rou_power_n2_q_last;
    /// For NTT-friendly context, pre-computation for multiplication with N^{-1} mod q_last where w is a root of unity
    struct ccrns_mul_modulus inv_degree_q_last;
    struct ccpolyzp_po2cyc_ctx *next; /// The next context
    /// Storage for values for the last modulus, q_L:
    /// 1) q_L, stored as a cczp with 64 bits
    /// 2) root of unity powers (cc_unit[N * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] )
    /// 3) mul_modulus for root of unity powers (ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(N) * ccrns_mul_modulus)
    /// 4) inverse root of unity powers (cc_unit[N * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] )
    /// 5) mul_modulus for inverse root of unity powers (ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(N) * ccrns_mul_modulus)
    cc_unit data[];
} CC_ALIGNED(CCN_UNIT_SIZE);
typedef struct ccpolyzp_po2cyc_dims *ccpolyzp_po2cyc_dims_t;
typedef const struct ccpolyzp_po2cyc_dims *ccpolyzp_po2cyc_dims_const_t;

typedef struct ccpolyzp_po2cyc_ctx *ccpolyzp_po2cyc_ctx_t;
typedef const struct ccpolyzp_po2cyc_ctx *ccpolyzp_po2cyc_ctx_const_t;

/// @brief Maximum polynomial degree supported
/// @details Arbitrary limit, but larger degrees are unlikely in practice
#define CCPOLYZP_PO2CYC_DEGREE_MAX (1 << 20)

/// @brief Maximum number of moduli supported
/// @details Arbitrary limit, but larger number of moduli are unlikely in practice
#define CCPOLYZP_PO2CYC_NMODULI_MAX (10)

/// @brief Ensure polynomial is a reasonable size
cc_static_assert(CCPOLYZP_PO2CYC_DEGREE_MAX *CCPOLYZP_PO2CYC_NMODULI_MAX < (1 << 30),
                 "ccpolyzp_po2cyc context dimensions (degree, number of moduli) may exceed 2^30");

/// @brief Returns the number of forward NTT root of unity mul_modulus factors to pre-compute
/// @param degree Polynomial degree
/// @details Pre-computing a larger number of factors speeds up the FwdNTT, at the cost of more memory usage.
CC_INLINE uint32_t ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(uint32_t degree)
{
    return CC_MIN(degree, (uint32_t)128);
}

/// @brief Returns the number of inverse NTT root of unity mul_modulus factors to pre-compute
/// @details Pre-computing a larger number of factors speeds up the InvNTT, at the cost of more memory usage
/// @param degree Polynomial degree
CC_INLINE uint32_t ccpolyzp_po2cyc_inv_ntt_mul_modulus_rou_npowers(uint32_t degree)
{
    return CC_MIN(degree, (uint32_t)128);
}

/// @brief Returns whether or not a degree is valid for a polynomial context
/// @param n Degree
CC_INLINE bool ccpolyzp_po2cyc_ctx_is_valid_degree(uint32_t n)
{
    return ccpolyzp_po2cyc_is_power_of_two_uint32(n) && n <= CCPOLYZP_PO2CYC_DEGREE_MAX;
}

/// @brief Returns whether or not the number of moduli is valid for a polynomial context
/// @param n Number of moduli
CC_INLINE bool ccpolyzp_po2cyc_ctx_is_valid_nmoduli(uint32_t n)
{
    return n > 0 && n <= CCPOLYZP_PO2CYC_NMODULI_MAX;
}

/// @brief Returns whether or not the dimensions are valid for a polynomial context
/// @param dims Dimensions
CC_INLINE CC_NONNULL_ALL bool ccpolyzp_po2cyc_ctx_is_valid_dims(ccpolyzp_po2cyc_dims_const_t dims)
{
    return ccpolyzp_po2cyc_ctx_is_valid_degree(dims->degree) && ccpolyzp_po2cyc_ctx_is_valid_nmoduli(dims->nmoduli);
}

/// @brief Initializes the context with the given moduli and dimensions
/// @param ws Workspace
/// @param context The context to initialize
/// @param dims The dimensions for the context
/// @param moduli The moduli q_0, ..., q_{L-1}; must be unique primes and < CCPOLYZP_PO2CYC_MAX_MODULUS
/// @param next_context The next context, with moduli q_0, ..., q_{L-2}.
/// Should be NULL iff L=1, i.e. only one modulus in the chain.
/// @return CCERR_OK if context is properly initialized
CC_NONNULL((1, 2, 3, 4))
int ccpolyzp_po2cyc_ctx_init_ws(cc_ws_t ws,
                                ccpolyzp_po2cyc_ctx_t context,
                                ccpolyzp_po2cyc_dims_const_t dims,
                                const ccrns_int *moduli,
                                const ccpolyzp_po2cyc_ctx_t next_context);

/// Returns the cczp representation of q_L
#define CCPOLYZP_PO2CYC_CTX_CCZP_MODULI(ctx) ((cczp_t)((ctx)->data))
#define CCPOLYZP_PO2CYC_CTX_CCZP_MODULI_CONST(ctx) ((cczp_const_t)((ctx)->data))

/// @brief Returns the child context with moduli q_0, ..., q_{idx}
/// @param context The context whose child context to return
/// @param idx The RNS index; must be less than context->dims.nmoduli
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_t ccpolyzp_po2cyc_ctx_idx(ccpolyzp_po2cyc_ctx_t context, uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_t cur_context = context;
    for (uint32_t cur_idx = cur_context->dims.nmoduli - 1; cur_idx > idx; --cur_idx) {
        cc_assert(cur_context->next != NULL);
        cur_context = cur_context->next;
    }
    return cur_context;
}

/// @brief Returns the child context with moduli q_0, ..., q_{idx}
/// @param context The context whose child context to return
/// @param idx The RNS index; must be less than context->dims.nmoduli
CC_NONNULL_ALL CC_INLINE ccpolyzp_po2cyc_ctx_const_t ccpolyzp_po2cyc_ctx_idx_const(ccpolyzp_po2cyc_ctx_const_t context,
                                                                                   uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_const_t cur_context = context;
    for (uint32_t cur_idx = cur_context->dims.nmoduli - 1; cur_idx > idx; --cur_idx) {
        cc_assert(cur_context->next != NULL);
        cur_context = cur_context->next;
    }
    return cur_context;
}

/// @brief Returns the RNS modulus q_idx
/// @param context The context whose moduli to retrieve from
/// @param idx The RNS index
CC_NONNULL_ALL CC_INLINE cczp_t ccpolyzp_po2cyc_ctx_cczp_modulus(ccpolyzp_po2cyc_ctx_t context, uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_t rns_ctx = ccpolyzp_po2cyc_ctx_idx(context, idx);
    cc_unit *cczp_moduli = (cc_unit *)CCPOLYZP_PO2CYC_CTX_CCZP_MODULI(rns_ctx);
    return (cczp_t)cczp_moduli;
}

/// @brief Returns the RNS modulus q_idx
/// @param context The context whose moduli to retrieve from
/// @param idx The RNS index
CC_NONNULL_ALL CC_INLINE cczp_const_t ccpolyzp_po2cyc_ctx_cczp_modulus_const(ccpolyzp_po2cyc_ctx_const_t context, uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_const_t rns_ctx = ccpolyzp_po2cyc_ctx_idx_const(context, idx);
    const cc_unit *cczp_moduli = (const cc_unit *)CCPOLYZP_PO2CYC_CTX_CCZP_MODULI_CONST(rns_ctx);
    return (cczp_const_t)cczp_moduli;
}

/// @brief Returns the modulus for multiplication by w^{-N/2} % q_{idx}
/// @param context The context
/// @param idx The RNS index
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_const_t ccpolyzp_po2cyc_ctx_inv_rou_power_n2_const(ccpolyzp_po2cyc_ctx_const_t context,
                                                                                              uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    return &ccpolyzp_po2cyc_ctx_idx_const(context, idx)->inv_rou_power_n2_q_last;
}

/// @brief Returns the modulus for multiplication by w^{-N/2} % q_{idx}
/// @param context The context
/// @param idx The RNS index
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_t ccpolyzp_po2cyc_ctx_inv_rou_power_n2(ccpolyzp_po2cyc_ctx_t context, uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    return &ccpolyzp_po2cyc_ctx_idx(context, idx)->inv_rou_power_n2_q_last;
}

/// @brief Returns the modulus for multiplication by N^{-1} % q_{idx}
/// @param context The context
/// @param idx The RNS index
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_const_t ccpolyzp_po2cyc_ctx_inv_degree_const(ccpolyzp_po2cyc_ctx_const_t context,
                                                                                        uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    return &ccpolyzp_po2cyc_ctx_idx_const(context, idx)->inv_degree_q_last;
}

/// @brief Returns the modulus for multiplication by N^{-1} % q_{idx}
/// @param context The context
/// @param idx The RNS index
CC_NONNULL_ALL CC_INLINE ccrns_mul_modulus_t ccpolyzp_po2cyc_ctx_inv_degree(ccpolyzp_po2cyc_ctx_t context, uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    return &ccpolyzp_po2cyc_ctx_idx(context, idx)->inv_degree_q_last;
}

/// @brief Returns an upper bound on the number of cc_units required to store the product of RNS moduli: q = q_0 * ... * q_{L-1}
/// @param nmoduli The number of moduli, L
CC_WARN_RESULT CC_INLINE cc_size ccpolyzp_po2cyc_ctx_q_prod_nof_n(uint32_t nmoduli)
{
    return nmoduli * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
}

/// @brief Computes the product of RNS moduli: q = q_0 * ... * q_{L-1}
/// @param ws Workspace
/// @param context The context whose modulus to return
/// @param q_prod Will be populated with the product q; should be allocated with
/// ccpolyzp_po2cyc_ctx_q_prod_nof_n(L) units
CC_NONNULL_ALL void ccpolyzp_po2cyc_ctx_q_prod_ws(cc_ws_t ws, cc_unit *q_prod, ccpolyzp_po2cyc_ctx_const_t context);

/// @brief Converts a cczp modulus to a ccrns_int
/// @param zp The modulus.
/// @returns The ccrns_int representation of the modulus
CC_NONNULL_ALL CC_INLINE ccrns_int ccpolyzp_po2cyc_modulus_to_rns_int(cczp_const_t zp)
{
    const uint8_t *mod_units = (const uint8_t *)cczp_prime(zp);
    ccrns_int rns_modulus;
    // Read modulus as big endian, then convert to host representation
    ccn_read_uint(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, (cc_unit *)&rns_modulus, sizeof(rns_modulus), mod_units);
    return CC_H2BE64(rns_modulus);
}

/// @brief Returns the RNS modulus q_idx
/// @param context The context whose moduli to retrieve from
/// @param idx The RNS index
CC_NONNULL_ALL
CC_INLINE ccrns_modulus_const_t ccpolyzp_po2cyc_ctx_ccrns_modulus(ccpolyzp_po2cyc_ctx_const_t context, uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    ccpolyzp_po2cyc_ctx_const_t rns_ctx = ccpolyzp_po2cyc_ctx_idx_const(context, idx);
    return (ccrns_modulus_const_t)&rns_ctx->ccrns_q_last;
}

/// @brief Returns the RNS modulus q_idx
/// @param context The context whose moduli to retrieve from
/// @param idx The RNS index
CC_NONNULL_ALL CC_INLINE ccrns_int ccpolyzp_po2cyc_ctx_int_modulus(ccpolyzp_po2cyc_ctx_const_t context, uint32_t idx)
{
    cc_assert(idx < context->dims.nmoduli);
    ccrns_modulus_const_t modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(context, idx);
    return modulus->value;
}

/// @brief Converts a prime modulus to a cczp type
/// @param ws Workspace
/// @param cczp_modulus The cczp_t modulus to populate
/// @param modulus The modulus value to convert; must be prime
/// @return CCERR_OK if successful
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_modulus_to_cczp_ws(cc_ws_t ws, cczp_t cczp_modulus, ccrns_int modulus);

// MARK: - Workspace helpers

/// @brief Returns the number of cc_units required to allocate a context with the given degree
/// @param degree The degree N of the polynomial context
CC_INLINE cc_size ccpolyzp_po2cyc_ctx_nof_n(uint32_t degree)
{
    // struct storage, rounded up to nearest number of cc_units
    cc_size rv = ccn_nof_size(sizeof_struct_ccpolyzp_po2cyc_ctx());
    rv += cczp_nof_n(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF); // cczp storage for q_L
    rv += degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;    // root of unity powers for q_L
    // mul_modulus root of unity powers for q_L
    rv += ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(degree) * ccrns_mul_modulus_nof_n();
    rv += degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF; // inverse root of unity powers for q_L
    // mul_modulus inverse root of unity powers for q_L
    rv += ccpolyzp_po2cyc_inv_ntt_mul_modulus_rou_npowers(degree) * ccrns_mul_modulus_nof_n();
    return rv;
}

/// @brief Allocates memory for a ccpolyzp_po2cyc_ctxt
/// @param ws Workspace to allocate memory from
/// @param degree The polynomial degree N
/// @return The allocated memory
#define CCPOLYZP_PO2CYC_CTX_ALLOC_WS(ws, degree) (ccpolyzp_po2cyc_ctx_t) CC_ALLOC_WS(ws, ccpolyzp_po2cyc_ctx_nof_n((degree)))

/// @brief Compares two dimensions. Not constant-time
/// @param x A dimension object to compare
/// @param y A dimension object to compare
/// @return true if the dimension objects are equal, false else
CC_NONNULL_ALL CC_WARN_RESULT bool ccpolyzp_po2cyc_dims_eq(ccpolyzp_po2cyc_dims_const_t x, ccpolyzp_po2cyc_dims_const_t y);

/// @brief Compares two contexts. Not constant-time
/// @param x A context to compare
/// @param y A context to compare
/// @return true if the contexts are equal (not including the derived context chain), false else
CC_NONNULL_ALL CC_WARN_RESULT bool ccpolyzp_po2cyc_ctx_eq(ccpolyzp_po2cyc_ctx_const_t x, ccpolyzp_po2cyc_ctx_const_t y);

/// @brief Copies a context to another context
/// @param r The context to copy to
/// @param x The context to copy from
CC_INLINE CC_NONNULL_ALL void ccpolyzp_po2cyc_ctx_copy(ccpolyzp_po2cyc_ctx_t r, ccpolyzp_po2cyc_ctx_const_t x)
{
    cc_memmove(r, x, ccn_sizeof_n(ccpolyzp_po2cyc_ctx_nof_n(x->dims.degree)));
}

/// @brief Check if the one context is in the same chain as another context
/// @param parent A parent context
/// @param child A child context
/// @return true if recursively following `parent->next` leads to child context
/// @details This uses pointer equivalence, so it will only return true with polynomial contexts that are in the same
/// context chain.
CC_NONNULL_ALL CC_WARN_RESULT bool ccpolyzp_po2cyc_ctx_is_parent(ccpolyzp_po2cyc_ctx_const_t parent,
                                                                 ccpolyzp_po2cyc_ctx_const_t child);

/// Data is a pointer to variable-length buffer for the coefficients which
/// stores the coefficients in RNS-major order, i.e. [x_0 mod q_0, x_0 mod q_1, ..., x_0 mod q_{L-1}, x_1 mod q_0, ...]
#define __CCPOLYZP_PO2CYC_ELEMENTS_DEFINITION \
    ccpolyzp_po2cyc_ctx_const_t context;      \
    cc_unit data[];

/// Represents a polynomial in R_q = Z_q(X)^N / (X^N + 1) for N a power of two and q a (possibly) multi-word integer.
/// The polynomial is in Coefficient format
/// Must have same bit representation as ccpolyzp_po2cyc_eval, to enable pointer casting between ccpolyzp_po2cyc_coeff_t and
/// ccpolyzp_po2cyc_eval_t
struct ccpolyzp_po2cyc_coeff {
    __CCPOLYZP_PO2CYC_ELEMENTS_DEFINITION
};
typedef struct ccpolyzp_po2cyc_coeff *ccpolyzp_po2cyc_coeff_t;
typedef const struct ccpolyzp_po2cyc_coeff *ccpolyzp_po2cyc_coeff_const_t;

/// @brief Returns the polynomial's coefficients at a given RNS index
/// @param polyzp The polynomial, either ccpolyzp_po2cyc_coeff_t or ccpolyzp_po2cyc_eval_t
/// @param rns_idx The RNS index
/// @param coeff_idx The coefficient index
/// @return The CCPOLYZP_PO2CYC_NUNITS_PER_COEFF coefficients for x_{coeff_idx} mod q_{rns_idx}
/// @details The return value is in host-endian order, suitable for use with cczp.
#define CCPOLYZP_PO2CYC_DATA(polyzp, rns_idx, coeff_idx)    \
    ((cc_unit *)((ccpolyzp_po2cyc_coeff_t)(polyzp))->data + \
     CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * ((rns_idx) * (((ccpolyzp_po2cyc_coeff_t)(polyzp))->context->dims.degree) + (coeff_idx)))

#define CCPOLYZP_PO2CYC_DATA_CONST(polyzp, rns_idx, coeff_idx)          \
    ((const cc_unit *)((ccpolyzp_po2cyc_coeff_const_t)(polyzp))->data + \
     CCPOLYZP_PO2CYC_NUNITS_PER_COEFF *                                 \
         ((rns_idx) * (((ccpolyzp_po2cyc_coeff_const_t)(polyzp))->context->dims.degree) + (coeff_idx)))

/// Represents a polynomial in R_q = Z_q(X)^N / (X^N + 1) for N a power of two and q a (possibly) multi-word integer.
/// The polynomial is in Evaluation format
/// Must have same bit representation as ccpolyzp_po2cyc_coeff, to enable pointer casting between ccpolyzp_po2cyc_coeff_t and
/// ccpolyzp_po2cyc_eval_t
struct ccpolyzp_po2cyc_eval {
    __CCPOLYZP_PO2CYC_ELEMENTS_DEFINITION
};
typedef struct ccpolyzp_po2cyc_eval *ccpolyzp_po2cyc_eval_t;
typedef const struct ccpolyzp_po2cyc_eval *ccpolyzp_po2cyc_eval_const_t;

/// Enables pointer casting between ccpolyzp_po2cyc_coeff_t and ccpolyzp_po2cyc_eval_t
/// Useful to avoid polynomial copies for in-place operations.
cc_static_assert(sizeof(struct ccpolyzp_po2cyc_coeff) == sizeof(struct ccpolyzp_po2cyc_eval),
                 "ccpolyzp_po2cyc_coeff and ccpolyzp_po2cyc_eval must have same size");

/// Abstract type which can represent either ccpolyzp_po2cyc_coeff or ccpolyzp_po2cyc_eval
/// The fwd_ntt can be used to transform from ccpolyzp_po2cyc_coeff to ccpolyzp_po2cyc_eval.
/// The inv_ntt can be used to transform from ccpolyzp_po2cyc_eval to ccpolyzp_po2cyc_coeff.
struct ccpolyzp_po2cyc; // Used as a pointer only.
typedef struct ccpolyzp_po2cyc *ccpolyzp_po2cyc_t;
typedef const struct ccpolyzp_po2cyc *ccpolyzp_po2cyc_const_t;

/// @brief Returns the polynomial's coefficient at a given RNS and coefficient index
/// @param poly The polynomial
/// @param rns_idx The RNS index
/// @param coeff_idx The coefficient index
/// @return poly_{coeff_idx} mod q_{rns_idx}
/// @details The return value should not be used for cczp operations. Use `CCPOLYZP_PO2CYC_DATA` or `CCPOLYZP_PO2CYC_DATA_CONST`
/// instead.
CC_NONNULL_ALL CC_INLINE ccrns_int ccpolyzp_po2cyc_data_int(ccpolyzp_po2cyc_const_t poly, uint32_t rns_idx, uint32_t coeff_idx)
{
    const cc_unit *coeffs = CCPOLYZP_PO2CYC_DATA_CONST(poly, rns_idx, coeff_idx);
    return ccpolyzp_po2cyc_units_to_rns_int(coeffs);
}

/// @brief Returns the polynomial's coefficient at a given RNS and coefficient index
/// @param poly The polynomial
/// @param rns_idx The RNS index
/// @param coeff_idx The coefficient index
/// @return poly_{coeff_idx} mod q_{rns_idx}
/// @details The return value should not be used for cczp operations. Use `CCPOLYZP_PO2CYC_DATA` or `CCPOLYZP_PO2CYC_DATA_CONST`
/// instead.
CC_NONNULL_ALL CC_INLINE ccrns_int ccpolyzp_po2cyc_coeff_data_int(ccpolyzp_po2cyc_coeff_const_t poly,
                                                                  uint32_t rns_idx,
                                                                  uint32_t coeff_idx)
{
    return ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)poly, rns_idx, coeff_idx);
}

/// @brief Returns the polynomial's coefficient at a given RNS and coefficient index
/// @param poly The polynomial
/// @param rns_idx The RNS index
/// @param coeff_idx The coefficient index
/// @return poly_{coeff_idx} mod q_{rns_idx}
/// @details The return value should not be used for cczp operations. Use `CCPOLYZP_PO2CYC_DATA` or `CCPOLYZP_PO2CYC_DATA_CONST`
/// instead.
CC_NONNULL_ALL CC_INLINE ccrns_int ccpolyzp_po2cyc_eval_data_int(ccpolyzp_po2cyc_eval_const_t poly,
                                                                 uint32_t rns_idx,
                                                                 uint32_t coeff_idx)
{
    return ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)poly, rns_idx, coeff_idx);
}

/// @brief Returns the number of cc_units required to allocate a polynomial with the given dimensions
/// @param dims The context dimensions
CC_INLINE CC_NONNULL_ALL cc_size ccpolyzp_po2cyc_nof_n(ccpolyzp_po2cyc_dims_const_t dims)
{
    cc_size rv = ccn_nof_size(sizeof_struct_ccpolyzp_po2cyc());
    // coefficients storage
    rv += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * dims->degree * dims->nmoduli;
    return rv;
}
#define CCPOLYZP_PO2CYC_ALLOC_WS(ws, dims) (ccpolyzp_po2cyc_t) CC_ALLOC_WS(ws, ccpolyzp_po2cyc_nof_n((dims)))

/// @brief Compares two polynomials in coefficient format. Not constant-time
/// @param x A polynomial to compare
/// @param y A polynomial to compare
/// @return True if x and y are equal, false else
CC_NONNULL_ALL
bool ccpolyzp_po2cyc_coeff_eq(ccpolyzp_po2cyc_coeff_const_t x, ccpolyzp_po2cyc_coeff_const_t y);

/// @brief Compares two polynomials in evaluation format. Not constant-time
/// @param x A polynomial to compare
/// @param y A polynomial to compare
/// @return True if x and y are equal, false else
CC_INLINE CC_NONNULL_ALL bool ccpolyzp_po2cyc_eval_eq(ccpolyzp_po2cyc_eval_const_t x, ccpolyzp_po2cyc_eval_const_t y)
{
    return ccpolyzp_po2cyc_coeff_eq((ccpolyzp_po2cyc_coeff_const_t)x, (ccpolyzp_po2cyc_coeff_const_t)y);
}

/// @brief Initializes a ccpolyzp_po2cyc with the given context and coefficients
/// @param x The polynomial to initialize
/// @param context The context with which to initialize the polynomial
/// @param coefficients The coefficients in RNS form
/// @return CCERR_OK if successful
CC_NONNULL_ALL
CC_WARN_RESULT int ccpolyzp_po2cyc_init(ccpolyzp_po2cyc_t x, ccpolyzp_po2cyc_ctx_const_t context, const ccrns_int *coefficients);

/// @brief Initializes a ccpolyzp_po2cyc with the given context and all zeros coefficients
/// @param x The polynomial to initialize
/// @param context The context with which to initialize the polynomial
CC_NONNULL_ALL
void ccpolyzp_po2cyc_init_zero(ccpolyzp_po2cyc_t x, ccpolyzp_po2cyc_ctx_const_t context);

/// @brief Copies a polynomial in coefficient format into another polynomial in coefficient format
/// @param r The polynomial to copy to; may overlap with x
/// @param x The polynomial to copy from
CC_INLINE CC_NONNULL_ALL void ccpolyzp_po2cyc_coeff_copy(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x)
{
    cc_memmove(r, x, ccn_sizeof_n(ccpolyzp_po2cyc_nof_n(&x->context->dims)));
}

/// @brief Copies a polynomial in evaluation format into another polynomial in evaluation format
/// @param r The polynomial to copy to; may overlap with x
/// @param x The polynomial to copy from
CC_INLINE CC_NONNULL_ALL void ccpolyzp_po2cyc_eval_copy(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x)
{
    ccpolyzp_po2cyc_coeff_copy((ccpolyzp_po2cyc_coeff_t)r, (ccpolyzp_po2cyc_coeff_const_t)x);
}

/// @brief Computes r = -x in coefficient format. Constant-time.
/// @param x The input polynomial
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_coeff_negate(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x);

/// @brief Computes r = -x in evaluation format. Constant-time.
/// @param x The input polynomial
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_eval_negate(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x);

/// @brief Computes r = x + y in coefficient format. Constant-time.
/// @param x An input polynomial
/// @param y An input polynomial
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x or r == y.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_coeff_add(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x, ccpolyzp_po2cyc_coeff_const_t y);

/// @brief Computes r = x + y in evaluation format. Constant-time.
/// @param x An input polynomial
/// @param y An input polynomial
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x or r == y.
CC_NONNULL_ALL void
ccpolyzp_po2cyc_eval_add(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, ccpolyzp_po2cyc_eval_const_t y);

/// @brief Computes r = x - y in coefficient format. Constant-time.
/// @param x An input polynomial
/// @param y An input polynomial
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x or r == y.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_coeff_sub(ccpolyzp_po2cyc_coeff_t r, ccpolyzp_po2cyc_coeff_const_t x, ccpolyzp_po2cyc_coeff_const_t y);

/// @brief Computes r = x - y in evaluation format. Constant-time.
/// @param x An input polynomial
/// @param y An input polynomial
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x or r == y.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_eval_sub(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, ccpolyzp_po2cyc_eval_const_t y);

/// @brief Computes r = x * y in evaluation format. Constant-time.
/// @param x An input polynomial
/// @param y An input polynomial
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x or r == y.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_eval_mul(ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, ccpolyzp_po2cyc_eval_const_t y);

/// @brief Computes r = x * y in coefficient format for polynomials x, r and a scalar y. Constant-time.
/// @param ws Workspace
/// @param x An input polynomial
/// @param y An input scalar in CRT form: y[i] is the remainder y mod q_i
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_coeff_scalar_mul_ws(cc_ws_t ws,
                                         ccpolyzp_po2cyc_coeff_t r,
                                         ccpolyzp_po2cyc_coeff_const_t x,
                                         const ccrns_int *y);

/// @brief Computes r = x * y in evaluation format for polynomials x, r and a scalar y. Constant-time.
/// @param ws Workspace
/// @param x An input polynomial
/// @param y An input scalar in CRT form: y[i] is the remainder y mod q_i
/// @param r The output polynomial
/// @details The polynomials must have the same context and not overlap, unless r == x.
CC_NONNULL_ALL
void ccpolyzp_po2cyc_eval_scalar_mul_ws(cc_ws_t ws, ccpolyzp_po2cyc_eval_t r, ccpolyzp_po2cyc_eval_const_t x, const ccrns_int *y);

/// @brief Computes the in-place forward negacyclic number-theoretic transform (NTT) on x. Constant-time.
/// @param x The input/output polynomial
/// @return CCERR_OK if successful
/// @details The NTT can be used for efficient multiplication in R_q
/// All moduli in x must be NTT-friendly, i.e. satisfy q_i = 1 mod 2 N.
/// The output indices will be in bit-reversed order. The standard bit order is restored with the inv_ntt.
/// Note, the output x can be cast to ccpolyzp_po2cyc_eval_t
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_fwd_ntt(ccpolyzp_po2cyc_coeff_t x);

/// @brief Computes the in-place inverse negacyclic number-theoretic transform (NTT) on x. Constant-time.
/// @param x The input/output polynomial
/// @return CCERR_OK if successful
/// @details The NTT can be used for efficient multiplication in R_q
/// All moduli in x must be NTT-friendly, i.e. satisfy q_i = 1 mod 2 N
/// This function assumes the input indices are in bit-reversed order, as output by the fwd_ntt.
/// and restores the output to standard bit order.
/// Note, the output x can be cast to ccpolyzp_po2cyc_coeff_t
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_inv_ntt(ccpolyzp_po2cyc_eval_t x);

/// @brief Divides and rounds each coefficient by the last modulus in the chain, q_{L-1}, then drops the last modulus.
/// Constant-time, apart from leaking context of x, which is public
/// @param ws Workspace
/// @param x The input/output polynomial; should have at least two moduli, and a non-null next context
/// @return CCERR_OK if successful
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_divide_and_round_q_last_ws(cc_ws_t ws, ccpolyzp_po2cyc_coeff_t x);

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_INTERNAL_H_ */
