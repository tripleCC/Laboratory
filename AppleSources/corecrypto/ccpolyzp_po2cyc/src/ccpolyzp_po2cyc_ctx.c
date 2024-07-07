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

#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>
#include "cc_workspaces.h"
#include "ccn_internal.h"
#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ntt.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_scalar.h"
#include "ccprime_internal.h"

cc_size CCPOLYZP_PO2CYC_CTX_WORKSPACE_N(cc_size degree)
{
    return ccpolyzp_po2cyc_ctx_nof_n((uint32_t)degree);
}

/// Returns true if dimensions x and y are equal, false otherwise
bool ccpolyzp_po2cyc_dims_eq(ccpolyzp_po2cyc_dims_const_t x, ccpolyzp_po2cyc_dims_const_t y)
{
    return (x->degree == y->degree) && (x->nmoduli == y->nmoduli);
}

/// Returns true if contexts x and y are equal, false otherwise
bool ccpolyzp_po2cyc_ctx_eq(ccpolyzp_po2cyc_ctx_const_t x, ccpolyzp_po2cyc_ctx_const_t y)
{
    if (x == y) {
        return true;
    }
    if (!ccpolyzp_po2cyc_dims_eq(&x->dims, &y->dims)) {
        return false;
    }
    for (uint32_t rns_idx = 0; rns_idx < x->dims.nmoduli; ++rns_idx) {
        if (ccpolyzp_po2cyc_ctx_int_modulus(x, rns_idx) != ccpolyzp_po2cyc_ctx_int_modulus(y, rns_idx)) {
            return false;
        }
        if (x->ntt_friendly && (ccpolyzp_po2cyc_ctx_rou(x, rns_idx) != ccpolyzp_po2cyc_ctx_rou(y, rns_idx))) {
            return false;
        }
    }
    return true;
}

bool ccpolyzp_po2cyc_ctx_is_parent(ccpolyzp_po2cyc_ctx_const_t parent, ccpolyzp_po2cyc_ctx_const_t child)
{
    do {
        if (parent == child) {
            return true;
        } else {
            parent = parent->next;
        }
    } while (parent);
    return false;
}

ccrns_int ccpolyzp_po2cyc_ctx_rou(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t idx)
{
    cc_assert(idx < ctx->dims.nmoduli);
    uint32_t rev_idx = ccpolyzp_po2cyc_reverse_bits(1, ccpolyzp_po2cyc_log2_uint32(ctx->dims.degree));
    const cc_unit *rou_units = ccpolyzp_po2cyc_ctx_rou_powers_const(ctx, idx);
    rou_units += rev_idx * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    return ccpolyzp_po2cyc_units_to_rns_int(rou_units);
}

/// @brief Returns whether or not root is a primitive degree'th root of unity mod modulus
/// @param ws Workspace
/// @param root Possible root of unity
/// @param degree Degree of the root; must be a power of two
/// @param modulus The modulus
/// @return True if root is a primitive degree'th root of unity mod modulus, false otherwise
CC_NONNULL_ALL static bool ccpolyzp_po2cyc_is_primitive_root_ws(cc_ws_t ws, const cc_unit *root, uint32_t degree, cczp_t modulus)
{
    cc_require_or_return(ccpolyzp_po2cyc_ctx_is_valid_degree(degree), CCERR_PARAMETER);
    if (ccn_is_zero(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, root)) {
        return false;
    }

    // For degree a power of two, it suffices to check root^(degree/2) == -1 mod modulus
    // This implies root^degree == 1 mod modulus. Also, note 2 is the only prime factor of
    // degree.
    cc_unit r[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit exp[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(exp, (ccrns_int)degree / 2);

    cc_unit modulus_minus_1[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(modulus_minus_1, (ccpolyzp_po2cyc_modulus_to_rns_int(modulus) - 1));
    cczp_power_ws(ws, modulus, r, root, CCN_UNIT_BITS * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, exp);

    return ccn_cmp(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, r, modulus_minus_1) == 0;
}

/// @brief Computes a primitive degree'th root of unity mod modulus
/// @param ws Workspace
/// @param r Will store computed root of unity if found
/// @param degree Degree of the root; must be a power of two that divides modulus - 1
/// @param modulus The modulus
/// @return CCERR_OK if root was generated succesfully
/// @details Not constant-time
CC_NONNULL_ALL static int ccpolyzp_po2cyc_gen_primitive_root_ws(cc_ws_t ws, cc_unit *r, uint32_t degree, cczp_t modulus)
{
    int rv = CCERR_INTERNAL;
    cc_require_or_return(ccpolyzp_po2cyc_ctx_is_valid_degree(degree), CCERR_PARAMETER);
    ccrns_int p = ccpolyzp_po2cyc_modulus_to_rns_int(modulus);

    // Carmichael function lambda(p) - p - 1 for p prime
    ccrns_int lambda_p = p - 1;
    cc_require_or_return(lambda_p % degree == 0, CCERR_PARAMETER);

    cc_unit exp[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(exp, (lambda_p / (ccrns_int)degree));

    struct ccrng_state *rng = ccrng(&rv);
    cc_require(rv == CCERR_OK, errOut);

    // The number of primitive roots mod p for p prime is phi(p-1), where phi is Euler's totient function.
    // We know phi(p-1) > p / (e^gamma log(log(p)) + 3 / log(log(p)).
    // So the probability that a random value in [0, p-1] is a primitive root is at least
    // phi(p-1)/p > 1 / (e^gamma log(log(p)) + 3 / log(log(p)) > 1/8 for p < 2^64 and where gamma is the Euler–Mascheroni constant
    // ~= 0.577. That is, we have at least 1/8 chance of finding a root on each attempt. So, (1 - 1/8)^T < 2^{-128} yields T = 665
    // trials suffices for less than 2^{-128} chance of failure.
    const uint32_t NPRIMITIVE_ROOT_TRIALS = 665;
    for (uint32_t i = 0; i < NPRIMITIVE_ROOT_TRIALS; ++i) {
        cc_unit root[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        cc_require((rv = cczp_generate_random_element_ws(ws, modulus, rng, root)) == CCERR_OK, errOut);

        // root^(lambda(p)/degree) will be a primitive degree'th root of unity if root
        // is a lambda(p)'th root
        cczp_power_ws(ws, modulus, root, root, CCN_UNIT_BITS * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, exp);
        if (ccpolyzp_po2cyc_is_primitive_root_ws(ws, root, degree, modulus)) {
            ccn_set(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, r, root);
            return CCERR_OK;
        }
    }

errOut:
    return rv;
}

/// @brief Stores a pre-computed minimum primitive root of unity
struct ccpolyzp_po2cyc_predefined_min_primitive_roots_t {
    /// modulus
    ccrns_int modulus;
    /// this is typically twice the polynomial modulus degree
    ccrns_int degree;
    /// minimial `degree`'th root of unity mod `modulus`
    ccrns_int root;
};

static struct ccpolyzp_po2cyc_predefined_min_primitive_roots_t predefined_min_primitive_roots[] = {
    // clang-format off
    { .modulus = 40961, .degree = 8192, .root = 12 },
    { .modulus = 65537, .degree = 8192, .root = 13 },
    { .modulus = 114689, .degree = 8192, .root = 2 },
    { .modulus = 147457, .degree = 8192, .root = 65 },
    { .modulus = 163841, .degree = 8192, .root = 25 },
    { .modulus = 134176769, .degree = 8192, .root = 24149 },
    { .modulus = 268361729, .degree = 8192, .root = 58939 },
    { .modulus = 268369921, .degree = 8192, .root = 62736 },
    { .modulus = 8589844481, .degree = 8192, .root = 4268790 },
    { .modulus = 8589852673, .degree = 8192, .root = 652337 },
    { .modulus = 18014398509309953, .degree = 8192, .root = 2104035327373 },
    { .modulus = 557057, .degree = 16384, .root = 268 },
    { .modulus = 8404993, .degree = 16384, .root = 272 },
    { .modulus = 33832961, .degree = 16384, .root = 2686 },
    { .modulus = 268369921, .degree = 16384, .root = 65274 },
    { .modulus = 268582913, .degree = 16384, .root = 15787 },
    { .modulus = 536690689, .degree = 16384, .root = 130289 },
    { .modulus = 536903681, .degree = 16384, .root = 78006 },
    { .modulus = 1099511480321, .degree = 16384, .root = 30370987 },
    { .modulus = 2199023288321, .degree = 16384, .root = 103974551 },
    { .modulus = 36028797017456641, .degree = 16384, .root = 4991203289951 },
    { .modulus = 36028797017571329, .degree = 16384, .root = 3055459936772 },
    { .modulus = 36028797018652673, .degree = 16384, .root = 15372713853695 },
    { .modulus = 1152921504606748673, .degree = 16384, .root = 100406242475323 },
    { .modulus = 1152921504606830593, .degree = 16384, .root = 25959043411404 },
    // clang-format on
};

/// @brief Generates the minimal degree'th root of unity mod modulus
/// @param ws Workspace
/// @param r Will store of computed root of unity if found
/// @param degree Degree of the root; must be a power of two that divides modulus - 1
/// @param modulus The modulus
/// @return CCERR_OK if root was generated succesfully
/// @details Leaks `modulus` and `degree` through timing. These are considered public, as they are part of the polynomial context.
CC_NONNULL_ALL static int ccpolyzp_po2cyc_min_primitive_root_ws(cc_ws_t ws, cc_unit *r, uint32_t degree, cczp_t modulus)
{
    cc_require_or_return(ccpolyzp_po2cyc_ctx_is_valid_degree(degree), CCERR_PARAMETER);

    ccrns_int p = ccpolyzp_po2cyc_modulus_to_rns_int(modulus);
    for (unsigned i = 0; i < CC_ARRAY_LEN(predefined_min_primitive_roots); ++i) {
        struct ccpolyzp_po2cyc_predefined_min_primitive_roots_t predefined = predefined_min_primitive_roots[i];
        if (predefined.degree == degree && predefined.modulus == p) {
            ccpolyzp_po2cyc_rns_int_to_units(r, predefined_min_primitive_roots[i].root);
            return CCERR_OK;
        }
    }

    // Carmichael function lambda(p) - p - 1 for p prime
    ccrns_int lambda_p = p - 1;
    cc_require_or_return(lambda_p % degree == 0, CCERR_PARAMETER);

    cc_unit smallest_generator_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccn_seti(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, smallest_generator_units, 1);
    int rv = (ccpolyzp_po2cyc_gen_primitive_root_ws(ws, smallest_generator_units, degree, modulus));
    cc_require_or_return(rv == CCERR_OK, rv);
    ccrns_int smallest_generator = ccpolyzp_po2cyc_units_to_rns_int(smallest_generator_units);

    struct ccrns_modulus int_modulus;
    rv = ccrns_modulus_init_var_time_ws(ws, &int_modulus, p);
    cc_require_or_return(rv == CCERR_OK, rv);

    // Given a generator g, g^l is a degree'th root of unity iff l and degree are
    // co-prime. Since degree is a power of two, we can check g, g^3, g^5, ...
    ccrns_int cur_generator = smallest_generator;
    ccrns_int generator_sq = ccpolyzp_po2cyc_scalar_mul_mod(smallest_generator, smallest_generator, &int_modulus);
    struct ccrns_mul_modulus mul_generator_sq_modulus;
    rv = ccrns_mul_modulus_init_ws(ws, &mul_generator_sq_modulus, p, generator_sq);
    cc_require_or_return(rv == CCERR_OK, rv);
    for (uint32_t i = 0; i < degree / 2; ++i) {
        if (cur_generator < smallest_generator) {
            smallest_generator = cur_generator;
        }
        cur_generator = ccpolyzp_po2cyc_scalar_shoup_mul_mod(cur_generator, &mul_generator_sq_modulus);
    }
    ccpolyzp_po2cyc_rns_int_to_units(r, smallest_generator);

    return CCERR_OK;
}

/// @brief Initializes a context with pre-computation for the NTT
/// @param ws Workspace
/// @param context Context to initialize; considered public
/// @return CCERR_OK if initialization was successful
/// @details Leaks `context` through timing
static int ccpolyzp_po2cyc_ctx_init_ntt_ws(cc_ws_t ws, ccpolyzp_po2cyc_ctx_t context)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_dims_const_t dims = &context->dims;
    uint32_t rns_idx = dims->nmoduli - 1;
    cczp_t cczp_modulus = ccpolyzp_po2cyc_ctx_cczp_modulus(context, rns_idx);
    ccrns_modulus_const_t rns_modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(context, rns_idx);

    context->ntt_friendly = true;
    for (uint32_t i = 0; i < dims->nmoduli; ++i) {
        ccrns_modulus_const_t q_i = ccpolyzp_po2cyc_ctx_ccrns_modulus(context, i);
        context->ntt_friendly &= is_ntt_modulus_and_degree(q_i->value, dims->degree);
    }
    cc_require_or_return(context->ntt_friendly, CCERR_OK);

    cc_unit *rou_powers = ccpolyzp_po2cyc_ctx_rou_powers(context, rns_idx);
    cc_unit *inv_rou_powers = ccpolyzp_po2cyc_ctx_inv_rou_powers(context, rns_idx);
    ccrns_mul_modulus_t mul_modulus_rou_powers = ccpolyzp_po2cyc_ctx_rou_powers_mul_modulus(context, rns_idx);
    ccrns_mul_modulus_t mul_modulus_inv_rou_powers = ccpolyzp_po2cyc_ctx_inv_rou_powers_mul_modulus(context, rns_idx);

    cc_unit rou_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    rv = ccpolyzp_po2cyc_min_primitive_root_ws(ws, rou_units, 2 * dims->degree, cczp_modulus);
    cc_require(rv == CCERR_OK, errOut);
    ccrns_int rou = ccpolyzp_po2cyc_units_to_rns_int(rou_units);
    struct ccrns_mul_modulus rou_mul_modulus;
    cc_require((rv = ccrns_mul_modulus_init_var_time_ws(ws, &rou_mul_modulus, rns_modulus->value, rou)) == CCERR_OK, errOut);

    cc_unit inv_rou_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_require((rv = cczp_inv_field_ws(ws, cczp_modulus, inv_rou_units, rou_units)) == CCERR_OK, errOut);
    ccrns_int inv_rou = ccpolyzp_po2cyc_units_to_rns_int(inv_rou_units);
    struct ccrns_mul_modulus inv_rou_mul_modulus;
    cc_require((rv = ccrns_mul_modulus_init_var_time_ws(ws, &inv_rou_mul_modulus, rns_modulus->value, inv_rou)) == CCERR_OK,
               errOut);

    // Compute root of unity powers in bit-reversed order
    ccpolyzp_po2cyc_rns_int_to_units(&rou_powers[0], 1);
    uint32_t degree_bits = ccpolyzp_po2cyc_log2_uint32(dims->degree);
    for (uint32_t prev_idx = 0, idx = 1; idx < dims->degree; ++idx) {
        uint32_t rev_idx = ccpolyzp_po2cyc_reverse_bits(idx, degree_bits);
        rev_idx *= CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        ccrns_int prev_power = ccpolyzp_po2cyc_units_to_rns_int(&rou_powers[prev_idx]);
        ccrns_int new_power = ccpolyzp_po2cyc_scalar_shoup_mul_mod(prev_power, &rou_mul_modulus);
        ccpolyzp_po2cyc_rns_int_to_units(&rou_powers[rev_idx], new_power);
        if (rev_idx < ccpolyzp_po2cyc_fwd_ntt_mul_modulus_rou_npowers(dims->degree)) {
            rv = ccrns_mul_modulus_init_var_time_ws(ws, &mul_modulus_rou_powers[rev_idx], rns_modulus->value, new_power);
            cc_require(rv == CCERR_OK, errOut);
        }
        prev_idx = rev_idx;
    }

    // Compute inverse root of unity powers in modified bit-reversed order for sequential access in invNTT
    ccpolyzp_po2cyc_rns_int_to_units(&inv_rou_powers[0], 1);
    for (uint32_t prev_idx = 0, m = dims->degree / 2; m > 0; m >>= 1) {
        for (uint32_t i = 0; i < m; ++i) {
            uint32_t rev_idx = ccpolyzp_po2cyc_reverse_bits(m + i, degree_bits);
            ccrns_int prev_power = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers[prev_idx * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF]);
            ccrns_int new_power = ccpolyzp_po2cyc_scalar_shoup_mul_mod(prev_power, &inv_rou_mul_modulus);
            ccpolyzp_po2cyc_rns_int_to_units(&inv_rou_powers[rev_idx * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF], new_power);
            // Store only the powers with large `rev_idx`, as they are used more often
            if (rev_idx >= dims->degree - ccpolyzp_po2cyc_inv_ntt_mul_modulus_rou_npowers(dims->degree)) {
                rv = ccrns_mul_modulus_init_var_time_ws(
                    ws, &mul_modulus_inv_rou_powers[dims->degree - rev_idx - 1], rns_modulus->value, new_power);
                cc_require(rv == CCERR_OK, errOut);
            }
            prev_idx = rev_idx;
        }
    }

    // Pre-computation for final layer of inverse NTT: modular multiplication with N^{-1} % q_i, and N^{-1} * w^{-N/2} % q_i
    ccrns_int n_mod_qi = ccpolyzp_po2cyc_scalar_mod1(dims->degree, rns_modulus);
    cc_unit n_mod_qi_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(n_mod_qi_units, n_mod_qi);
    cc_unit n_inv_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF] = { dims->degree };
    cc_require((rv = cczp_inv_field_ws(ws, cczp_modulus, n_inv_units, n_mod_qi_units)) == CCERR_OK, errOut);
    ccrns_int n_inv = ccpolyzp_po2cyc_units_to_rns_int(n_inv_units);
    rv = ccrns_mul_modulus_init_var_time_ws(ws, &context->inv_degree_q_last, rns_modulus->value, n_inv);
    cc_require(rv == CCERR_OK, errOut);

    ccrns_int w_inv_n2 = ccpolyzp_po2cyc_units_to_rns_int(&inv_rou_powers[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF * (dims->degree - 1)]);
    ccrns_int n_inv_w_inv_n2 = ccpolyzp_po2cyc_scalar_mul_mod(n_inv, w_inv_n2, rns_modulus);
    rv = ccrns_mul_modulus_init_var_time_ws(ws, &context->inv_rou_power_n2_q_last, rns_modulus->value, n_inv_w_inv_n2);
    cc_require(rv == CCERR_OK, errOut);
errOut:
    return rv;
}

cc_size CCPOLYZP_PO2CYC_CTX_INIT_WORKSPACE_N(cc_size n)
{
    return CC_MAX_EVAL(CCPRIME_RABIN_MILLER_WORKSPACE_N(n),
                       CC_MAX_EVAL(CCPOLYZP_PO2CYC_MODULUS_TO_CCZP_WORKSPACE_N(n), CCPOLYZP_PO2CYC_CTX_INIT_NTT_WORKSPACE_N(n)));
}

int ccpolyzp_po2cyc_ctx_init_ws(cc_ws_t ws,
                                ccpolyzp_po2cyc_ctx_t context,
                                ccpolyzp_po2cyc_dims_const_t dims,
                                const ccrns_int *cc_counted_by(dims->nmoduli) moduli,
                                const ccpolyzp_po2cyc_ctx_t next_context)
{
    cc_require_or_return(ccpolyzp_po2cyc_ctx_is_valid_dims(dims), CCERR_PARAMETER);
    cc_require_or_return(next_context != NULL || dims->nmoduli == 1, CCERR_PARAMETER);
    int rv = CCERR_OK;
    context->dims = *dims;
    context->next = next_context;

    // Checks moduli are co-prime and < CCPOLYZP_PO2CYC_MAX_MODULUS
    for (uint32_t rns_idx = 0; rns_idx < dims->nmoduli; ++rns_idx) {
        cc_require_or_return(moduli[rns_idx] < CCPOLYZP_PO2CYC_MAX_MODULUS, CCERR_PARAMETER);
        for (uint32_t i = 0; i < rns_idx; ++i) {
            cc_require_or_return(moduli[rns_idx] != moduli[i], CCERR_PARAMETER);
        }
        // Prime checking is slow; in practice, the moduli come from pre-defined encryption parameters, so they will be guaranteed
        // to be prime
#if CORECRYPTO_DEBUG
        struct ccrng_state *rng = ccrng(&rv);
        cc_require(rv == CCERR_OK, errOut);
        cc_unit modulus_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
        ccpolyzp_po2cyc_rns_int_to_units(modulus_units, moduli[rns_idx]);
        int prime_rv = ccprime_rabin_miller_ws(ws, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, modulus_units, 44, rng);
        cc_require_or_return(prime_rv == 1, prime_rv == 0 ? CCERR_PARAMETER : prime_rv);
#endif // CORECRYPTO_DEBUG
    }

    uint32_t rns_idx = dims->nmoduli - 1;
    cczp_t cczp_modulus = ccpolyzp_po2cyc_ctx_cczp_modulus(context, rns_idx);
    cc_require((rv = ccpolyzp_po2cyc_modulus_to_cczp_ws(ws, cczp_modulus, moduli[rns_idx])) == CCERR_OK, errOut);
    cc_require((rv = ccrns_modulus_init_ws(ws, &context->ccrns_q_last, moduli[rns_idx])) == CCERR_OK, errOut);
    cc_require((rv = ccpolyzp_po2cyc_ctx_init_ntt_ws(ws, context)) == CCERR_OK, errOut);

errOut:
    return rv;
}

int ccpolyzp_po2cyc_ctx_chain_init_ws(cc_ws_t ws,
                                      ccpolyzp_po2cyc_ctx_chain_t context_chain,
                                      ccpolyzp_po2cyc_dims_const_t dims,
                                      const ccrns_int *moduli)
{
    cc_require_or_return(ccpolyzp_po2cyc_ctx_is_valid_degree(dims->degree) && dims->nmoduli > 0, CCERR_PARAMETER);
    int rv = CCERR_OK;

    context_chain->dims = *dims;

    ccpolyzp_po2cyc_ctx_t prev_context = NULL;
    for (uint32_t nmoduli = 1; nmoduli <= dims->nmoduli; ++nmoduli) {
        struct ccpolyzp_po2cyc_dims parital_dims = { .degree = dims->degree, .nmoduli = nmoduli };
        ccpolyzp_po2cyc_ctx_t partial_context = ccpolyzp_po2cyc_ctx_chain_context(context_chain, nmoduli);
        cc_require((rv = ccpolyzp_po2cyc_ctx_init_ws(ws, partial_context, &parital_dims, moduli, prev_context)) == CCERR_OK,
                   errOut);
        prev_context = partial_context;
    }
errOut:
    return rv;
}

cc_size CCPOLYZP_PO2CYC_CTX_Q_PROD_WORKSPACE_N(cc_size nmoduli)
{
    return ccpolyzp_po2cyc_ctx_q_prod_nof_n((uint32_t)nmoduli);
}

void ccpolyzp_po2cyc_ctx_q_prod_ws(cc_ws_t ws, cc_unit *q_prod, ccpolyzp_po2cyc_ctx_const_t context)
{
    CC_DECL_BP_WS(ws, bp);

    cc_size q_prod_max_nunits = ccpolyzp_po2cyc_ctx_q_prod_nof_n(context->dims.nmoduli);
    const cc_unit *q_0 = CCZP_PRIME(ccpolyzp_po2cyc_ctx_cczp_modulus_const(context, 0));
    ccn_setn(q_prod_max_nunits, q_prod, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_0);
    cc_unit *q_prod_tmp = CC_ALLOC_WS(ws, q_prod_max_nunits);
    for (uint32_t i = 1; i < context->dims.nmoduli; ++i) {
        const cc_unit *q_i = CCZP_PRIME(ccpolyzp_po2cyc_ctx_cczp_modulus_const(context, i));
        ccn_muln(i * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_prod_tmp, q_prod, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_i);
        ccn_set((i + 1) * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, q_prod, q_prod_tmp);
    }

    CC_FREE_BP_WS(ws, bp);
}
