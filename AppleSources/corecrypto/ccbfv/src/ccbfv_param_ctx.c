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

#include "cc_internal.h"
#include "ccbfv_internal.h"
#include "ccbfv_param_ctx.h"
#include "ccpolyzp_po2cyc_scalar.h"
#include "ccbfv_decrypt_ctx.h"
#include "ccbfv_cipher_plain_ctx.h"
#include "ccpolyzp_po2cyc_serialization.h"

bool ccbfv_param_ctx_eq(ccbfv_param_ctx_const_t x, ccbfv_param_ctx_const_t y)
{
    if (x == y) {
        return true;
    }
    return (ccbfv_encrypt_params_eq(ccbfv_param_ctx_encrypt_params_const(x), ccbfv_param_ctx_encrypt_params_const(y)));
}

const uint32_t ccbfv_encoding_generator_column = 3;

/// @brief Initializes the parameter context for encoding/decoding
/// @param param_ctx The parameter context to initialize
CC_NONNULL_ALL static void ccbfv_encode_init(ccbfv_param_ctx_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    uint32_t degree = plain_ctx->dims.degree;

    uint32_t log2n = ccpolyzp_po2cyc_log2_uint32(degree);
    uint32_t row_size = degree >> 1; // n_2
    uint32_t twice_n = degree << 1;

    uint32_t *encoding_indices = ccbfv_param_ctx_encoding_indices(param_ctx);
    uint32_t g_pow_i = 1;
    for (uint32_t i = 0; i < row_size; ++i) {
        // g_pow_i = g_1^0 * g_2^i = g_2^i (odd)
        // twice_n - g_pow_i = g_1^1 * g_2^i * = -g_2^i = 2N - g_2^i (odd)
        // The operation f(i): (g^i - 1) >> 1 maps from odd powers of eta to the index of alpha_i, i.e. from indices
        // in (2) to indices in (1).
        uint32_t idx_1 = (g_pow_i - 1) >> 1;
        uint32_t idx_2 = (twice_n - g_pow_i - 1) >> 1;

        // Store in bit-reversed order, so the inv_ntt can restore the standard bit-ordering during encoding
        encoding_indices[i] = ccpolyzp_po2cyc_reverse_bits(idx_1, log2n);
        encoding_indices[row_size + i] = ccpolyzp_po2cyc_reverse_bits(idx_2, log2n);

        g_pow_i *= ccbfv_encoding_generator_column;
        g_pow_i &= twice_n - 1;
    }
}

cc_size CCBFV_PARAM_CTX_INIT_WORKSPACE_N(cc_size nmoduli)
{
    return CC_MAX_EVAL(
        CCPOLYZP_PO2CYC_CTX_INIT_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF),
        CC_MAX_EVAL(CCBFV_DECRYPT_CTX_INIT_WORKSPACE_N(nmoduli), CCBFV_CIPHER_PLAIN_CTX_INIT_WORKSPACE_N(nmoduli)));
}

int ccbfv_param_ctx_init_ws(cc_ws_t ws, ccbfv_param_ctx_t param_ctx, ccbfv_encrypt_params_const_t encrypt_params)
{
    int rv = CCERR_OK;

    // check that plaintext modulus is smaller than all the coefficient moduli
    for (uint32_t i = 0; i < encrypt_params->nmoduli; ++i) {
        if (encrypt_params->plaintext_modulus >= CCBFV_ENCRYPT_PARAMS_COEFF_MODULI_CONST(encrypt_params)[i]) {
            return CCERR_PARAMETER;
        }
    }
    // ensure nskip_bits is reasonable, but not that nskip_bits enforces decryption correctness
    cc_require_or_return(CC_ARRAY_LEN(encrypt_params->nskip_lsbs) == ccbfv_ciphertext_fresh_npolys(), CCERR_PARAMETER);
    for (uint32_t i = 0; i < CC_ARRAY_LEN(encrypt_params->nskip_lsbs); ++i) {
        uint32_t log2_q0 = ccpolyzp_po2cyc_log2_uint64(CCBFV_ENCRYPT_PARAMS_COEFF_MODULI_CONST(encrypt_params)[0]);
        cc_require_or_return(encrypt_params->nskip_lsbs[i] <= log2_q0, CCERR_PARAMETER);
    }

    const struct ccpolyzp_po2cyc_dims dims = { .degree = encrypt_params->poly_modulus_degree,
                                               .nmoduli = encrypt_params->nmoduli };
    const struct ccpolyzp_po2cyc_dims plaintext_dims = { .degree = encrypt_params->poly_modulus_degree, .nmoduli = 1 };
    ccbfv_encrypt_params_copy(ccbfv_param_ctx_encrypt_params(param_ctx), encrypt_params);

    ccpolyzp_po2cyc_ctx_chain_t ctx_chain = ccbfv_param_ctx_chain(param_ctx);
    rv = ccpolyzp_po2cyc_ctx_chain_init_ws(ws, ctx_chain, &dims, CCBFV_ENCRYPT_PARAMS_COEFF_MODULI_CONST(encrypt_params));
    cc_require(rv == CCERR_OK, errOut);

    // check if all coefficient moduli are NTT-friendly
    cc_require_or_return(ccpolyzp_po2cyc_ctx_chain_context(ctx_chain, ctx_chain->dims.nmoduli)->ntt_friendly, CCERR_PARAMETER);

    ccpolyzp_po2cyc_ctx_t plaintext_ctx = ccbfv_param_ctx_plaintext_ctx(param_ctx);
    rv = ccpolyzp_po2cyc_ctx_init_ws(ws, plaintext_ctx, &plaintext_dims, &encrypt_params->plaintext_modulus, NULL);
    cc_require(rv == CCERR_OK, errOut);

    ccbfv_encode_init(param_ctx);

    ccbfv_decrypt_ctx_t decrypt_ctx = ccbfv_param_ctx_decrypt_ctx(param_ctx);
    cc_require((rv = ccbfv_decrypt_ctx_init_ws(ws, decrypt_ctx, param_ctx)) == CCERR_OK, errOut);

    for (uint32_t i = 1; i <= encrypt_params->nmoduli; ++i) {
        ccbfv_cipher_plain_ctx_t cipher_plain_ctx = ccbfv_param_ctx_cipher_plain_ctx(param_ctx, i);
        rv = ccbfv_cipher_plain_ctx_init_ws(
            ws, cipher_plain_ctx, param_ctx, ccpolyzp_po2cyc_ctx_chain_context_const(ctx_chain, i));
        cc_require(rv == CCERR_OK, errOut);
    }

errOut:
    return rv;
}

int ccbfv_param_ctx_init(ccbfv_param_ctx_t param_ctx, ccbfv_predefined_encryption_params_t encrypt_params)
{
    CC_ENSURE_DIT_ENABLED

    ccbfv_encrypt_params_const_t params = ccbfv_encrypt_params_get(encrypt_params);
    cc_require_or_return(params, CCERR_PARAMETER);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCBFV_PARAM_CTX_INIT_WORKSPACE_N(params->nmoduli));
    int rv = ccbfv_param_ctx_init_ws(ws, param_ctx, params);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

cc_size ccbfv_param_ctx_nof_n(ccbfv_encrypt_params_const_t enc_params)
{
    struct ccpolyzp_po2cyc_dims dims = { .degree = enc_params->poly_modulus_degree, .nmoduli = enc_params->nmoduli };
    // struct storage, rounded up to nearest number of cc_units
    cc_size rv = ccn_nof_size(sizeof_struct_ccbfv_param_ctx());
    rv += ccbfv_encrypt_params_nof_n(enc_params->nmoduli);
    rv += ccpolyzp_po2cyc_ctx_chain_nof_n(&dims);
    rv += ccpolyzp_po2cyc_ctx_nof_n(enc_params->poly_modulus_degree);
    rv += ccn_nof_size(sizeof(uint32_t) * enc_params->poly_modulus_degree); // Encoding indices array
    rv += ccbfv_decrypt_ctx_nof_n(&dims);
    for (uint32_t i = 1; i <= enc_params->nmoduli; ++i) {
        dims.nmoduli = i;
        rv += ccbfv_cipher_plain_ctx_nof_n(&dims);
    }
    return rv;
}

ccpolyzp_po2cyc_ctx_chain_t ccbfv_param_ctx_chain(ccbfv_param_ctx_t param_ctx)
{
    ccbfv_encrypt_params_t encrypt_params = ccbfv_param_ctx_encrypt_params(param_ctx);
    cc_unit *rv = (cc_unit *)encrypt_params;
    rv += ccbfv_encrypt_params_nof_n(encrypt_params->nmoduli);
    return (ccpolyzp_po2cyc_ctx_chain_t)rv;
}

ccpolyzp_po2cyc_ctx_chain_const_t ccbfv_param_ctx_chain_const(ccbfv_param_ctx_const_t param_ctx)
{
    ccbfv_encrypt_params_const_t encrypt_params = ccbfv_param_ctx_encrypt_params_const(param_ctx);
    const cc_unit *rv = (const cc_unit *)encrypt_params;
    rv += ccbfv_encrypt_params_nof_n(encrypt_params->nmoduli);
    return (ccpolyzp_po2cyc_ctx_chain_const_t)rv;
}

CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_t ccbfv_param_ctx_plaintext_ctx(ccbfv_param_ctx_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_chain_t ctx_chain = ccbfv_param_ctx_chain(param_ctx);
    cc_unit *rv = (cc_unit *)ctx_chain;
    rv += ccpolyzp_po2cyc_ctx_chain_nof_n(&ctx_chain->dims);
    return (ccpolyzp_po2cyc_ctx_t)rv;
}

CC_NONNULL_ALL ccpolyzp_po2cyc_ctx_const_t ccbfv_param_ctx_plaintext_ctx_const(ccbfv_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_ctx_chain_const_t ctx_chain = ccbfv_param_ctx_chain_const(param_ctx);
    const cc_unit *rv = (const cc_unit *)ctx_chain;
    rv += ccpolyzp_po2cyc_ctx_chain_nof_n(&ctx_chain->dims);
    return (ccpolyzp_po2cyc_ctx_const_t)rv;
}

size_t ccbfv_param_ctx_sizeof(ccbfv_predefined_encryption_params_t enc_params)
{
    ccbfv_encrypt_params_const_t params = ccbfv_encrypt_params_get(enc_params);
    cc_require_or_return(params, 0);
    return ccbfv_param_ctx_nof_n(params) * sizeof_cc_unit();
}

uint64_t ccbfv_param_ctx_plaintext_modulus(ccbfv_param_ctx_const_t param_ctx)
{
    return ccbfv_param_ctx_encrypt_params_const(param_ctx)->plaintext_modulus;
}

uint32_t ccbfv_param_ctx_polynomial_degree(ccbfv_param_ctx_const_t param_ctx)
{
    return ccbfv_param_ctx_encrypt_params_const(param_ctx)->poly_modulus_degree;
}

uint32_t ccbfv_param_ctx_key_ctx_nmoduli(ccbfv_param_ctx_const_t param_ctx)
{
    return ccbfv_param_ctx_encrypt_key_context(param_ctx)->dims.nmoduli;
}

uint32_t ccbfv_param_ctx_ciphertext_ctx_nmoduli(ccbfv_param_ctx_const_t param_ctx)
{
    return ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;
}

const uint64_t *ccbfv_param_ctx_coefficient_moduli(ccbfv_param_ctx_const_t param_ctx)
{
    CC_ENSURE_DIT_ENABLED

    return ccbfv_param_ctx_encrypt_params_const(param_ctx)->moduli;
}

size_t ccbfv_param_ctx_key_ctx_poly_nbytes(ccbfv_param_ctx_const_t param_ctx)
{
    CC_ENSURE_DIT_ENABLED

    return ccpolyzp_po2cyc_serialize_poly_nbytes(ccbfv_param_ctx_encrypt_key_context(param_ctx), 0);
}

int ccbfv_param_ctx_plaintext_modulus_inverse(uint64_t *inverse, ccbfv_param_ctx_const_t param_ctx, uint64_t x)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_ctx_const_t ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    cczp_const_t t = ccpolyzp_po2cyc_ctx_cczp_modulus_const(ctx, 0);
    cc_unit x_unit[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    cc_unit r_unit[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(x_unit, (ccrns_int)x);
    cczp_modn(t, x_unit, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, x_unit);
    int rv = cczp_inv(t, r_unit, x_unit);
    cc_require_or_return(rv == CCERR_OK, rv);
    *inverse = (uint64_t)ccpolyzp_po2cyc_units_to_rns_int(r_unit);
    return CCERR_OK;
}
