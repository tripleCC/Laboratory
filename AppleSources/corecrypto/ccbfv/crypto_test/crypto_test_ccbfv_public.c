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

#include "crypto_test_ccbfv.h"
#include "ccbfv_util.h"
#include <corecrypto/ccbfv_priv.h>
#include <stdlib.h>
#include <math.h>
#include "ccpolyzp_po2cyc_scalar.h"

/// Structure that hold the common things used for the tests
struct ccbfv_public_test_common {
    ccbfv_param_ctx_t param_ctx;                   /// Parameter context
    ccbfv_secret_key_t secret_key;                 /// Secret key
    ccbfv_relin_key_t relin_key;                   /// Relinearization key
    uint64_t *values;                              /// Values for encoding
    uint64_t *sum_values;                          /// Sum: (values[i] + values[i]) % t
    uint64_t *prod_values;                         /// Product: (values[i] * values[i]) % t
    ccbfv_plaintext_t plaintext;                   /// Plaintext
    ccbfv_dcrt_plaintext_t dcrt_plaintext;         /// Dcrt plaintext
    ccbfv_rng_seed_t ciphertext_seed;              /// Ciphertext seed
    ccbfv_ciphertext_coeff_t ciphertext;           /// Ciphertext
    ccbfv_ciphertext_coeff_t ciphertext_1_modulus; /// Ciphertext encrypted with 1 modulus
};

typedef struct ccbfv_public_test_common *ccbfv_public_test_common_t;
typedef const struct ccbfv_public_test_common *ccbfv_public_test_common_const_t;

/// @brief Set up the common structures
/// @param common The common structure to set up
/// @param enc_params The encryption parameters
/// @return `CCERR_OK` if initialization succeeds
/// @details To avoid memory leak, one should call `test_ccbfv_common_cleanup` after using `common`.
static int test_ccbfv_common_setup(ccbfv_public_test_common_t common, ccbfv_predefined_encryption_params_t enc_params)
{
    ccbfv_param_ctx_t param_ctx = (ccbfv_param_ctx_t)malloc(ccbfv_param_ctx_sizeof(enc_params));
    int rv = ccbfv_param_ctx_init(param_ctx, enc_params);
    if (rv != CCERR_OK) {
        goto err_param_ctx;
    }

    ccbfv_secret_key_t secret_key = (ccbfv_secret_key_t)malloc(ccbfv_secret_key_sizeof(param_ctx));
    rv = ccbfv_secret_key_generate(secret_key, param_ctx, global_test_rng);
    if (rv != CCERR_OK) {
        goto err_secret_key;
    }

    // Overwrite secret key with one generated from a seed
    struct ccpolyzp_po2cyc_block_rng_seed seed = { .data = { 1 } };
    rv = ccbfv_secret_key_generate_from_seed(secret_key, param_ctx, (ccbfv_rng_seed_t)&seed);
    if (rv != CCERR_OK) {
        goto err_secret_key;
    }

    ccbfv_relin_key_t relin_key = NULL;
    if (ccbfv_encryption_params_coefficient_nmoduli(enc_params) > 1) {
        relin_key = (ccbfv_relin_key_t)malloc(ccbfv_relin_key_sizeof(param_ctx));
        rv = ccbfv_relin_key_generate(relin_key, secret_key, param_ctx, 0, NULL, global_test_rng);
        if (rv != CCERR_OK) {
            goto err_relin_key;
        }
    }

    ccbfv_plaintext_t plaintext = (ccbfv_plaintext_t)malloc(ccbfv_plaintext_sizeof(param_ctx));
    ccrns_modulus_const_t t = &(ccbfv_param_ctx_plaintext_ctx_const(param_ctx))->ccrns_q_last;
    uint32_t degree = ccbfv_param_ctx_polynomial_degree(param_ctx);
    uint64_t plaintext_modulus = ccbfv_param_ctx_plaintext_modulus(param_ctx);
    uint64_t *values = calloc(degree, sizeof(uint64_t));
    uint64_t *sum_values = calloc(degree, sizeof(uint64_t));
    uint64_t *prod_values = calloc(degree, sizeof(uint64_t));
    for (uint32_t value_idx = 0; value_idx < degree; ++value_idx) {
        values[value_idx] = value_idx % plaintext_modulus;
        sum_values[value_idx] = (uint64_t)ccpolyzp_po2cyc_scalar_add_mod(values[value_idx], values[value_idx], t->value);
        prod_values[value_idx] = (uint64_t)ccpolyzp_po2cyc_scalar_mul_mod(values[value_idx], values[value_idx], t);
    }

    if (ccbfv_param_ctx_supports_simd_encoding(param_ctx)) {
        rv = ccbfv_encode_simd_uint64(plaintext, param_ctx, degree, values);
    } else {
        rv = ccbfv_encode_poly_uint64(plaintext, param_ctx, degree, values);
    }
    if (rv != CCERR_OK) {
        goto err_encode;
    }

    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    ccbfv_dcrt_plaintext_t dcrt_plaintext = (ccbfv_dcrt_plaintext_t)malloc(ccbfv_dcrt_plaintext_sizeof(param_ctx, nmoduli));
    rv = ccbfv_dcrt_plaintext_encode(dcrt_plaintext, plaintext, nmoduli);
    if (rv != CCERR_OK) {
        goto err_encode_dcrt;
    }

    ccbfv_rng_seed_t ciphertext_seed = (ccbfv_rng_seed_t)malloc(ccbfv_rng_seed_sizeof());
    const size_t ciphertext_size = ccbfv_ciphertext_sizeof(param_ctx, nmoduli, ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t ciphertext = (ccbfv_ciphertext_coeff_t)malloc(ciphertext_size);

    const size_t ciphertext_1_modulus_size = ccbfv_ciphertext_sizeof(param_ctx, 1, ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t ciphertext_1_modulus = (ccbfv_ciphertext_coeff_t)malloc(ciphertext_1_modulus_size);

    rv = ccbfv_encrypt_symmetric(ciphertext, plaintext, param_ctx, secret_key, nmoduli, ciphertext_seed, global_test_rng);
    rv |= ccbfv_encrypt_symmetric(ciphertext_1_modulus, plaintext, param_ctx, secret_key, 1, NULL, global_test_rng);
    if (rv != CCERR_OK) {
        goto err_encrypt;
    }

    common->param_ctx = param_ctx;
    common->secret_key = secret_key;
    common->values = values;
    common->sum_values = sum_values;
    common->prod_values = prod_values;
    common->plaintext = plaintext;
    common->dcrt_plaintext = dcrt_plaintext;
    common->ciphertext_seed = ciphertext_seed;
    common->ciphertext = ciphertext;
    common->ciphertext_1_modulus = ciphertext_1_modulus;

    return CCERR_OK;

err_encrypt:
    free(ciphertext);
    free(ciphertext_1_modulus);
    free(ciphertext_seed);
err_encode_dcrt:
    free(dcrt_plaintext);
err_encode:
    free(values);
    free(sum_values);
    free(prod_values);
    free(plaintext);
err_relin_key:
    free(relin_key);
err_secret_key:
    free(secret_key);
err_param_ctx:
    free(param_ctx);
    return rv;
}

/// @brief Free the memory used for common things
/// @param common The object to free
static void test_ccbfv_common_cleanup(ccbfv_public_test_common_const_t common)
{
    free(common->ciphertext);
    free(common->ciphertext_seed);
    free(common->values);
    free(common->plaintext);
    free(common->secret_key);
    free(common->param_ctx);
}

#define COMMON_SETUP(enc_params)                                         \
    struct ccbfv_public_test_common common_storage;                      \
    ccbfv_public_test_common_t common = &common_storage;                 \
    const int common_rv = test_ccbfv_common_setup(common, (enc_params)); \
    is_or_goto(common_rv, CCERR_OK, __func__, cleanup);                  \
    COMMON_SCOPE(common);

#define COMMON_SCOPE(common)                                                                  \
    CC_UNUSED ccbfv_param_ctx_const_t param_ctx = (common)->param_ctx;                        \
    CC_UNUSED ccbfv_secret_key_const_t secret_key = (common)->secret_key;                     \
    CC_UNUSED uint64_t *values = (common)->values;                                            \
    CC_UNUSED uint64_t *sum_values = (common)->sum_values;                                    \
    CC_UNUSED uint64_t *prod_values = (common)->prod_values;                                  \
    CC_UNUSED ccbfv_plaintext_t plaintext = (common)->plaintext;                              \
    CC_UNUSED ccbfv_dcrt_plaintext_t dcrt_plaintext = (common)->dcrt_plaintext;               \
    CC_UNUSED ccbfv_rng_seed_t ciphertext_seed = (common)->ciphertext_seed;                   \
    CC_UNUSED ccbfv_ciphertext_coeff_t ciphertext = (common)->ciphertext;                     \
    CC_UNUSED ccbfv_ciphertext_coeff_t ciphertext_1_modulus = (common)->ciphertext_1_modulus; \
    CC_UNUSED uint32_t degree = ccbfv_param_ctx_polynomial_degree(param_ctx);

#define COMMON_CLEANUP                     \
    cleanup:                               \
    if (common_rv == CCERR_OK) {           \
        test_ccbfv_common_cleanup(common); \
    }

static void test_ccbfv_param_ctx_plaintext_modulus_inverse(ccbfv_predefined_encryption_params_t enc_params)
{
    ccbfv_param_ctx_t param_ctx = (ccbfv_param_ctx_t)malloc(ccbfv_param_ctx_sizeof(enc_params));
    int rv = ccbfv_param_ctx_init(param_ctx, enc_params);
    if (rv != CCERR_OK) {
        goto err_param_ctx;
    }

    // (t - 1)^{-1} mod t = t - 1
    {
        uint64_t plaintext_modulus = ccbfv_param_ctx_plaintext_modulus(param_ctx);
        uint64_t inverse;
        rv = ccbfv_param_ctx_plaintext_modulus_inverse(&inverse, param_ctx, plaintext_modulus - 1);
        is(rv, CCERR_OK, "ccbfv_param_ctx_plaintext_modulus_inverse");
        is(inverse, plaintext_modulus - 1, "ccbfv_param_ctx_plaintext_modulus_inverse t - 1");
    }
    // (kt - 1))^{-1} mod t = t - 1 for integer k > 1
    {
        uint64_t plaintext_modulus = ccbfv_param_ctx_plaintext_modulus(param_ctx);
        uint64_t inverse;
        rv = ccbfv_param_ctx_plaintext_modulus_inverse(&inverse, param_ctx, 3 * plaintext_modulus - 1);
        is(rv, CCERR_OK, "ccbfv_param_ctx_plaintext_modulus_inverse");
        is(inverse, plaintext_modulus - 1, "ccbfv_param_ctx_plaintext_modulus_inverse 3t - 1");
    }

err_param_ctx:
    free(param_ctx);
}

static void test_ccbfv_decrypt_equal(ccbfv_public_test_common_const_t common,
                                     ccbfv_ciphertext_coeff_const_t ciphertext,
                                     const uint64_t *values)
{
    ccbfv_param_ctx_const_t param_ctx = common->param_ctx;
    uint32_t degree = ccbfv_param_ctx_polynomial_degree(param_ctx);
    ccbfv_secret_key_const_t secret_key = common->secret_key;

    ccbfv_plaintext_t plaintext = (ccbfv_plaintext_t)malloc(ccbfv_plaintext_sizeof(common->param_ctx));
    is(ccbfv_decrypt(plaintext, param_ctx, ciphertext, secret_key), CCERR_OK, "ccbfv_decrypt");
    uint64_t *decoded_values = calloc(degree, sizeof(uint64_t));
    if (ccbfv_param_ctx_supports_simd_encoding(param_ctx)) {
        is(ccbfv_decode_simd_uint64(degree, decoded_values, plaintext), CCERR_OK, "ccbfv_decode_simd_uint64");
    } else {
        is(ccbfv_decode_poly_uint64(degree, decoded_values, plaintext), CCERR_OK, "ccbfv_decode_poly_uint64");
    }
    is(array_eq_uint64(degree, decoded_values, values), true, "decoded != original");

    free(decoded_values);
}

static void test_ccbfv_encryption(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    test_ccbfv_decrypt_equal(common, ciphertext, values);

    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_ntt(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    is(ccbfv_ciphertext_fwd_ntt(ciphertext), CCERR_OK, "ccbfv_ciphertext_fwd_ntt");
    is(ccbfv_ciphertext_inv_ntt((ccbfv_ciphertext_eval_t)ciphertext), CCERR_OK, "ccbfv_ciphertext_inv_ntt");
    test_ccbfv_decrypt_equal(common, ciphertext, values);

    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_plaintext_add(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const size_t ciphertext_size = ccbfv_ciphertext_sizeof(param_ctx, nmoduli, ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t sum = (ccbfv_ciphertext_coeff_t)malloc(ciphertext_size);
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context(param_ctx);
    ccbfv_ciphertext_coeff_init(sum, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);

    is(ccbfv_ciphertext_plaintext_add(sum, ciphertext, plaintext), CCERR_OK, "ccbfv_ciphertext_plaintext_add");
    if (ccbfv_param_ctx_supports_simd_encoding(param_ctx)) {
        test_ccbfv_decrypt_equal(common, sum, sum_values);
    }
    free(sum);

    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_coeff_plaintext_mul(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const size_t ciphertext_size = ccbfv_ciphertext_sizeof(param_ctx, nmoduli, ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t prod = (ccbfv_ciphertext_coeff_t)malloc(ciphertext_size);
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context(param_ctx);
    ccbfv_ciphertext_coeff_init(prod, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);

    is(ccbfv_ciphertext_coeff_plaintext_mul(prod, ciphertext, plaintext), CCERR_OK, "ccbfv_ciphertext_coeff_plaintext_mul");
    if (ccbfv_param_ctx_supports_simd_encoding(param_ctx)) {
        test_ccbfv_decrypt_equal(common, prod, prod_values);
    }
    free(prod);

    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_eval_plaintext_mul(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const size_t ciphertext_size = ccbfv_ciphertext_sizeof(param_ctx, nmoduli, ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t prod = (ccbfv_ciphertext_coeff_t)malloc(ciphertext_size);
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context(param_ctx);
    ccbfv_ciphertext_coeff_init(prod, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);

    is(ccbfv_ciphertext_fwd_ntt(ciphertext), CCERR_OK, "ccbfv_ciphertext_fwd_ntt");
    is(ccbfv_ciphertext_eval_plaintext_mul((ccbfv_ciphertext_eval_t)prod, (ccbfv_ciphertext_eval_const_t)ciphertext, plaintext),
       CCERR_OK,
       "ccbfv_ciphertext_eval_plaintext_mul");
    is(ccbfv_ciphertext_inv_ntt((ccbfv_ciphertext_eval_t)prod), CCERR_OK, "ccbfv_ciphertext_inv_ntt");
    if (ccbfv_param_ctx_supports_simd_encoding(param_ctx)) {
        test_ccbfv_decrypt_equal(common, prod, prod_values);
    }
    free(prod);

    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_coeff_dcrt_plaintext_mul(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const size_t ciphertext_size = ccbfv_ciphertext_sizeof(param_ctx, nmoduli, ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t prod = (ccbfv_ciphertext_coeff_t)malloc(ciphertext_size);
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context(param_ctx);
    ccbfv_ciphertext_coeff_init(prod, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);

    is(ccbfv_ciphertext_coeff_dcrt_plaintext_mul(prod, ciphertext, dcrt_plaintext),
       CCERR_OK,
       "ccbfv_ciphertext_coeff_dcrt_plaintext_mul");
    if (ccbfv_param_ctx_supports_simd_encoding(param_ctx)) {
        test_ccbfv_decrypt_equal(common, prod, prod_values);
    }
    free(prod);

    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_eval_dcrt_plaintext_mul(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const size_t ciphertext_size = ccbfv_ciphertext_sizeof(param_ctx, nmoduli, ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_t prod = (ccbfv_ciphertext_coeff_t)malloc(ciphertext_size);
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context(param_ctx);
    ccbfv_ciphertext_coeff_init(prod, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);

    is(ccbfv_ciphertext_fwd_ntt(ciphertext), CCERR_OK, "ccbfv_ciphertext_fwd_ntt");
    is(ccbfv_ciphertext_eval_dcrt_plaintext_mul(
           (ccbfv_ciphertext_eval_t)prod, (ccbfv_ciphertext_eval_const_t)ciphertext, dcrt_plaintext),
       CCERR_OK,
       "ccbfv_ciphertext_eval_dcrt_plaintext_mul");
    is(ccbfv_ciphertext_inv_ntt((ccbfv_ciphertext_eval_t)prod), CCERR_OK, "ccbfv_ciphertext_inv_ntt");
    if (ccbfv_param_ctx_supports_simd_encoding(param_ctx)) {
        test_ccbfv_decrypt_equal(common, prod, prod_values);
    }
    free(prod);

    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_serialization_coeff(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    const size_t nbytes = ccbfv_serialize_ciphertext_coeff_nbytes(ciphertext, NULL);
    uint8_t *bytes = malloc(nbytes);

    is(ccbfv_serialize_ciphertext_coeff(nbytes, bytes, ciphertext, NULL), CCERR_OK, "ccbfv_serialize_ciphertext_coeff");
    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const uint32_t npolys = 2;

    ccbfv_ciphertext_coeff_t deserialized = (ccbfv_ciphertext_coeff_t)malloc(ccbfv_ciphertext_sizeof(param_ctx, nmoduli, npolys));
    is(ccbfv_deserialize_ciphertext_coeff(deserialized, nbytes, bytes, param_ctx, nmoduli, npolys, NULL),
       CCERR_OK,
       "ccbfv_deserialize_ciphertext_coeff");
    test_ccbfv_decrypt_equal(common, deserialized, values);

    free(deserialized);
    free(bytes);
    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_serialization_coeff_skip_lsbs(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    // Given a ciphertext of two polynomials (b, a), the low l' := floor(log2(q / t)) - 1 bits are unused during decryption.
    // Decryption of a message `m_e` is computed as `round(m_e * t / q)`. Note, the MSB decimal bit of `m_e * t / q` is used
    // to ensure correct rounding, hence why `l' = floor(log2(q / t)) - 1` rather than `floor(log2(q / t))`.
    // We write `b = b_L + b_H 2^{l_b}` and `a = a_H + 2^{l_a} + a_L`, where `{a, b}_L` are the LSBs, and
    // `{a, b}_H` are the MSBs of `a, b` respectively.
    // So, we have `b + as = b_L + a_L s + b_H 2^{l_b} + a_H s 2^{l_a}`.
    // If `b_L + a_L s < 2^{l'}`, we can omit `b_L` and `b_L` from serialization without decryption error.

    // Since s is uniform ternary {-1, 0, 1}, and a ~ U[0, 2^a),
    // Var(a_L s) = (2N / 9) * 2^{2 l_a}, so by the central limit theorem,
    // with probability p > 1 - 2^-49.5, |a_L s| < z_score * sqrt(Var(a_L * s)).
    // Hence, we need `z_score * sqrt(2N/9) * 2^{l_a} + 2^{l_b} < 2^{l'}
    // Setting `l_b = l' - 1`, this yields
    // `z_score * sqrt(2N/9) * 2^{l_a} < 2^{l'-1}`, iff
    // `log2(z_score * sqrt(2N/9)) + l_a < l' - 1`, iff
    // `l_a < l' - 1 - log2(z_score * sqrt(2N/9))`, which is true for
    // `l_a = floor(l' - 1 - log2(z_score * sqrt(2N/9)))`
    // We use a relatively large `z_score=8` since we are decrypting `N`
    // coefficients, rather than a single LWE coefficient. This yields a
    // a per-coefficient decryption error Pr(|x| > z_score), where `x ~ N(0, 1)`.
    // This yields a per-coefficient decryption error `< 2^-49.5` .
    // By union bound, the message decryption error is
    // `< 2^(log2(N) - 49.5) = 2^-36.5` for `N=8192`
    uint32_t expected_nskip_lsbs[CCBFV_CIPHERTEXT_FRESH_NPOLYS] = { 0 };
    uint64_t t = ccbfv_param_ctx_plaintext_modulus(param_ctx);
    uint64_t q = ccbfv_param_ctx_coefficient_moduli(param_ctx)[0];
    uint32_t l_prime = (q >= 2 * t) ? ccpolyzp_po2cyc_log2_uint64(q / t) - 1 : 0;
    expected_nskip_lsbs[0] = l_prime >= 1 ? l_prime - 1 : 0;
    uint32_t n = ccbfv_param_ctx_polynomial_degree(param_ctx);
    double z_score = 8;
    uint64_t tmp = (uint64_t)(z_score * sqrt(2. * (double)n / 9.));
    uint32_t log2_tmp = tmp > 0 ? ccpolyzp_po2cyc_ceil_log2_uint64(tmp) : 0;
    expected_nskip_lsbs[1] = l_prime >= log2_tmp + 1 ? l_prime - 1 - log2_tmp : 0;

    const uint32_t nmoduli = 1;
    uint32_t nskip_lsbs[CCBFV_CIPHERTEXT_FRESH_NPOLYS] = { 0 };
    ccbfv_serialize_ciphertext_coeff_max_nskip_lsbs(nskip_lsbs, ciphertext_1_modulus);
    is(array_eq_uint32(ccbfv_ciphertext_fresh_npolys(), expected_nskip_lsbs, nskip_lsbs),
       true,
       "ccbfv_serialize_ciphertext_coeff_max_nskip_lsbs");

    const size_t nbytes = ccbfv_serialize_ciphertext_coeff_nbytes(ciphertext_1_modulus, nskip_lsbs);
    uint8_t *bytes = malloc(nbytes);
    is(ccbfv_serialize_ciphertext_coeff(nbytes, bytes, ciphertext_1_modulus, nskip_lsbs),
       CCERR_OK,
       "ccbfv_serialize_ciphertext_coeff");

    const uint32_t npolys = 2;
    ccbfv_ciphertext_coeff_t deserialized = (ccbfv_ciphertext_coeff_t)malloc(ccbfv_ciphertext_sizeof(param_ctx, nmoduli, npolys));
    is(ccbfv_deserialize_ciphertext_coeff(deserialized, nbytes, bytes, param_ctx, nmoduli, npolys, nskip_lsbs),
       CCERR_OK,
       "ccbfv_deserialize_ciphertext_coeff");
    test_ccbfv_decrypt_equal(common, deserialized, values);

    free(deserialized);
    free(bytes);
    COMMON_CLEANUP
}

static void test_ccbfv_ciphertext_serialization_eval(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    is(ccbfv_ciphertext_fwd_ntt(ciphertext), CCERR_OK, "ccbfv_ciphertext_fwd_ntt");
    ccbfv_ciphertext_eval_t ciphertext_eval = (ccbfv_ciphertext_eval_t)ciphertext;

    const size_t nbytes = ccbfv_serialize_ciphertext_eval_nbytes(ciphertext_eval);
    uint8_t *bytes = malloc(nbytes);

    is(ccbfv_serialize_ciphertext_eval(nbytes, bytes, ciphertext_eval), CCERR_OK, "ccbfv_serialize_ciphertext_eval");
    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const uint32_t npolys = 2;

    ccbfv_ciphertext_eval_t deserialized = (ccbfv_ciphertext_eval_t)malloc(ccbfv_ciphertext_sizeof(param_ctx, nmoduli, npolys));
    is(ccbfv_deserialize_ciphertext_eval(deserialized, nbytes, bytes, param_ctx, nmoduli, npolys),
       CCERR_OK,
       "ccbfv_deserialize_ciphertext_coeff");
    is(ccbfv_ciphertext_inv_ntt(deserialized), CCERR_OK, "ccbfv_ciphertext_inv_ntt");
    ccbfv_ciphertext_coeff_t deserialized_coeff = (ccbfv_ciphertext_coeff_t)deserialized;
    test_ccbfv_decrypt_equal(common, deserialized_coeff, values);

    free(deserialized);
    free(bytes);
    COMMON_CLEANUP
}

static void test_ccbfv_seeded_ciphertext_serialization_coeff(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    const size_t nbytes = ccbfv_serialize_seeded_ciphertext_coeff_nbytes(ciphertext);
    uint8_t *bytes = malloc(nbytes);

    is(ccbfv_serialize_seeded_ciphertext_coeff(nbytes, bytes, ciphertext), CCERR_OK, "ccbfv_serialize_seeded_ciphertext_coeff");
    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);

    ccbfv_ciphertext_coeff_t deserialized =
        (ccbfv_ciphertext_coeff_t)malloc(ccbfv_ciphertext_sizeof(param_ctx, nmoduli, ccbfv_ciphertext_fresh_npolys()));
    is(ccbfv_deserialize_seeded_ciphertext_coeff(deserialized, nbytes, bytes, ciphertext_seed, param_ctx, nmoduli),
       CCERR_OK,
       "ccbfv_deserialize_seeded_ciphertext_coeff");
    test_ccbfv_decrypt_equal(common, deserialized, values);

    free(deserialized);
    free(bytes);
    COMMON_CLEANUP
}

static void test_ccbfv_seeded_ciphertext_serialization_eval(ccbfv_predefined_encryption_params_t enc_params)
{
    COMMON_SETUP(enc_params);

    is(ccbfv_ciphertext_fwd_ntt(ciphertext), CCERR_OK, "ccbfv_ciphertext_fwd_ntt");
    ccbfv_ciphertext_eval_t ciphertext_eval = (ccbfv_ciphertext_eval_t)ciphertext;

    const size_t nbytes = ccbfv_serialize_seeded_ciphertext_eval_nbytes(ciphertext_eval);
    uint8_t *bytes = malloc(nbytes);

    is(ccbfv_serialize_seeded_ciphertext_eval(nbytes, bytes, ciphertext_eval),
       CCERR_OK,
       "ccbfv_serialize_seeded_ciphertext_eval");
    const uint32_t nmoduli = ccbfv_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    const uint32_t npolys = 2;

    ccbfv_ciphertext_eval_t deserialized = (ccbfv_ciphertext_eval_t)malloc(ccbfv_ciphertext_sizeof(param_ctx, nmoduli, npolys));
    is(ccbfv_deserialize_seeded_ciphertext_eval(deserialized, nbytes, bytes, ciphertext_seed, param_ctx, nmoduli),
       CCERR_OK,
       "ccbfv_deserialize_seeded_ciphertext_eval");
    is(ccbfv_ciphertext_inv_ntt(deserialized), CCERR_OK, "ccbfv_ciphertext_inv_ntt");
    ccbfv_ciphertext_coeff_t deserialized_coeff = (ccbfv_ciphertext_coeff_t)deserialized;
    test_ccbfv_decrypt_equal(common, deserialized_coeff, values);

    free(deserialized);
    free(bytes);
    COMMON_CLEANUP
}

static uint32_t ceil_log2(uint64_t x)
{
    return ccpolyzp_po2cyc_ceil_log2_uint64(x);
}

static void test_ccbfv_encryption_params_case(ccbfv_predefined_encryption_params_t enc_params,
                                              uint32_t degree,
                                              size_t nmoduli,
                                              uint32_t *cc_counted_by(nmoduli) log2_moduli,
                                              uint32_t log2_plaintext,
                                              bool supports_simd_encoding)
{
    is(ccbfv_encryption_params_polynomial_degree(enc_params), degree, "ccbfv_encryption_params_polynomial_degree");
    is(ccbfv_encryption_params_coefficient_nmoduli(enc_params), nmoduli, "ccbfv_encryption_params_coefficient_nmoduli");
    uint64_t moduli[nmoduli];
    ccbfv_encryption_params_coefficient_moduli(nmoduli, moduli, enc_params);
    bool mismatch = false;
    for (uint32_t mod_idx = 0; mod_idx < nmoduli; ++mod_idx) {
        mismatch |= ceil_log2(moduli[mod_idx]) != log2_moduli[mod_idx];
    }
    is(mismatch, false, "ccbfv_encryption_params_coefficient_moduli");
    uint64_t plaintext_modulus = ccbfv_encryption_params_plaintext_modulus(enc_params);
    is(ceil_log2(plaintext_modulus), log2_plaintext, "ccbfv_encryption_params_plaintext_modulus");

    ccbfv_param_ctx_t param_ctx = (ccbfv_param_ctx_t)malloc(ccbfv_param_ctx_sizeof(enc_params));
    int rv = ccbfv_param_ctx_init(param_ctx, enc_params);
    is(rv, CCERR_OK, "ccbfv_param_ctx_init");
    is(ccbfv_param_ctx_supports_simd_encoding(param_ctx), supports_simd_encoding, "ccbfv_param_ctx_supports_simd_encoding");
    {
        bool mismatch = false;
        for (uint32_t mod_idx = 0; mod_idx < nmoduli; ++mod_idx) {
            mismatch |= (ccbfv_param_ctx_coefficient_moduli(param_ctx)[mod_idx] != moduli[mod_idx]);
        }
        is(mismatch, false, "ccbfv_param_ctx_coefficient_moduli");
    }

    free(param_ctx);
}

static void test_ccbfv_encryption_params(void)
{
    {
        uint32_t log2_moduli[] = { 18, 18, 18, 18, 18 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_8_LOGQ_5x18_LOGT_5, 8, 5, log2_moduli, 5, true);
    }
    {
        uint32_t log2_moduli[] = { 60, 60, 60, 60 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_512_LOGQ_4x60_LOGT_20, 512, 4, log2_moduli, 20, true);
    }
    {
        uint32_t log2_moduli[] = { 27, 28, 28 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_13, 4096, 3, log2_moduli, 13, false);
    }
    {
        uint32_t log2_moduli[] = { 55, 55, 55 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_42, 8192, 3, log2_moduli, 42, true);
    }
    {
        uint32_t log2_moduli[] = { 55, 55, 55 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_30, 8192, 3, log2_moduli, 30, true);
    }
    {
        uint32_t log2_moduli[] = { 55, 55, 55 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_29, 8192, 3, log2_moduli, 29, true);
    }
    {
        uint32_t log2_moduli[] = { 27, 28, 28 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_5, 4096, 3, log2_moduli, 5, false);
    }
    {
        uint32_t log2_moduli[] = { 55, 55, 55 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_24, 8192, 3, log2_moduli, 24, true);
    }
    {
        uint32_t log2_moduli[] = { 29, 60, 60 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_29_60_60_LOGT_15, 8192, 3, log2_moduli, 15, false);
    }
    {
        uint32_t log2_moduli[] = { 40, 60, 60 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_40_60_60_LOGT_26, 8192, 3, log2_moduli, 26, true);
    }
    {
        uint32_t log2_moduli[] = { 28, 60, 60 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_28_60_60_LOGT_20, 8192, 3, log2_moduli, 20, true);
    }
    {
        uint32_t log2_moduli[] = { 16, 33, 33 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_16_33_33_LOGT_4, 4096, 3, log2_moduli, 4, false);
    }
    {
        uint32_t log2_moduli[] = { 60 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_16_LOGQ_60_LOGT_15, 16, 1, log2_moduli, 15, true);
    }
    {
        uint32_t log2_moduli[] = { 27, 28, 28 };
        test_ccbfv_encryption_params_case(
            CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_6, 4096, 3, log2_moduli, 6, false);
    }
}

int ntests_ccbfv_public(void)
{
    int nall_params_tests = 0;
    int nsimd_tests = 0;

    nall_params_tests += 7; // test_ccbfv_encryption_params
    nall_params_tests += 4; // test_ccbfv_param_ctx_plaintext_modulus_inverse
    nall_params_tests += 4; // test_ccbfv_encryption
    nall_params_tests += 6; // test_ccbfv_ciphertext_ntt
    // test_ccbfv_ciphertext_plaintext_add
    nsimd_tests += 3;
    nall_params_tests += 2;
    //  test_ccbfv_ciphertext_coeff_plaintext_mul
    nsimd_tests += 3;
    nall_params_tests += 2;
    //   test_ccbfv_ciphertext_eval_plaintext_mul
    nsimd_tests += 3;
    nall_params_tests += 4;
    // test_ccbfv_ciphertext_coeff_dcrt_plaintext_mul
    nsimd_tests += 3;
    nall_params_tests += 2;
    //  test_ccbfv_ciphertext_eval_dcrt_plaintext_mul
    nsimd_tests += 3;
    nall_params_tests += 4;
    nall_params_tests += 6; // test_ccbfv_ciphertext_serialization_coeff
    nall_params_tests += 7; // test_ccbfv_ciphertext_serialization_coeff_skip_lsbs
    nall_params_tests += 8; // test_ccbfv_ciphertext_serialization_eval
    nall_params_tests += 6; // test_ccbfv_seeded_ciphertext_serialization_coeff
    nall_params_tests += 8; // test_ccbfv_seeded_ciphertext_serialization_eval

    nall_params_tests *= CCBFV_PREDEFINED_ENCRYPTION_PARAMS_COUNT;
    nsimd_tests *= CCBFV_PREDEFINED_ENCRYPTION_PARAMS_SIMD_COUNT;

    int ntests = nall_params_tests + nsimd_tests;
    return ntests;
}

void test_ccbfv_public(void)
{
    test_ccbfv_encryption_params();
    for (uint32_t i = 0; i < CCBFV_PREDEFINED_ENCRYPTION_PARAMS_COUNT; ++i) {
        test_ccbfv_param_ctx_plaintext_modulus_inverse(i);
        test_ccbfv_encryption(i);
        test_ccbfv_ciphertext_ntt(i);
        test_ccbfv_ciphertext_plaintext_add(i);
        test_ccbfv_ciphertext_coeff_plaintext_mul(i);
        test_ccbfv_ciphertext_eval_plaintext_mul(i);
        test_ccbfv_ciphertext_coeff_dcrt_plaintext_mul(i);
        test_ccbfv_ciphertext_eval_dcrt_plaintext_mul(i);
        test_ccbfv_ciphertext_serialization_coeff(i);
        test_ccbfv_ciphertext_serialization_coeff_skip_lsbs(i);
        test_ccbfv_ciphertext_serialization_eval(i);
        test_ccbfv_seeded_ciphertext_serialization_coeff(i);
        test_ccbfv_seeded_ciphertext_serialization_eval(i);
    }
}
