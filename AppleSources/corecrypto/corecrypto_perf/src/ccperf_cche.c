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

#include "ccperf.h"
#include <math.h>
#include <corecrypto/ccrng.h>
#include "cche_priv.h"
#include "testmore.h"

static const size_t perf_degrees[] = {
    4096,
    8192,
};

static cche_predefined_encryption_params_t perf_get_params(uint32_t degree)
{
    switch (degree) {
    case 4096:
        return CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_13;
    case 8192:
        return CCHE_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_42;
    default:
        cc_printf("perf_get_params invalid degree (%" PRIu32 " degree)", degree);
        abort();
    }
};

/// @brief Holds pre-computed values used in benchmarks
struct cche_perf_common {
    /// Tracker for if the struct has been set up
    bool is_setup;
    /// parameter context
    cche_param_ctx_t param_ctx;
    /// secret key
    cche_secret_key_t secret_key;
    /// relinearization key
    cche_relin_key_t relin_key;
    /// Galois key
    cche_galois_key_t galois_key;
    /// Galois elements
    uint32_t *galois_elts;
    /// number of Galois elements
    uint32_t ngalois_elts;
    /// encoding values
    uint64_t *encoding_values;
    /// plaintext
    cche_plaintext_t plaintext;
    /// double-CRT plaintext
    cche_dcrt_plaintext_t dcrt_plaintext;
    /// ciphertext seed
    cche_rng_seed_t ciphertext_seed;
    /// ciphertext
    cche_ciphertext_coeff_t ciphertext;
};

typedef struct cche_perf_common *cche_perf_common_t;
typedef const struct cche_perf_common *cche_perf_common_const_t;

static struct cche_perf_common cche_bfv_perf_common_4096;
static struct cche_perf_common cche_bgv_perf_common_4096;
static struct cche_perf_common cche_bfv_perf_common_8192;
static struct cche_perf_common cche_bgv_perf_common_8192;

static cche_perf_common_t perf_get_common_setup(uint32_t degree, cche_scheme_t he_scheme)
{
    switch (degree) {
    case 4096:
        switch (he_scheme) {
        case CCHE_SCHEME_BFV:
            return &cche_bfv_perf_common_4096;
        case CCHE_SCHEME_BGV:
            return &cche_bgv_perf_common_4096;
        default:
            cc_printf(
                "perf_get_common_setup invalid scheme (%" PRIu8 " scheme) for degree (%" PRIu32 " degree)", he_scheme, degree);
            abort();
        }
    case 8192:
        switch (he_scheme) {
        case CCHE_SCHEME_BFV:
            return &cche_bfv_perf_common_8192;
        case CCHE_SCHEME_BGV:
            return &cche_bgv_perf_common_8192;
        default:
            cc_printf(
                "perf_get_common_setup invalid scheme (%" PRIu8 " scheme) for degree (%" PRIu32 " degree)", he_scheme, degree);
            abort();
        }
    default:
        cc_printf("perf_get_common_setup invalid degree (%" PRIu32 " degree)", degree);
        abort();
    }
};

/// @brief Set up the common structures
/// @param common The common structure to set up
/// @param enc_params The encryption parameters
/// @param he_scheme The homomorphic encryption scheme
/// @return `CCERR_OK` if initialization succeeds
/// @details To avoid memory leak, one should call `perf_cche_common_cleanup` after using `common`.
static int
perf_cche_common_setup(cche_perf_common_t common, cche_predefined_encryption_params_t enc_params, cche_scheme_t he_scheme)
{
    if (common->is_setup) {
        return CCERR_OK;
    }
    cche_param_ctx_t param_ctx = (cche_param_ctx_t)malloc(cche_param_ctx_sizeof(enc_params));
    int rv = cche_param_ctx_init(param_ctx, he_scheme, enc_params);
    if (rv != CCERR_OK) {
        goto err_param_ctx;
    }

    cche_secret_key_t secret_key = (cche_secret_key_t)malloc(cche_secret_key_sizeof(param_ctx));
    rv = cche_secret_key_generate(secret_key, param_ctx, rng);
    if (rv != CCERR_OK) {
        goto err_secret_key;
    }

    cche_relin_key_t relin_key = (cche_relin_key_t)malloc(cche_relin_key_sizeof(param_ctx));
    rv = cche_relin_key_generate(relin_key, secret_key, param_ctx, 0, NULL, rng);
    if (rv != CCERR_OK) {
        goto err_relin_key;
    }

    uint32_t degree = cche_param_ctx_polynomial_degree(param_ctx);
    uint32_t ngalois_elts = 3;
    uint32_t *galois_elts = calloc(ngalois_elts, sizeof(uint32_t));
    rv |= cche_ciphertext_galois_elt_rotate_rows_left(&galois_elts[0], 1, degree);
    rv |= cche_ciphertext_galois_elt_rotate_rows_right(&galois_elts[1], 1, degree);
    rv |= cche_ciphertext_galois_elt_swap_columns(&galois_elts[2], degree);
    cche_galois_key_t galois_key = (cche_galois_key_t)malloc(cche_galois_key_sizeof(param_ctx, ngalois_elts));
    rv |= cche_galois_key_generate(galois_key, ngalois_elts, galois_elts, secret_key, param_ctx, 0, NULL, rng);
    if (rv != CCERR_OK) {
        goto err_galois_key;
    }

    cche_plaintext_t plaintext = (cche_plaintext_t)malloc(cche_plaintext_sizeof(param_ctx));

    uint64_t plaintext_modulus = cche_param_ctx_plaintext_modulus(param_ctx);
    uint64_t *encoding_values = calloc(degree, sizeof(uint64_t));
    for (uint32_t value_idx = 0; value_idx < degree; ++value_idx) {
        encoding_values[value_idx] = value_idx % plaintext_modulus;
    }
    rv = cche_encode_poly_uint64(plaintext, param_ctx, degree, encoding_values);
    if (rv != CCERR_OK) {
        goto err_encode;
    }

    const uint32_t nmoduli = cche_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    cche_dcrt_plaintext_t dcrt_plaintext = (cche_dcrt_plaintext_t)malloc(cche_dcrt_plaintext_sizeof(param_ctx, nmoduli));
    rv = cche_dcrt_plaintext_encode(dcrt_plaintext, plaintext, param_ctx, nmoduli);
    if (rv != CCERR_OK) {
        goto err_encode_dcrt;
    }

    cche_rng_seed_t ciphertext_seed = (cche_rng_seed_t)malloc(cche_rng_seed_sizeof());
    const size_t ciphertext_size = cche_ciphertext_sizeof(param_ctx, nmoduli, cche_ciphertext_fresh_npolys());
    uint8_t *ciphertext_state = malloc(ciphertext_size);
    cche_ciphertext_coeff_t ciphertext = (cche_ciphertext_coeff_t)ciphertext_state;
    rv = cche_encrypt_symmetric(ciphertext, plaintext, param_ctx, secret_key, nmoduli, ciphertext_seed, rng);
    if (rv != CCERR_OK) {
        goto err_encrypt;
    }

    common->param_ctx = param_ctx;
    common->secret_key = secret_key;
    common->relin_key = relin_key;
    common->galois_key = galois_key;
    common->galois_elts = galois_elts;
    common->ngalois_elts = ngalois_elts;
    common->encoding_values = encoding_values;
    common->plaintext = plaintext;
    common->dcrt_plaintext = dcrt_plaintext;
    common->ciphertext_seed = ciphertext_seed;
    common->ciphertext = ciphertext;
    common->is_setup = true;

    return CCERR_OK;

err_encrypt:
    free(ciphertext);
    free(ciphertext_seed);
err_encode_dcrt:
    free(dcrt_plaintext);
err_encode:
    free(encoding_values);
    free(plaintext);
err_galois_key:
    free(galois_key);
    free(galois_elts);
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
static void perf_cche_common_cleanup(cche_perf_common_const_t common)
{
    free(common->ciphertext);
    free(common->ciphertext_seed);
    free(common->encoding_values);
    free(common->plaintext);
    free(common->dcrt_plaintext);
    free(common->galois_key);
    free(common->galois_elts);
    free(common->relin_key);
    free(common->secret_key);
    free(common->param_ctx);
}

/// @brief Frees the memory used by the common structures, for a certain scheme
static void perf_cche_cleanup(cche_scheme_t he_scheme)
{
    for (size_t i = 0; i < CC_ARRAY_LEN(perf_degrees); i++) {
        uint32_t degree = (uint32_t)perf_degrees[i];
        cche_perf_common_t common = perf_get_common_setup(degree, he_scheme);
        common->is_setup = false;
        perf_cche_common_cleanup(common);
    }
}

static void perf_cche_bfv_cleanup(void)
{
    perf_cche_cleanup(CCHE_SCHEME_BFV);
}

static void perf_cche_bgv_cleanup(void)
{
    perf_cche_cleanup(CCHE_SCHEME_BGV);
}

static double perf_cche_param_ctx_init(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_t param_ctx = perf_setup->param_ctx;

    perf_start();
    do {
        if (cche_param_ctx_init(param_ctx, he_scheme, encrypt_params) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_secret_key_generate(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    cche_secret_key_t secret_key = perf_setup->secret_key;

    perf_start();
    do {
        if (cche_secret_key_generate(secret_key, param_ctx, rng) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_relin_key_generate(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    cche_secret_key_t secret_key = perf_setup->secret_key;
    cche_relin_key_t relin_key = perf_setup->relin_key;

    perf_start();
    do {
        if (cche_relin_key_generate(relin_key, secret_key, param_ctx, 0, NULL, rng) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_galois_key_generate(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    cche_secret_key_t secret_key = perf_setup->secret_key;
    cche_galois_key_t galois_key = perf_setup->galois_key;
    uint32_t ngalois_elts = perf_setup->ngalois_elts;
    const uint32_t *galois_elts = perf_setup->galois_elts;

    perf_start();
    do {
        if (cche_galois_key_generate(galois_key, ngalois_elts, galois_elts, secret_key, param_ctx, 0, NULL, rng) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_encode_poly_uint64(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    cche_plaintext_t plaintext = perf_setup->plaintext;
    const uint64_t *encoding_values = perf_setup->encoding_values;

    perf_start();
    do {
        if (cche_encode_poly_uint64(plaintext, param_ctx, degree, encoding_values) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_decode_poly_uint64(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_plaintext_t plaintext = perf_setup->plaintext;
    uint64_t *encoding_values = perf_setup->encoding_values;

    perf_start();
    do {
        if (cche_decode_poly_uint64(degree, encoding_values, plaintext) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_encode_simd_uint64(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    cche_plaintext_t plaintext = perf_setup->plaintext;
    const uint64_t *encoding_values = perf_setup->encoding_values;

    perf_start();
    do {
        if (cche_encode_simd_uint64(plaintext, param_ctx, degree, encoding_values) != CCERR_OK) {
            // Don't abort, since not all parameter contexts support SIMD encoding
            return NAN;
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_decode_simd_uint64(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    cche_plaintext_t plaintext = perf_setup->plaintext;
    uint64_t *encoding_values = perf_setup->encoding_values;

    perf_start();
    do {
        if (cche_decode_simd_uint64(param_ctx, degree, encoding_values, plaintext) != CCERR_OK) {
            // Don't abort, since not all parameter contexts support SIMD encoding
            return NAN;
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_encrypt(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    uint32_t nmoduli = cche_param_ctx_ciphertext_ctx_nmoduli(param_ctx);
    cche_plaintext_t plaintext = perf_setup->plaintext;
    cche_ciphertext_coeff_t ciphertext = perf_setup->ciphertext;
    cche_secret_key_t secret_key = perf_setup->secret_key;
    cche_rng_seed_t ciphertext_seed = perf_setup->ciphertext_seed;

    perf_start();
    do {
        if (cche_encrypt_symmetric(ciphertext, plaintext, param_ctx, secret_key, nmoduli, ciphertext_seed, rng) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_decrypt(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_param_ctx_const_t param_ctx = perf_setup->param_ctx;
    cche_plaintext_t plaintext = perf_setup->plaintext;
    cche_ciphertext_coeff_t ciphertext = perf_setup->ciphertext;
    cche_secret_key_t secret_key = perf_setup->secret_key;

    perf_start();
    do {
        if (cche_decrypt(plaintext, param_ctx, ciphertext, secret_key) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_ciphertext_fwd_ntt(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_ciphertext_coeff_t ciphertext = perf_setup->ciphertext;

    perf_start();
    do {
        if (cche_ciphertext_fwd_ntt(ciphertext) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_ciphertext_inv_ntt(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_ciphertext_coeff_t ciphertext = perf_setup->ciphertext;

    perf_start();
    do {
        if (cche_ciphertext_inv_ntt((cche_ciphertext_eval_t)ciphertext) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_ciphertext_plaintext_add(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_ciphertext_coeff_t ciphertext = perf_setup->ciphertext;
    cche_plaintext_t plaintext = perf_setup->plaintext;

    perf_start();
    do {
        if (cche_ciphertext_plaintext_add(ciphertext, ciphertext, plaintext) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_ciphertext_coeff_plaintext_mul(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_ciphertext_coeff_t ciphertext = perf_setup->ciphertext;
    cche_plaintext_t plaintext = perf_setup->plaintext;

    perf_start();
    do {
        if (cche_ciphertext_coeff_plaintext_mul(ciphertext, ciphertext, plaintext) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

static double perf_cche_ciphertext_coeff_dcrt_plaintext_mul(size_t loops, uint32_t degree, cche_scheme_t he_scheme)
{
    cche_predefined_encryption_params_t encrypt_params = perf_get_params(degree);
    cche_perf_common_t perf_setup = perf_get_common_setup(degree, he_scheme);
    if (perf_cche_common_setup(perf_setup, encrypt_params, he_scheme) != CCERR_OK) {
        cc_abort("Error during perf_cche_common_setup");
    }
    cche_ciphertext_coeff_t ciphertext = perf_setup->ciphertext;
    cche_dcrt_plaintext_t dcrt_plaintext = perf_setup->dcrt_plaintext;

    perf_start();
    do {
        if (cche_ciphertext_coeff_dcrt_plaintext_mul(ciphertext, ciphertext, dcrt_plaintext) != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);
    double perf_res = perf_seconds();
    return perf_res;
}

#define TEST(_x)                       \
    {                                  \
        .name = #_x, .func = perf_##_x \
    }

static struct cche_perf_test {
    /// Benchmark name
    const char *name;
    /// Benchmark function
    double (*func)(size_t loops, uint32_t degree, cche_scheme_t he_scheme);
} cche_bfv_perf_tests[] = {
    TEST(cche_param_ctx_init),
    TEST(cche_secret_key_generate),
    TEST(cche_relin_key_generate),
    TEST(cche_galois_key_generate),
    // Encoding
    TEST(cche_encode_poly_uint64),
    TEST(cche_decode_poly_uint64),
    TEST(cche_encode_simd_uint64),
    TEST(cche_decode_simd_uint64),
    // Encryption
    TEST(cche_encrypt),
    TEST(cche_decrypt),
    // HE operations
    TEST(cche_ciphertext_fwd_ntt),
    TEST(cche_ciphertext_inv_ntt),
    TEST(cche_ciphertext_plaintext_add),
    TEST(cche_ciphertext_coeff_plaintext_mul),
    TEST(cche_ciphertext_coeff_dcrt_plaintext_mul),
};

static struct cche_perf_test cche_bgv_perf_tests[] = {
    TEST(cche_param_ctx_init),
    TEST(cche_secret_key_generate),
    TEST(cche_relin_key_generate),
    TEST(cche_galois_key_generate),
    // Encoding
    TEST(cche_encode_poly_uint64),
    TEST(cche_decode_poly_uint64),
    TEST(cche_encode_simd_uint64),
    TEST(cche_decode_simd_uint64),
    // Encryption
    TEST(cche_encrypt),
    TEST(cche_decrypt),
    // HE operations
    TEST(cche_ciphertext_fwd_ntt),
    TEST(cche_ciphertext_inv_ntt),
    TEST(cche_ciphertext_plaintext_add),
    TEST(cche_ciphertext_coeff_plaintext_mul),
    TEST(cche_ciphertext_coeff_dcrt_plaintext_mul),
};

static double perf_cche_bfv(size_t loops, size_t *psize, const void *arg)
{
    const struct cche_perf_test *test = arg;
    return test->func(loops, (uint32_t)*psize, CCHE_SCHEME_BFV);
}

static double perf_cche_bgv(size_t loops, size_t *psize, const void *arg)
{
    const struct cche_perf_test *test = arg;
    return test->func(loops, (uint32_t)*psize, CCHE_SCHEME_BGV);
}

static struct ccperf_family bfv_family;
static struct ccperf_family bgv_family;

struct ccperf_family *ccperf_family_cche_bfv(int argc, char *argv[])
{
    F_GET_ALL(bfv_family, cche_bfv);

    F_SIZES_FROM_ARRAY(bfv_family, perf_degrees);
    bfv_family.size_kind = ccperf_size_units;
    bfv_family.teardown = &perf_cche_bfv_cleanup;
    return &bfv_family;
}

struct ccperf_family *ccperf_family_cche_bgv(int argc, char *argv[])
{
    F_GET_ALL(bgv_family, cche_bgv);

    F_SIZES_FROM_ARRAY(bgv_family, perf_degrees);
    bgv_family.size_kind = ccperf_size_units;
    bgv_family.teardown = &perf_cche_bgv_cleanup;
    return &bgv_family;
}
