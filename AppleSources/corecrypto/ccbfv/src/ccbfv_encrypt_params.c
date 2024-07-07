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

/// @warning Insecure; use for testing only
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_insecure_n_8_logq_5x18_logt_5 = {
    .plaintext_modulus = (1ULL << 4) + 1, // 17
    .poly_modulus_degree = 8,
    .nskip_lsbs = { 10, 6 },
    .nmoduli = 5,
    //           131249,            131297,              131441,            131489,             131617
    .moduli = { (1ULL << 17) + 177, (1ULL << 17) + 225, (1ULL << 17) + 369, (1ULL << 17) + 417, (1ULL << 17) + 545 }
};

/// @warning Insecure; use for testing only
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_insecure_n_512_logq_4x60_logt_20 = {
    .plaintext_modulus = (1ULL << 19) + 1025, // 525313
    .poly_modulus_degree = 512,
    .nskip_lsbs = { 37, 30 },
    .nmoduli = 4,
    //           576460752303436801,   576460752303439873,  576460752303447041,    576460752303471617
    .moduli = { (1ULL << 59) + 13313, (1ULL << 59) + 16385, (1ULL << 59) + 23553, (1ULL << 59) + 48129 }
};

/// @brief satisfies post-quantum 128-bit security; plaintext modulus not NTT-friendly
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_4096_logq_27_28_28_logt_13 = {
    .plaintext_modulus = (1ULL << 12) + 3, // 4099
    .poly_modulus_degree = 4096,
    .nskip_lsbs = { 12, 4 },
    .nmoduli = 3,
    //          134176769,            268369921,            268361729
    .moduli = { (1ULL << 27) - 40959, (1ULL << 28) - 65535, (1ULL << 28) - 73727 }
};

/// @brief satisfies post-quantum 128-bit security
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_42 = {
    .plaintext_modulus = (1ULL << 41) + 32769, // 2199023288321
    .poly_modulus_degree = 8192,
    .nskip_lsbs = { 11, 2 },
    .nmoduli = 3,
    //          36028797018652673,     36028797017571329,      36028797017456641
    .moduli = { (1ULL << 55) - 311295, (1ULL << 55) - 1392639, (1ULL << 55) - 1507327 }
};

/// @brief satisfies post-quantum 128-bit security
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_30 = {
    .plaintext_modulus = (1ULL << 29) + 32769, // 536903681
    .poly_modulus_degree = 8192,
    .nskip_lsbs = { 23, 14 },
    .nmoduli = 3,
    //          36028797018652673,     36028797017571329,      36028797017456641
    .moduli = { (1ULL << 55) - 311295, (1ULL << 55) - 1392639, (1ULL << 55) - 1507327 }
};

/// @brief satisfies post-quantum 128-bit security
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_29 = {
    .plaintext_modulus = (1ULL << 28) + 147457, // 268582913
    .poly_modulus_degree = 8192,
    .nskip_lsbs = { 24, 15 },
    .nmoduli = 3,
    //          36028797018652673,     36028797017571329,      36028797017456641
    .moduli = { (1ULL << 55) - 311295, (1ULL << 55) - 1392639, (1ULL << 55) - 1507327 }
};

/// @brief satisfies post-quantum 128-bit security; plaintext modulus not NTT-friendly
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_4096_logq_27_28_28_logt_5 = {
    .plaintext_modulus = (1ULL << 4) + 1, // 17
    .poly_modulus_degree = 4096,
    .nskip_lsbs = { 20, 12 },
    .nmoduli = 3,
    //          134176769,            268369921,            268361729
    .moduli = { (1ULL << 27) - 40959, (1ULL << 28) - 65535, (1ULL << 28) - 73727 }
};

/// @brief satisfies post-quantum 128-bit security
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_24 = {
    .plaintext_modulus = (1 << 23) + 16385, // 8404993
    .poly_modulus_degree = 8192,
    .nskip_lsbs = { 29, 20 },
    .nmoduli = 3,
    //          36028797018652673,     36028797017571329,      36028797017456641
    .moduli = { (1ULL << 55) - 311295, (1ULL << 55) - 1392639, (1ULL << 55) - 1507327 }
};

/// @brief satisfies post-quantum 128-bit security; plaintext modulus not NTT-friendly
/// @details Small lowest-level ciphertext modulus reduces serialization size when ciphertext is mod-switched to a single modulus
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_8192_logq_29_60_60_logt_15 = {
    .plaintext_modulus = (1 << 14) + 27, // 16411
    .poly_modulus_degree = 8192,
    .nmoduli = 3,
    //          536690689,     1152921504606830593,      1152921504606748673
    .moduli = { (1ULL << 29) - 180223, (1ULL << 60) - 16383, (1ULL << 60) - 98303 },
    .nskip_lsbs = { 12, 3 },
};

/// @brief satisfies post-quantum 128-bit security
/// @details Small lowest-level ciphertext modulus reduces serialization size when ciphertext is mod-switched to a single modulus
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_8192_logq_40_60_60_logt_26 = {
    .plaintext_modulus = (1 << 25) + 278529, // 33832961
    .poly_modulus_degree = 8192,
    .nskip_lsbs = { 12, 3 },
    .nmoduli = 3,
    //          1099511480321,         1152921504606830593,      1152921504606748673
    .moduli = { (1ULL << 40) - 147455, (1ULL << 60) - 16383, (1ULL << 60) - 98303 }
};

/// @brief satisfies post-quantum 128-bit security
/// @details Small lowest-level ciphertext modulus reduces serialization size when ciphertext is mod-switched to a single modulus
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_8192_logq_28_60_60_logt_20 = {
    .plaintext_modulus = (1 << 19) + 32769, // 557057
    .poly_modulus_degree = 8192,
    .nskip_lsbs = { 6, 0 },
    .nmoduli = 3,
    //          268369921,            1152921504606830593,  1152921504606748673
    .moduli = { (1ULL << 28) - 65535, (1ULL << 60) - 16383, (1ULL << 60) - 98303 }
};

/// @brief satisfies post-quantum 128-bit security; plaintext modulus not NTT-friendly
/// @details Small lowest-level ciphertext modulus reduces serialization size when ciphertext is mod-switched to a single modulus
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_4096_logq_16_33_33_logt_4 = {
    .plaintext_modulus = (1 << 3) + 3, // 11
    .poly_modulus_degree = 4096,
    .nskip_lsbs = { 9, 1 },
    .nmoduli = 3,
    //          40961,                8589852673,           8589844481
    .moduli = { (1ULL << 16) - 24575, (1ULL << 33) - 81919, (1ULL << 33) - 90111 }
};

/// @warning Insecure; use for testing only
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_insecure_n_16_logq_60_logt_15 = {
    .plaintext_modulus = (1 << 14) + 33, // 16417
    .poly_modulus_degree = 16,
    .nskip_lsbs = { 43, 39 },
    .nmoduli = 1,
    .moduli = { (1ULL << 60) - 16383 } // 1152921504606830593
};

/// @brief satisfies post-quantum 128-bit security; plaintext modulus not NTT-friendly
const static struct ccbfv_encrypt_params ccbfv_predefined_encryption_params_n_4096_logq_27_28_28_logt_6 = {
    .plaintext_modulus = (1ULL << 5) + 5, // 37
    .poly_modulus_degree = 4096,
    .nskip_lsbs = { 19, 11 },
    .nmoduli = 3,
    //          134176769,            268369921,            268361729
    .moduli = { (1ULL << 27) - 40959, (1ULL << 28) - 65535, (1ULL << 28) - 73727 }
};

ccbfv_encrypt_params_const_t ccbfv_encrypt_params_get(ccbfv_predefined_encryption_params_t params)
{
    ccbfv_encrypt_params_const_t encrypt_params = NULL;
    switch (params) {
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_8_LOGQ_5x18_LOGT_5:
        encrypt_params = &ccbfv_predefined_encryption_params_insecure_n_8_logq_5x18_logt_5;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_512_LOGQ_4x60_LOGT_20:
        encrypt_params = &ccbfv_predefined_encryption_params_insecure_n_512_logq_4x60_logt_20;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_13:
        encrypt_params = &ccbfv_predefined_encryption_params_n_4096_logq_27_28_28_logt_13;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_5:
        encrypt_params = &ccbfv_predefined_encryption_params_n_4096_logq_27_28_28_logt_5;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_42:
        encrypt_params = &ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_42;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_30:
        encrypt_params = &ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_30;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_29:
        encrypt_params = &ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_29;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_3x55_LOGT_24:
        encrypt_params = &ccbfv_predefined_encryption_params_n_8192_logq_3x55_logt_24;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_29_60_60_LOGT_15:
        encrypt_params = &ccbfv_predefined_encryption_params_n_8192_logq_29_60_60_logt_15;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_40_60_60_LOGT_26:
        encrypt_params = &ccbfv_predefined_encryption_params_n_8192_logq_40_60_60_logt_26;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_8192_LOGQ_28_60_60_LOGT_20:
        encrypt_params = &ccbfv_predefined_encryption_params_n_8192_logq_28_60_60_logt_20;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_16_33_33_LOGT_4:
        encrypt_params = &ccbfv_predefined_encryption_params_n_4096_logq_16_33_33_logt_4;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_INSECURE_N_16_LOGQ_60_LOGT_15:
        encrypt_params = &ccbfv_predefined_encryption_params_insecure_n_16_logq_60_logt_15;
        break;
    case CCBFV_PREDEFINED_ENCRYPTION_PARAMS_N_4096_LOGQ_27_28_28_LOGT_6:
        encrypt_params = &ccbfv_predefined_encryption_params_n_4096_logq_27_28_28_logt_6;
        break;
    default:
        break;
    }

    return encrypt_params;
}

uint64_t ccbfv_encryption_params_plaintext_modulus(ccbfv_predefined_encryption_params_t enc_params)
{
    CC_ENSURE_DIT_ENABLED

    ccbfv_encrypt_params_const_t params = ccbfv_encrypt_params_get(enc_params);
    return params->plaintext_modulus;
}

uint32_t ccbfv_encryption_params_polynomial_degree(ccbfv_predefined_encryption_params_t enc_params)
{
    CC_ENSURE_DIT_ENABLED

    ccbfv_encrypt_params_const_t params = ccbfv_encrypt_params_get(enc_params);
    return params->poly_modulus_degree;
}

size_t ccbfv_encryption_params_coefficient_nmoduli(ccbfv_predefined_encryption_params_t enc_params)
{
    CC_ENSURE_DIT_ENABLED

    ccbfv_encrypt_params_const_t params = ccbfv_encrypt_params_get(enc_params);
    return params->nmoduli;
}

void ccbfv_encryption_params_coefficient_moduli(size_t nmoduli,
                                                uint64_t *cc_counted_by(nmoduli) moduli,
                                                ccbfv_predefined_encryption_params_t enc_params)
{
    CC_ENSURE_DIT_ENABLED

    ccbfv_encrypt_params_const_t params = ccbfv_encrypt_params_get(enc_params);
    for (uint32_t mod_idx = 0; mod_idx < CC_MIN_EVAL(nmoduli, params->nmoduli); ++mod_idx) {
        moduli[mod_idx] = params->moduli[mod_idx];
    }
}

bool ccbfv_encrypt_params_eq(ccbfv_encrypt_params_const_t x, ccbfv_encrypt_params_const_t y)
{
    if (x == y) {
        return true;
    }
    if (x->nmoduli != y->nmoduli) {
        return false;
    }
    cc_size n = ccn_sizeof_n(ccbfv_encrypt_params_nof_n(x->nmoduli));
    return cc_memcmp(x, y, n) == 0;
}
