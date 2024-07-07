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

#include "cche_internal.h"
#include "cche_galois_key.h"
#include "cche_relin_key.h"
#include "ccpolyzp_po2cyc_random.h"

CC_PURE size_t sizeof_struct_cche_cipher_plain_ctx(void)
{
    return sizeof(struct cche_cipher_plain_ctx);
}

CC_PURE size_t sizeof_struct_cche_ciphertext(void)
{
    return sizeof(struct cche_ciphertext_coeff);
}

CC_PURE size_t sizeof_struct_cche_decrypt_ctx(void)
{
    return sizeof(struct cche_decrypt_ctx);
}

CC_PURE size_t sizeof_struct_cche_encrypt_params(void)
{
    return sizeof(struct cche_encrypt_params);
}

CC_PURE size_t sizeof_struct_cche_galois_key(void)
{
    return sizeof(struct cche_galois_key);
}

CC_PURE size_t sizeof_struct_cche_relin_key(void)
{
    return sizeof(struct cche_relin_key);
}

size_t cche_secret_key_sizeof(cche_param_ctx_const_t param_ctx)
{
    return (cche_secret_key_nof_n(param_ctx) * sizeof_cc_unit());
}

size_t cche_ciphertext_sizeof(cche_param_ctx_const_t param_ctx, uint32_t nmoduli, uint32_t npolys)
{
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = cche_param_ctx_ciphertext_context_specific(param_ctx, nmoduli);
    return ccn_sizeof_n(cche_ciphertext_nof_n(&cipher_ctx->dims, npolys));
}

size_t cche_plaintext_sizeof(cche_param_ctx_const_t param_ctx)
{
    ccpolyzp_po2cyc_dims_const_t dims = &cche_param_ctx_plaintext_context(param_ctx)->dims;
    return ccn_sizeof_n(cche_plaintext_nof_n(dims));
}

size_t cche_dcrt_plaintext_sizeof(cche_param_ctx_const_t param_ctx, uint32_t nmoduli)
{
    struct ccpolyzp_po2cyc_dims dims = { .degree = cche_param_ctx_polynomial_degree(param_ctx), .nmoduli = nmoduli };
    return ccn_sizeof_n(cche_dcrt_plaintext_nof_n(&dims));
}

size_t cche_rng_seed_sizeof(void)
{
    return CCPOLYZP_PO2CYC_RANDOM_RNG_SEED_SIZE;
}

size_t cche_galois_key_sizeof(cche_param_ctx_const_t param_ctx, uint32_t ngalois_elts)
{
    return ccn_sizeof_n(cche_galois_key_nof_n(param_ctx, ngalois_elts));
}

size_t cche_relin_key_sizeof(cche_param_ctx_const_t param_ctx)
{
    return ccn_sizeof_n(cche_relin_key_nof_n(param_ctx));
}
