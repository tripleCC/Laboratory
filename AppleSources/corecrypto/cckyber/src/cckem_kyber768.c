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

#include "cc_macros.h"
#include "cckem_internal.h"
#include "cckyber_internal.h"

// Parameters for Kyber768.
// NIST security level 3 with decryption failure probability 2^-164.
const cckyber_params_t cckyber768_params = {
    // Dimension of the module.
    .k = 3,

    // No. of bits to retain per coefficient of polynomial v,
    // the private-key dependent part of the ciphertext.
    .dv = 4,

    // No. of bits to retain per coefficient of vector u,
    // the private-key independent part of the ciphertext.
    .du = 10,

    // (De-)Compression of a single polynomial.
    .poly_compress = cckyber_poly_compress_d4,
    .poly_decompress = cckyber_poly_decompress_d4,

    // (De-)Compression of a vector of polynomials.
    .polyvec_compress = cckyber_poly_compress_d10,
    .polyvec_decompress = cckyber_poly_decompress_d10
};

#define CCKYBER768_PUBKEY_NBYTES  1184
#define CCKYBER768_PRIVKEY_NBYTES 2400
#define CCKYBER768_EK_NBYTES      1088
#define CCKYBER768_SK_NBYTES        32

static int cckem_kyber768_generate_key(cckem_full_ctx_t ctx,
                                       struct ccrng_state *rng)
{
    uint8_t *pubkey = cckem_ctx_pubkey(cckem_public_ctx(ctx));
    uint8_t *privkey = cckem_ctx_privkey(ctx);
    return cckyber_kem_keypair(&cckyber768_params, pubkey, privkey, rng);
}

static int cckem_kyber768_encapsulate(const cckem_pub_ctx_t ctx,
                                      uint8_t *cc_unsafe_indexable ek,
                                      uint8_t *cc_unsafe_indexable sk,
                                      struct ccrng_state *rng)
{
    return cckyber_kem_encapsulate(&cckyber768_params, cckem_ctx_pubkey(ctx), ek, sk, rng);
}

static int cckem_kyber768_decapsulate(const cckem_full_ctx_t ctx,
                                      const uint8_t *cc_unsafe_indexable ek,
                                      uint8_t *cc_unsafe_indexable sk)
{
    return cckyber_kem_decapsulate(&cckyber768_params, cckem_ctx_privkey(ctx), ek, sk);
}

static int cckem_kyber768_export_pubkey(const cckem_pub_ctx_t ctx,
                                        size_t *pubkey_nbytes,
                                        uint8_t *pubkey)
{
    cc_require_or_return(*pubkey_nbytes >= cckem_pubkey_nbytes_ctx(ctx), CCERR_PARAMETER);
    *pubkey_nbytes = cckem_pubkey_nbytes_ctx(ctx);
    cc_memcpy(pubkey, cckem_ctx_pubkey(ctx), *pubkey_nbytes);
    return CCERR_OK;
}

static int cckem_kyber768_import_pubkey(const struct cckem_info *info,
                                        size_t pubkey_nbytes,
                                        const uint8_t * pubkey,
                                        cckem_pub_ctx_t ctx)
{
    cc_require_or_return(pubkey_nbytes == cckem_pubkey_nbytes_info(info), CCERR_PARAMETER);
    cckem_pub_ctx_init(ctx, info);
    cc_memcpy(cckem_ctx_pubkey(ctx), pubkey, pubkey_nbytes);
    return CCERR_OK;
}

static int cckem_kyber768_export_privkey(const cckem_full_ctx_t ctx,
                                         size_t *privkey_nbytes,
                                         uint8_t *privkey)
{
    cc_require_or_return(*privkey_nbytes >= cckem_privkey_nbytes_ctx(cckem_public_ctx(ctx)), CCERR_PARAMETER);
    *privkey_nbytes = cckem_privkey_nbytes_ctx(cckem_public_ctx(ctx));
    cc_memcpy(privkey, cckem_ctx_privkey(ctx), *privkey_nbytes);
    return CCERR_OK;
}

static int cckem_kyber768_import_privkey(const struct cckem_info *info,
                                         size_t privkey_nbytes,
                                         const uint8_t *privkey,
                                         cckem_full_ctx_t ctx)
{
    // We explicitly do not validate the public key (contained in `privkey`)
    // against its hash or that it corresponds to the private key. Any
    // inconsistency in `privkey` will lead to a decapsulation failure
    // and a key pair mismatch will not allow an attack on the Kyber KEM.

    cc_require_or_return(privkey_nbytes == cckem_privkey_nbytes_info(info), CCERR_PARAMETER);
    cckem_full_ctx_init(ctx, info);
    cc_memcpy(cckem_ctx_privkey(ctx), privkey, privkey_nbytes);
    return CCERR_OK;
}

static const struct cckem_info cckem_kyber768_info = {
    .fullkey_nbytes = CCKYBER768_PRIVKEY_NBYTES + CCKYBER768_PUBKEY_NBYTES,
    .pubkey_nbytes = CCKYBER768_PUBKEY_NBYTES,
    .encapsulated_key_nbytes = CCKYBER768_EK_NBYTES,
    .shared_key_nbytes = CCKYBER768_SK_NBYTES,

    .generate_key = cckem_kyber768_generate_key,
    .encapsulate = cckem_kyber768_encapsulate,
    .decapsulate = cckem_kyber768_decapsulate,
    .export_pubkey = cckem_kyber768_export_pubkey,
    .import_pubkey = cckem_kyber768_import_pubkey,
    .export_privkey = cckem_kyber768_export_privkey,
    .import_privkey = cckem_kyber768_import_privkey
};

const struct cckem_info *cckem_kyber768(void)
{
    return &cckem_kyber768_info;
}
