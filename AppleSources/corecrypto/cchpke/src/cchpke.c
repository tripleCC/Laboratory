/* Copyright (c) (2019-2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"
#include <corecrypto/ccmode.h>
#include <corecrypto/cchkdf.h>
#include <corecrypto/ccec25519.h>
#include <corecrypto/cchpke_priv.h>
#include "cc_priv.h"
#include "cchpke_internal.h"

// This is draft 8 of the following draft rfc:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-08.txt
static const uint8_t HPKE_KDF_CONTEXT[7] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };

static const uint8_t HPKE_SUITE_ID_PREFIX_KEM[3] = { 'K', 'E', 'M' };
static const uint8_t HPKE_SUITE_ID_PREFIX_HPKE[4] = { 'H', 'P', 'K', 'E' };

static const uint8_t HPKE_PSK_ID_LABEL[11] = { 'p', 's', 'k', '_', 'i', 'd', '_', 'h', 'a', 's', 'h' };
static const uint8_t HPKE_INFO_LABEL[9] = { 'i', 'n', 'f', 'o', '_', 'h', 'a', 's', 'h' };
static const uint8_t HPKE_SECRET_LABEL[6] = { 's', 'e', 'c', 'r', 'e', 't' };
static const uint8_t HPKE_KEY_LABEL[3] = { 'k', 'e', 'y' };
static const uint8_t HPKE_NONCE_LABEL[10] = { 'b', 'a', 's', 'e', '_', 'n', 'o', 'n', 'c', 'e' };
static const uint8_t HPKE_EXP_LABEL[3] = { 'e', 'x', 'p' };
static const uint8_t HPKE_EAE_LABEL[7] = { 'e', 'a', 'e', '_', 'p', 'r', 'k' };
static const uint8_t HPKE_SHARED_SECRET_LABEL[13] = { 's', 'h', 'a', 'r', 'e', 'd', '_', 's', 'e', 'c', 'r', 'e', 't' };
static const uint8_t HPKE_SEC_LABEL[3] = { 's', 'e', 'c' };

/*
    The preprocessor does not reduce expressions involving CC_MAX_EVAL, leading to errors when CC_MAX_EVAL
    is used in conjuction with -Wvla. To circumvent this, manually specify the largest sizes and provide
    static asserts to maintain these invariants.
 
    output = cchkdf_extract(   HPKE_KDF_CONTEXT
                            || suite_id
                            || label = (HPKE_EAE_LABEL | HPKE_PSK_ID_LABEL | HPKE_INFO_LABEL | HPKE_SECRET_LABEL) ||
                            || IKM = (DH | pskID | psk | info)
                           )
           = cchkdf_extract(   HPKE_KDF_CONTEXT
                            || suite_id
                            || max_label_size = sizeof(HPKE_PSK_ID_LABEL)
                            || max_IKM_size = CCHPKE_INFO_MAX_SIZE
                           )
 */


cc_static_assert(CCHPKE_INFO_MAX_SIZE >= CCHPKE_PSK_MAX_SIZE, "Invalid Labeled Extract Assumption(CCHPKE_PSK_ID_MAX_SIZE)");
cc_static_assert(sizeof(HPKE_PSK_ID_LABEL) >= sizeof(HPKE_EAE_LABEL), "Invalid Labeled Extract Assumption(HPKE_EAE_LABEL)");
cc_static_assert(sizeof(HPKE_PSK_ID_LABEL) >= sizeof(HPKE_INFO_LABEL), "Invalid Labeled Extract Assumption(HPKE_INFO_LABEL)");
cc_static_assert(sizeof(HPKE_PSK_ID_LABEL) >= sizeof(HPKE_SECRET_LABEL), "Invalid Labeled Extract Assumption(HPKE_SECRET_LABEL)");
cc_static_assert(CCHPKE_INFO_MAX_SIZE >= sizeof(ccec25519pubkey), "Invalid Labeled Extract Assumption(ccec25519pubkey)");
cc_static_assert(CCHPKE_INFO_MAX_SIZE >= CCHPKE_PSK_ID_MAX_SIZE, "Invalid Labeled Extract Assumption(CCHPKE_PSK_ID_MAX_SIZE)");
cc_static_assert(CCHPKE_INFO_MAX_SIZE >= CCHPKE_PSK_MAX_SIZE, "Invalid Labeled Extract Assumption(CCHPKE_PSK_ID_MAX_SIZE)");

#define CCHPKE_LABELED_EXTRACT_MAX_SIZE (sizeof(HPKE_KDF_CONTEXT) + CCHPKE_SUITE_ID_MAX_NBYTES + sizeof(HPKE_PSK_ID_LABEL) + CCHPKE_INFO_MAX_SIZE)


/* kem_context = enc || pkR */
#define CCHPKE_KEM_CONTEXT_MAX_SIZE (sizeof(ccec25519pubkey) + sizeof(ccec25519pubkey))

/* key_schedule_context = mode ||  psk_id_hash ||  info_hash */
#define CCHPKE_KS_CONTEXT_MAX_SIZE (sizeof(cchpke_mode_t) + CCHPKE_HASH_MAX_SIZE + CCHPKE_HASH_MAX_SIZE)

/*
 output = cchkdf_expand(   len(output) = sizeof(uint16_t)
                        || HPKE_KDF_CONTEXT
                        || suite_id
                        || HPKE_SHARED_SECRET_LABEL | HPKE_KEY_LABEL | HPKE_NONCE_LABEL | HPKE_EXP_LABEL | HPKE_SEC_LABEL
                        || kem_context | key_schedule_context | exporter_context
                       )
        = cchkdf_extract(   sizeof(uint16_t)
                         || HPKE_KDF_CONTEXT
                         || CCHPKE_SUITE_ID_MAX_NBYTES
                         || max_label_size = HPKE_SHARED_SECRET_LABEL
                         || max_context = key_schedule_context
 */


cc_static_assert(sizeof(HPKE_SHARED_SECRET_LABEL) >= sizeof(HPKE_KEY_LABEL), "Invalid Labeled Expand Assumption(HPKE_KEY_LABEL)");
cc_static_assert(sizeof(HPKE_SHARED_SECRET_LABEL) >= sizeof(HPKE_NONCE_LABEL), "Invalid Labeled Expand Assumption(HPKE_NONCE_LABEL)");
cc_static_assert(sizeof(HPKE_SHARED_SECRET_LABEL) >= sizeof(HPKE_EXP_LABEL), "Invalid Labeled Expand Assumption(HPKE_EXP_LABEL)");
cc_static_assert(sizeof(HPKE_SHARED_SECRET_LABEL) >= sizeof(HPKE_SEC_LABEL), "Invalid Labeled Expand Assumption(HPKE_SEC_LABEL)");
cc_static_assert(CCHPKE_KS_CONTEXT_MAX_SIZE >= CCHPKE_KEM_CONTEXT_MAX_SIZE, "Invalid Labeled Expand Assumption(CCHPKE_KEM_CONTEXT_MAX_SIZE)");
cc_static_assert(CCHPKE_KS_CONTEXT_MAX_SIZE >= CCHPKE_EXPORTER_CONTEXT_MAX_SIZE, "Invalid Labeled Expand Assumption(CCHPKE_EXPORTER_CONTEXT_MAX_SIZE)");

#define CCHPKE_LABELED_EXPAND_MAX_SIZE (sizeof(uint16_t) + sizeof(HPKE_KDF_CONTEXT) + CCHPKE_SUITE_ID_MAX_NBYTES + sizeof(HPKE_SHARED_SECRET_LABEL) + CCHPKE_KS_CONTEXT_MAX_SIZE)


struct cchpke_params {
    cchpke_const_kdf_t kdf;
    cchpke_const_aead_t aead;
    cchpke_const_kem_t kem;
};

#define CCHPKE_MEMCPY_HELPER(_buf_, _data_, _nbytes_, _byteswritten_) \
    cc_memcpy(_buf_ + (_byteswritten_), _data_, (_nbytes_));          \
    _byteswritten_ += _nbytes_

static size_t cchpke_suite_id(cchpke_const_params_t algorithms, bool kem_suite_id, uint8_t *output)
{
    size_t suite_id_prefix_nbytes = 0;
    size_t additional_suite_id_nbytes = 0;
    size_t output_bytes_written = 0;

    if (kem_suite_id) {
        suite_id_prefix_nbytes = sizeof(HPKE_SUITE_ID_PREFIX_KEM);
        additional_suite_id_nbytes = 0;
    } else {
        suite_id_prefix_nbytes = sizeof(HPKE_SUITE_ID_PREFIX_HPKE);
        additional_suite_id_nbytes = sizeof(algorithms->kdf->identifier) + sizeof(algorithms->aead->identifier);
    }
    size_t total_output_nbytes = sizeof(algorithms->kem->identifier) + suite_id_prefix_nbytes + additional_suite_id_nbytes;
    cc_assert(total_output_nbytes <= CCHPKE_SUITE_ID_MAX_NBYTES);

    cchpke_kem_id_t kem_id = endian_swap_u16(algorithms->kem->identifier);
    cchpke_kdf_id_t kdf_id = endian_swap_u16(algorithms->kdf->identifier);
    cchpke_aead_id_t aead_id = endian_swap_u16(algorithms->aead->identifier);

    // Now finally write it to the output buffer
    if (kem_suite_id) {
        CCHPKE_MEMCPY_HELPER(output, HPKE_SUITE_ID_PREFIX_KEM, sizeof(HPKE_SUITE_ID_PREFIX_KEM), output_bytes_written);
    } else {
        CCHPKE_MEMCPY_HELPER(output, HPKE_SUITE_ID_PREFIX_HPKE, sizeof(HPKE_SUITE_ID_PREFIX_HPKE), output_bytes_written);
    }

    CCHPKE_MEMCPY_HELPER(output, &kem_id, sizeof(algorithms->kem->identifier), output_bytes_written);

    if (!kem_suite_id) {
        CCHPKE_MEMCPY_HELPER(output, &kdf_id, sizeof(algorithms->kdf->identifier), output_bytes_written);
        CCHPKE_MEMCPY_HELPER(output, &aead_id, sizeof(algorithms->aead->identifier), output_bytes_written);
    }
    return total_output_nbytes;
}

CC_WARN_RESULT
static int cchpke_labeled_extract(cchpke_const_params_t params,
                                  bool kem_suite_id,
                                  size_t salt_nbytes,
                                  const uint8_t *salt,
                                  size_t label_nbytes,
                                  const uint8_t *label,
                                  size_t ikm_nbytes,
                                  const uint8_t *ikm,
                                  uint8_t *output)
{
    size_t labeled_ikm_bytes_written = 0;
    uint8_t labeled_ikm[CCHPKE_LABELED_EXTRACT_MAX_SIZE];

    CCHPKE_MEMCPY_HELPER(labeled_ikm, HPKE_KDF_CONTEXT, sizeof(HPKE_KDF_CONTEXT), labeled_ikm_bytes_written);

    uint8_t *likm_suite_id = labeled_ikm + labeled_ikm_bytes_written;
    size_t suite_id_nbytes = cchpke_suite_id(params, kem_suite_id, likm_suite_id);
    labeled_ikm_bytes_written += suite_id_nbytes;

    CCHPKE_MEMCPY_HELPER(labeled_ikm, label, label_nbytes, labeled_ikm_bytes_written);
    CCHPKE_MEMCPY_HELPER(labeled_ikm, ikm, ikm_nbytes, labeled_ikm_bytes_written);

    int ret = cchkdf_extract(params->kdf->hashFunction(), salt_nbytes, salt, labeled_ikm_bytes_written, labeled_ikm, output);
    cc_clear(CCHPKE_LABELED_EXTRACT_MAX_SIZE, labeled_ikm);
    return ret;
}

static int cchpke_labeled_expand(cchpke_const_params_t params,
                                 bool kem_suite_id,
                                 size_t prk_nbytes,
                                 const uint8_t *prk,
                                 size_t label_nbytes,
                                 const uint8_t *label,
                                 size_t info_nbytes,
                                 const uint8_t *info,
                                 size_t L,
                                 uint8_t *output)
{
    cc_require_or_return(L <= UINT16_MAX, CCERR_PARAMETER);
    uint16_t output_size_info = endian_swap_u16((uint16_t)L);

    size_t labeled_info_bytes_written = 0;
    uint8_t labeled_info[CCHPKE_LABELED_EXPAND_MAX_SIZE];

    CCHPKE_MEMCPY_HELPER(labeled_info, &output_size_info, sizeof(output_size_info), labeled_info_bytes_written);
    CCHPKE_MEMCPY_HELPER(labeled_info, HPKE_KDF_CONTEXT, sizeof(HPKE_KDF_CONTEXT), labeled_info_bytes_written);

    uint8_t *li_suite_id = labeled_info + labeled_info_bytes_written;
    size_t suite_id_nbytes = cchpke_suite_id(params, kem_suite_id, li_suite_id);
    labeled_info_bytes_written += suite_id_nbytes;

    CCHPKE_MEMCPY_HELPER(labeled_info, label, label_nbytes, labeled_info_bytes_written);
    CCHPKE_MEMCPY_HELPER(labeled_info, info, info_nbytes, labeled_info_bytes_written);

    int ret = cchkdf_expand(params->kdf->hashFunction(), prk_nbytes, prk, labeled_info_bytes_written, labeled_info, L, output);
    cc_clear(sizeof(labeled_info), labeled_info);
    return ret;
}

static int cchpke_extract_and_expand(cchpke_const_params_t params,
                                     size_t dh_len,
                                     const uint8_t *dh,
                                     size_t kem_context_len,
                                     const uint8_t *kem_context,
                                     uint8_t *shared_secret)
{
    int ret;
    uint8_t eae_prk[CCHPKE_KDF_EXTRACT_MAX_SIZE];
    ret = cchpke_labeled_extract(params, true, 0, NULL, sizeof(HPKE_EAE_LABEL), HPKE_EAE_LABEL, dh_len, dh, eae_prk);
    cc_require_or_return(ret == CCERR_OK, ret);

    ret = cchpke_labeled_expand(params,
                                true,
                                params->kdf->Nh,
                                eae_prk,
                                sizeof(HPKE_SHARED_SECRET_LABEL),
                                HPKE_SHARED_SECRET_LABEL,
                                kem_context_len,
                                kem_context,
                                params->kem->Nsecret,
                                shared_secret);
    if (ret != CCERR_OK) {
        cc_clear(params->kem->Nsecret, shared_secret);
    }
    cc_clear(CCHPKE_KDF_EXTRACT_MAX_SIZE, eae_prk);
    return ret;
}

static int
cchpke_kem_x25519_generate_key_pair(struct ccrng_state *rng, size_t sk_nbytes, uint8_t *sk, size_t pk_nbytes, uint8_t *pk)
{
    cc_require_or_return(sk_nbytes == sizeof(ccec25519secretkey), CCERR_PARAMETER);
    cc_require_or_return(pk_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);

    ccec25519secretkey secret_key;
    ccec25519pubkey public_key;
    int result = cccurve25519_make_key_pair(rng, public_key, secret_key);
    if (result != CCERR_OK) {
        return result;
    }

    cc_memcpy(sk, secret_key, sk_nbytes);
    cc_memcpy(pk, public_key, pk_nbytes);
    return CCERR_OK;
}

static int cchpke_kem_x25519_serialize(size_t pk_nbytes, const uint8_t *pk, uint8_t *output)
{
    cc_require_or_return(pk_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);

    cc_memcpy(output, pk, pk_nbytes);
    return CCERR_OK;
}

static int cchpke_kem_x25519_deserialize(size_t blob_nbytes, const uint8_t *blob, uint8_t *pk)
{
    cc_require_or_return(blob_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);

    cc_memcpy(pk, blob, blob_nbytes);
    return CCERR_OK;
}

static int cchpke_kem_x25519_encap_deterministic(cchpke_const_params_t params,
                                                 size_t skE_nbytes,
                                                 const uint8_t *skE,
                                                 size_t pkE_nbytes,
                                                 const uint8_t *pkE,
                                                 size_t pkR_nbytes,
                                                 const uint8_t *pkR,
                                                 size_t key_nbytes,
                                                 uint8_t *key,
                                                 size_t enc_nbytes,
                                                 uint8_t *enc)
{
    cc_require_or_return(enc_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);
    cc_require_or_return(key_nbytes == sizeof(ccec25519key), CCERR_PARAMETER);
    cc_require_or_return(pkR_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);
    cc_require_or_return(skE_nbytes == sizeof(ccec25519secretkey), CCERR_PARAMETER);
    cc_require_or_return(pkE_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);
    cc_require_or_return(enc_nbytes <= CCHPKE_KEM_CONTEXT_MAX_SIZE, CCERR_PARAMETER);
    cc_require_or_return(enc_nbytes + sizeof(ccec25519pubkey) <= CCHPKE_KEM_CONTEXT_MAX_SIZE, CCERR_PARAMETER);

    ccec25519pubkey DH;

    int result = cccurve25519(DH, skE, pkR);
    if (result != CCERR_OK) {
        return result;
    }

    result = cchpke_kem_x25519_serialize(enc_nbytes, pkE, enc);
    if (result != CCERR_OK) {
        return result;
    }

    uint8_t kem_context[CCHPKE_KEM_CONTEXT_MAX_SIZE];
    cc_memcpy(kem_context, enc, enc_nbytes);

    result = cchpke_kem_x25519_serialize(pkR_nbytes, pkR, kem_context + enc_nbytes);
    if (result != CCERR_OK) {
        return result;
    }

    result = cchpke_extract_and_expand(params, sizeof(ccec25519pubkey), DH, CCHPKE_KEM_CONTEXT_MAX_SIZE, kem_context, key);
    return result;
}

static int cchpke_kem_x25519_encap(cchpke_const_params_t params,
                                   struct ccrng_state *rng,
                                   size_t pkR_nbytes,
                                   const uint8_t *pkR,
                                   size_t key_nbytes,
                                   uint8_t *key,
                                   size_t enc_nbytes,
                                   uint8_t *enc)
{
    cc_require_or_return(enc_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);
    cc_require_or_return(key_nbytes == sizeof(ccec25519secretkey), CCERR_PARAMETER);
    cc_require_or_return(pkR_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);

    uint8_t skE[sizeof(ccec25519secretkey)];
    uint8_t pkE[sizeof(ccec25519pubkey)];
    int result = cchpke_kem_x25519_generate_key_pair(rng, sizeof(ccec25519secretkey), skE, sizeof(ccec25519pubkey), pkE);
    if (result != CCERR_OK) {
        return result;
    }

    int status = cchpke_kem_x25519_encap_deterministic(
        params, sizeof(skE), skE, enc_nbytes, pkE, pkR_nbytes, pkR, key_nbytes, key, enc_nbytes, enc);
    return status;
}

static int cchpke_kem_x25519_decap(cchpke_const_params_t params,
                                   size_t enc_nbytes,
                                   const uint8_t *enc,
                                   size_t skR_nbytes,
                                   const uint8_t *skR,
                                   size_t key_nbytes,
                                   uint8_t *key)
{
    cc_require_or_return(enc_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);
    cc_require_or_return(key_nbytes == sizeof(ccec25519secretkey), CCERR_PARAMETER);
    cc_require_or_return(skR_nbytes == sizeof(ccec25519secretkey), CCERR_PARAMETER);
    cc_require_or_return(enc_nbytes <= CCHPKE_KEM_CONTEXT_MAX_SIZE, CCERR_PARAMETER);

    uint8_t pkE[sizeof(ccec25519pubkey)];
    int result = cchpke_kem_x25519_deserialize(enc_nbytes, enc, pkE);
    if (result != CCERR_OK) {
        return result;
    }

    ccec25519pubkey pkR;
    result = cccurve25519_make_pub(pkR, skR);
    if (result != CCERR_OK) {
        return result;
    }

    uint8_t kem_context[CCHPKE_KEM_CONTEXT_MAX_SIZE];
    cc_memcpy(kem_context, enc, enc_nbytes);

    result = cchpke_kem_x25519_serialize(sizeof(ccec25519pubkey), pkR, kem_context + enc_nbytes);
    if (result != CCERR_OK) {
        return result;
    }

    ccec25519pubkey DH;
    result = cccurve25519(DH, skR, pkE);
    if (result != CCERR_OK) {
        return result;
    }

    result = cchpke_extract_and_expand(params, sizeof(ccec25519pubkey), DH, CCHPKE_KEM_CONTEXT_MAX_SIZE, kem_context, key);
    return result;
}

static int cchpke_kem_x25519_public_key(size_t sk_nbytes, const uint8_t *sk, size_t pk_nbytes, uint8_t *pk)
{
    cc_require_or_return(sk_nbytes == sizeof(ccec25519secretkey), CCERR_PARAMETER);
    cc_require_or_return(pk_nbytes == sizeof(ccec25519pubkey), CCERR_PARAMETER);

    return cccurve25519_make_pub(pk, sk);
}

static const struct cchpke_kem cchpke_kem_x25519 = {
    .identifier = CCHPKE_KEM_ID_X25519_HKDF_SHA256,
    .Nenc = 32,
    .Nsecret = 32,
    .Npk = 32,
    .Npkm = 32,
    .Nsk = 32,
    .generate_key_pair = cchpke_kem_x25519_generate_key_pair,
    .serialize = cchpke_kem_x25519_serialize,
    .deserialize = cchpke_kem_x25519_deserialize,
    .public_key = cchpke_kem_x25519_public_key,
    .encap = cchpke_kem_x25519_encap,
    .encap_deterministic = cchpke_kem_x25519_encap_deterministic,
    .decap = cchpke_kem_x25519_decap,
};

int cchpke_kem_generate_key_pair(cchpke_const_params_t params,
                                 struct ccrng_state *rng,
                                 size_t sk_nbytes,
                                 uint8_t *sk,
                                 size_t pk_nbytes,
                                 uint8_t *pk)
{
    CC_ENSURE_DIT_ENABLED

    return params->kem->generate_key_pair(rng, sk_nbytes, sk, pk_nbytes, pk);
}

size_t cchpke_params_sizeof_kem_enc(cchpke_const_params_t params)
{
    return params->kem->Nenc;
}

size_t cchpke_params_sizeof_kem_shared_secret(cchpke_const_params_t params)
{
    return params->kem->Nsecret;
}

size_t cchpke_params_sizeof_kem_pk(cchpke_const_params_t params)
{
    return params->kem->Npk;
}

size_t cchpke_params_sizeof_kem_pk_marshalled(cchpke_const_params_t params)
{
    return params->kem->Npkm;
}

size_t cchpke_params_sizeof_kem_sk(cchpke_const_params_t params)
{
    return params->kem->Nsk;
}

static void cchpke_kdf_hkdf_sha256_hash(size_t message_nbytes, const uint8_t *message, uint8_t *digest)
{
    ccdigest(ccsha256_di(), message_nbytes, message, digest);
}

static const struct cchpke_kdf cchpke_kdf_hkdf_sha256 = { .identifier = CCHPKE_KDF_ID_HKDF_SHA256,
                                                          .Nh = CCSHA256_OUTPUT_SIZE,
                                                          .hash = cchpke_kdf_hkdf_sha256_hash,
                                                          .hashFunction = &ccsha256_di };

size_t cchpke_params_sizeof_kdf_hash(cchpke_const_params_t params)
{
    return params->kdf->Nh;
}

static int cchpke_aead_aesgcm128_seal(size_t key_nbytes,
                                      const uint8_t *key,
                                      size_t nonce_nbytes,
                                      const uint8_t *nonce,
                                      size_t aad_nbytes,
                                      const uint8_t *aad,
                                      size_t pt_nbytes,
                                      const uint8_t *pt,
                                      uint8_t *ct,
                                      size_t tag_nbytes,
                                      uint8_t *tag)
{
    return ccgcm_one_shot(
        ccaes_gcm_encrypt_mode(), key_nbytes, key, nonce_nbytes, nonce, aad_nbytes, aad, pt_nbytes, pt, ct, tag_nbytes, tag);
}

static int cchpke_aead_aesgcm128_open(size_t key_nbytes,
                                      const uint8_t *key,
                                      size_t nonce_nbytes,
                                      const uint8_t *nonce,
                                      size_t aad_nbytes,
                                      const uint8_t *aad,
                                      size_t ct_nbytes,
                                      const uint8_t *ct,
                                      uint8_t *pt,
                                      size_t tag_nbytes,
                                      uint8_t *tag)
{
    return ccgcm_one_shot(
        ccaes_gcm_decrypt_mode(), key_nbytes, key, nonce_nbytes, nonce, aad_nbytes, aad, ct_nbytes, ct, pt, tag_nbytes, tag);
}

static const struct cchpke_aead cchpke_aead_aesgcm128 = {
    .identifier = CCHPKE_AEAD_ID_AESGCM128,
    .Nk = CCAES_KEY_SIZE_128,
    .Nt = 16,
    .Nn = 12,
    .seal = cchpke_aead_aesgcm128_seal,
    .open = cchpke_aead_aesgcm128_open,
};

size_t cchpke_params_sizeof_aead_key(cchpke_const_params_t params)
{
    return params->aead->Nk;
}

size_t cchpke_params_sizeof_aead_tag(cchpke_const_params_t params)
{
    return params->aead->Nt;
}

size_t cchpke_params_sizeof_aead_nonce(cchpke_const_params_t params)
{
    return params->aead->Nn;
}

cchpke_const_params_t cchpke_params_x25519_AESGCM128_HKDF_SHA256(void)
{
    static struct cchpke_params params = {
        .kem = &cchpke_kem_x25519,
        .kdf = &cchpke_kdf_hkdf_sha256,
        .aead = &cchpke_aead_aesgcm128,
    };
    return &params;
}

static int cchpke_encryption_context_init(cchpke_const_params_t params,
                                          struct cchpke_inner_context *hpke_context,
                                          cchpke_mode_t mode,
                                          size_t shared_secret_nbytes,
                                          const uint8_t *shared_secret,
                                          size_t info_nbytes,
                                          const uint8_t *info,
                                          size_t psk_nbytes,
                                          const uint8_t *psk,
                                          size_t pskID_nbytes,
                                          const uint8_t *pskID)
{
    // key_schedule_context = concat(mode, psk_id_hash, info_hash)
    size_t key_schedule_context_len = sizeof(mode) + params->kdf->Nh + params->kdf->Nh;
    uint8_t key_schedule_context[CCHPKE_KS_CONTEXT_MAX_SIZE];

    cc_memcpy(key_schedule_context, &mode, sizeof(mode));

    uint8_t *pskID_hash = key_schedule_context + sizeof(mode);
    int ret = cchpke_labeled_extract(params, false, 0, NULL, sizeof(HPKE_PSK_ID_LABEL), HPKE_PSK_ID_LABEL, pskID_nbytes, pskID, pskID_hash);
    cc_require_or_return(ret == CCERR_OK, ret);
    
    uint8_t *info_hash = key_schedule_context + sizeof(mode) + params->kdf->Nh;
    ret = cchpke_labeled_extract(params, false, 0, NULL, sizeof(HPKE_INFO_LABEL), HPKE_INFO_LABEL, info_nbytes, info, info_hash);
    cc_require_or_return(ret == CCERR_OK, ret);
    
    // secret = Extract(shared_secret, "secret", psk)
    uint8_t secret[CCHPKE_KDF_EXTRACT_MAX_SIZE];
    ret = cchpke_labeled_extract(params,
                                 false,
                                 shared_secret_nbytes,
                                 shared_secret,
                                 sizeof(HPKE_SECRET_LABEL),
                                 HPKE_SECRET_LABEL,
                                 psk_nbytes,
                                 psk,
                                 secret);
    cc_require_or_return(ret == CCERR_OK, ret);

    // key = Expand(secret, "key", key_schedule_context, Nk)
    ret = cchpke_labeled_expand(params,
                                false,
                                params->kdf->Nh,
                                secret,
                                sizeof(HPKE_KEY_LABEL),
                                HPKE_KEY_LABEL,
                                key_schedule_context_len,
                                key_schedule_context,
                                params->aead->Nk,
                                hpke_context->key);
    cc_require_or_return(ret == CCERR_OK, ret);

    // nonce = Expand(secret, "base_nonce", key_schedule_context, Nn)
    ret = cchpke_labeled_expand(params,
                          false,
                          params->kdf->Nh,
                          secret,
                          sizeof(HPKE_NONCE_LABEL),
                          HPKE_NONCE_LABEL,
                          key_schedule_context_len,
                          key_schedule_context,
                          params->aead->Nn,
                          hpke_context->nonce);
    cc_require_or_return(ret == CCERR_OK, ret);

    // exporter_secret = Expand(secret, "exp", key_schedule_context, Nh)
    ret = cchpke_labeled_expand(params,
                          false,
                          params->kdf->Nh,
                          secret,
                          sizeof(HPKE_EXP_LABEL),
                          HPKE_EXP_LABEL,
                          key_schedule_context_len,
                          key_schedule_context,
                          params->kdf->Nh,
                          hpke_context->exporter_secret);
    
    return ret;
}

int cchpke_initiator_setup_deterministic(cchpke_initiator_t initiator,
                                         cchpke_const_params_t params,
                                         struct ccrng_state *rng,
                                         size_t skE_nbytes,
                                         const uint8_t *skE,
                                         size_t pkE_nbytes,
                                         const uint8_t *pkE,
                                         size_t pkR_nbytes,
                                         const uint8_t *pkR,
                                         size_t info_nbytes,
                                         const uint8_t *info,
                                         size_t enc_nbytes,
                                         uint8_t *enc)
{
    cc_require_or_return(cchpke_params_sizeof_kem_enc(params) == enc_nbytes, CCERR_PARAMETER);
    cc_require_or_return(info_nbytes <= CCHPKE_INFO_MAX_SIZE, CCERR_PARAMETER);
    cc_clear(sizeof(struct cchpke_initiator), initiator);

    initiator->params = params;

    int result = CCERR_OK;

    uint8_t shared_secret[CCHPKE_AEAD_KEY_MAX_SIZE];
    if (skE_nbytes > 0 && skE != NULL && pkE_nbytes > 0 && pkE != NULL) {
        result = params->kem->encap_deterministic(params,
                                                  skE_nbytes,
                                                  skE,
                                                  pkE_nbytes,
                                                  pkE,
                                                  pkR_nbytes,
                                                  pkR,
                                                  cchpke_params_sizeof_kem_shared_secret(params),
                                                  shared_secret,
                                                  cchpke_params_sizeof_kem_enc(params),
                                                  enc);
    } else {
        result = params->kem->encap(params,
                                    rng,
                                    pkR_nbytes,
                                    pkR,
                                    cchpke_params_sizeof_kem_shared_secret(params),
                                    shared_secret,
                                    cchpke_params_sizeof_kem_enc(params),
                                    enc);
    }

    if (result != CCERR_OK) {
        return result;
    }
    struct cchpke_inner_context *context = (struct cchpke_inner_context *)&initiator->context;
    return cchpke_encryption_context_init(params,
                                          context,
                                          CCHPKE_MODE_BASE,
                                          cchpke_params_sizeof_kem_shared_secret(params),
                                          shared_secret,
                                          info_nbytes,
                                          info,
                                          0,
                                          NULL,
                                          0,
                                          NULL);
}

int cchpke_initiator_setup(cchpke_initiator_t initiator,
                           cchpke_const_params_t params,
                           struct ccrng_state *rng,
                           size_t pkR_nbytes,
                           const uint8_t *pkR,
                           size_t info_nbytes,
                           const uint8_t *info,
                           size_t enc_nbytes,
                           uint8_t *enc)
{
    CC_ENSURE_DIT_ENABLED

    return cchpke_initiator_setup_deterministic(
        initiator, params, rng, 0, NULL, 0, NULL, pkR_nbytes, pkR, info_nbytes, info, enc_nbytes, enc);
}

int cchpke_responder_setup(cchpke_responder_t responder,
                           cchpke_const_params_t params,
                           size_t skR_nbytes,
                           const uint8_t *skR,
                           size_t info_nbytes,
                           const uint8_t *info,
                           size_t enc_nbytes,
                           const uint8_t *enc)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(enc_nbytes == cchpke_params_sizeof_kem_enc(params), CCERR_PARAMETER);
    cc_require_or_return(info_nbytes <= CCHPKE_INFO_MAX_SIZE, CCERR_PARAMETER);
    cc_clear(sizeof(struct cchpke_responder), responder);

    responder->params = params;

    uint8_t shared_secret[CCHPKE_AEAD_KEY_MAX_SIZE];
    int result = params->kem->decap(params,
                                    cchpke_params_sizeof_kem_enc(params),
                                    enc,
                                    skR_nbytes,
                                    skR,
                                    cchpke_params_sizeof_kem_shared_secret(params),
                                    shared_secret);
    if (result != CCERR_OK) {
        return result;
    }

    struct cchpke_inner_context *context = (struct cchpke_inner_context *)&responder->context;
    return cchpke_encryption_context_init(params,
                                          context,
                                          CCHPKE_MODE_BASE,
                                          cchpke_params_sizeof_kem_shared_secret(params),
                                          shared_secret,
                                          info_nbytes,
                                          info,
                                          0,
                                          NULL,
                                          0,
                                          NULL);
}

static int cchpke_nonce(cchpke_const_params_t params, struct cchpke_inner_context *context, size_t nonce_nbytes, uint8_t *nonce)
{
    cc_require_or_return(nonce_nbytes == params->aead->Nn, CCERR_PARAMETER);

    cc_memset(nonce, 0, params->aead->Nn);
    size_t offset = params->aead->Nn - sizeof(context->sequence_number);
    cc_store64_be(context->sequence_number, nonce + offset);

    for (size_t i = 0; i < params->aead->Nn; i++) {
        nonce[i] ^= context->nonce[i];
    }

    return CCERR_OK;
}

int cchpke_initiator_encrypt(cchpke_initiator_t initiator,
                             size_t aad_nbytes,
                             const uint8_t *aad,
                             size_t pt_nbytes,
                             const uint8_t *pt,
                             uint8_t *ct,
                             size_t tag_nbytes,
                             uint8_t *tag)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t nonce[CCHPKE_NONCE_MAX_SIZE];

    struct cchpke_inner_context *context = (struct cchpke_inner_context *)&initiator->context;
    int result = cchpke_nonce(initiator->params, context, cchpke_params_sizeof_aead_nonce(initiator->params), nonce);
    if (result != CCERR_OK) {
        return result;
    }

    result = initiator->params->aead->seal(cchpke_params_sizeof_aead_key(initiator->params),
                                           context->key,
                                           cchpke_params_sizeof_aead_nonce(initiator->params),
                                           nonce,
                                           aad_nbytes,
                                           aad,
                                           pt_nbytes,
                                           pt,
                                           ct,
                                           tag_nbytes,
                                           tag);
    if (result != CCERR_OK) {
        return result;
    }

    context->sequence_number++;
    return result;
}

int cchpke_responder_decrypt(cchpke_responder_t responder,
                             size_t aad_nbytes,
                             const uint8_t *aad,
                             size_t ct_nbytes,
                             const uint8_t *ct,
                             size_t tag_nbytes,
                             uint8_t *tag,
                             uint8_t *pt)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t nonce[CCHPKE_NONCE_MAX_SIZE];
    struct cchpke_inner_context *context = (struct cchpke_inner_context *)&responder->context;
    int result = cchpke_nonce(responder->params, context, cchpke_params_sizeof_aead_nonce(responder->params), nonce);
    if (result != CCERR_OK) {
        return result;
    }

    result = responder->params->aead->open(cchpke_params_sizeof_aead_key(responder->params),
                                           context->key,
                                           cchpke_params_sizeof_aead_nonce(responder->params),
                                           nonce,
                                           aad_nbytes,
                                           aad,
                                           ct_nbytes,
                                           ct,
                                           pt,
                                           tag_nbytes,
                                           tag);
    if (result != CCERR_OK) {
        return result;
    }

    context->sequence_number++;
    return result;
}

int cchpke_initiator_seal(cchpke_const_params_t params,
                          struct ccrng_state *rng,
                          size_t pkR_nbytes,
                          const uint8_t *pkR,
                          size_t info_nbytes,
                          const uint8_t *info,
                          size_t aad_nbytes,
                          const uint8_t *aad,
                          size_t pt_nbytes,
                          const uint8_t *pt,
                          uint8_t *ct,
                          size_t tag_nbytes,
                          uint8_t *tag,
                          size_t enc_nbytes,
                          uint8_t *enc)
{
    CC_ENSURE_DIT_ENABLED

    struct cchpke_initiator initiator;
    int result = cchpke_initiator_setup(&initiator, params, rng, pkR_nbytes, pkR, info_nbytes, info, enc_nbytes, enc);
    if (result != CCERR_OK) {
        return result;
    }

    result = cchpke_initiator_encrypt(&initiator, aad_nbytes, aad, pt_nbytes, pt, ct, tag_nbytes, tag);
    cc_clear(sizeof(initiator), &initiator);

    return result;
}

int cchpke_responder_open(cchpke_const_params_t params,
                          size_t skR_nbytes,
                          const uint8_t *skR,
                          size_t info_nbytes,
                          const uint8_t *info,
                          size_t aad_nbytes,
                          const uint8_t *aad,
                          size_t ct_nbytes,
                          const uint8_t *ct,
                          size_t tag_nbytes,
                          uint8_t *tag,
                          size_t enc_nbytes,
                          uint8_t *enc,
                          uint8_t *pt)
{
    CC_ENSURE_DIT_ENABLED

    struct cchpke_responder responder;
    int result = cchpke_responder_setup(&responder, params, skR_nbytes, skR, info_nbytes, info, enc_nbytes, enc);
    if (result != CCERR_OK) {
        return result;
    }

    result = cchpke_responder_decrypt(&responder, aad_nbytes, aad, ct_nbytes, ct, tag_nbytes, tag, pt);
    cc_clear(sizeof(responder), &responder);

    return result;
}

static int cchpke_export_secret(struct cchpke_inner_context *hpke_context,
                                cchpke_const_params_t params,
                                size_t exporter_context_nbytes,
                                const uint8_t *exporter_context,
                                size_t exporter_secret_nbytes,
                                uint8_t *exporter_secret)
{
    cc_require_or_return(exporter_context_nbytes <= CCHPKE_EXPORTER_CONTEXT_MAX_SIZE, CCERR_PARAMETER);
    return cchpke_labeled_expand(params,
                                 false,
                                 params->kdf->Nh,
                                 hpke_context->exporter_secret,
                                 sizeof(HPKE_SEC_LABEL),
                                 HPKE_SEC_LABEL,
                                 exporter_context_nbytes,
                                 exporter_context,
                                 exporter_secret_nbytes,
                                 exporter_secret);
}

int cchpke_responder_export(cchpke_responder_t responder,
                            size_t exporter_context_nbytes,
                            const uint8_t *exporter_context,
                            size_t exporter_secret_nbytes,
                            uint8_t *exporter_secret)
{
    CC_ENSURE_DIT_ENABLED

    return cchpke_export_secret((struct cchpke_inner_context *)&responder->context,
                                responder->params,
                                exporter_context_nbytes,
                                exporter_context,
                                exporter_secret_nbytes,
                                exporter_secret);
}

int cchpke_initiator_export(cchpke_initiator_t initiator,
                            size_t exporter_context_nbytes,
                            const uint8_t *exporter_context,
                            size_t exporter_secret_nbytes,
                            uint8_t *exporter_secret)
{
    CC_ENSURE_DIT_ENABLED

    return cchpke_export_secret((struct cchpke_inner_context *)&initiator->context,
                                initiator->params,
                                exporter_context_nbytes,
                                exporter_context,
                                exporter_secret_nbytes,
                                exporter_secret);
}
