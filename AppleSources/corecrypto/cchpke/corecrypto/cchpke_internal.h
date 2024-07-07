/* Copyright (c) (2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCHPKE_INTERNAL_H_
#define _CORECRYPTO_CCHPKE_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>
#include "cchpke_priv.h"

typedef uint8_t cchpke_mode_t;
typedef uint16_t cchpke_kem_id_t;
typedef uint16_t cchpke_kdf_id_t;
typedef uint16_t cchpke_aead_id_t;

CC_INLINE uint16_t
endian_swap_u16(uint16_t data)
{
    return (uint16_t)((data << 8) | (data >> 8));
}

struct cchpke_kem {
    cchpke_kem_id_t identifier;
    size_t Nenc;
    size_t Nsecret;
    size_t Npk;
    size_t Npkm;
    size_t Nsk;

    int (*CC_SPTR(cchpke_kem,generate_key_pair))(struct ccrng_state *rng,
                             size_t sk_nbytes, uint8_t *sk,
                             size_t pk_nbytes, uint8_t *pk);
    int (*CC_SPTR(cchpke_kem,serialize))(size_t pk_nbytes, const uint8_t *pk, uint8_t *output);
    int (*CC_SPTR(cchpke_kem,deserialize))(size_t blob_nbytes, const uint8_t *blob, uint8_t *pk);
    int (*CC_SPTR(cchpke_kem,public_key))(size_t sk_nbytes, const uint8_t *sk, size_t pk_nbytes, uint8_t *pk);
    int (*CC_SPTR(cchpke_kem,encap))(cchpke_const_params_t params, struct ccrng_state *rng,
                 size_t pkR_nbytes, const uint8_t *pkR,
                 size_t key_nbytes, uint8_t *key,
                 size_t enc_nbytes, uint8_t *enc);
    int (*CC_SPTR(cchpke_kem,encap_deterministic))(cchpke_const_params_t params,
                               size_t skE_nbytes, const uint8_t *skE,
                               size_t pkE_nbytes, const uint8_t *pkE,
                               size_t pkR_nbytes, const uint8_t *pkR,
                               size_t key_nbytes, uint8_t *key,
                               size_t enc_nbytes, uint8_t *enc);
    int (*CC_SPTR(cchpke_kem,decap))(cchpke_const_params_t params,
                 size_t enc_nbytes, const uint8_t *enc,
                 size_t skR_nbytes, const uint8_t *skR,
                 size_t key_nbytes, uint8_t *key);
};

typedef struct cchpke_kem *cchpke_kem_t;
typedef const struct cchpke_kem *cchpke_const_kem_t;

struct cchpke_kdf {
    cchpke_kdf_id_t identifier;
    size_t Nh;
    void (*CC_SPTR(cchpke_kdf, hash))(size_t message_nbytes, const uint8_t *message, uint8_t *digest);
    const struct ccdigest_info* (*CC_SPTR(cchpke_kdf, hashFunction))
    (void);
};

typedef struct cchpke_kdf *cchpke_kdf_t;
typedef const struct cchpke_kdf *cchpke_const_kdf_t;

struct cchpke_aead {
    cchpke_aead_id_t identifier;
    size_t Nk;
    size_t Nt;
    size_t Nn;

    int (*CC_SPTR(cchpke_aead, seal))(size_t key_nbytes,
                                      const uint8_t *key,
                                      size_t nonce_nbytes,
                                      const uint8_t *nonce,
                                      size_t aad_nbytes,
                                      const uint8_t *aad,
                                      size_t pt_nbytes,
                                      const uint8_t *pt,
                                      uint8_t *ct,
                                      size_t tag_nbytes,
                                      uint8_t *tag);
    int (*CC_SPTR(cchpke_aead, open))(size_t key_nbytes,
                                      const uint8_t *key,
                                      size_t nonce_nbytes,
                                      const uint8_t *nonce,
                                      size_t aad_nbytes,
                                      const uint8_t *aad,
                                      size_t ct_nbytes,
                                      const uint8_t *ct,
                                      uint8_t *pt,
                                      size_t tag_nbytes,
                                      uint8_t *tag);
};

typedef struct cchpke_aead *cchpke_aead_t;
typedef const struct cchpke_aead *cchpke_const_aead_t;

/*!
 * Inner context structure that stores secret keying material for
 * successive encryption and decryption attempts.
 */
struct cchpke_inner_context {
    uint8_t key[CCHPKE_AEAD_KEY_MAX_SIZE];
    uint8_t nonce[CCHPKE_AEAD_NONCE_MAX_SIZE];
    uint8_t exporter_secret[CCHPKE_KDF_EXTRACT_MAX_SIZE];
    uint64_t sequence_number;
};

cc_static_assert(sizeof(struct cchpke_context) >= sizeof(struct cchpke_inner_context), "Opaque struct cchpke_context size mismatch");

/*!
 * Constants for KEMs
 * See https://tools.ietf.org/html/draft-irtf-cfrg-hpke-00#section-7.
 */
#define CCHPKE_KEM_ID_X25519_HKDF_SHA256 0x0020

/*!
 * Constants for supported HPKE modes. Not all specified modes
 * are currently supported.
 * See https://tools.ietf.org/html/draft-irtf-cfrg-hpke-00#section-7.
 */
#define CCHPKE_MODE_BASE 0x00

// Testing APIs
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
                                         uint8_t *enc);

#endif // _CORECRYPTO_CCHPKE_INTERNAL_H_
