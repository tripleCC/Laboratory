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

#ifndef _CORECRYPTO_CCHPKE_H_
#define _CORECRYPTO_CCHPKE_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccsha2.h>

#define CCHPKE_DRAFT_VERSION_8

/*
* The corecrypto HPKE API: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke
*
* NOTE: HPKE is still an IRTF draft and is subject to change.
* Thus, this SPI is experimental and MUST NOT BE USED without
* consultation.
*/

struct cchpke_params;
typedef struct cchpke_params *cchpke_params_t;
typedef const struct cchpke_params *cchpke_const_params_t;

#define CCHPKE_HASH_MAX_SIZE CCSHA256_OUTPUT_SIZE

#define CCHPKE_AEAD_KEY_MAX_SIZE 32
#define CCHPKE_AEAD_NONCE_MAX_SIZE 16
#define CCHPKE_KDF_EXTRACT_MAX_SIZE CCHPKE_HASH_MAX_SIZE
#define CCHPKE_NONCE_MAX_SIZE 12

#define CCHPKE_SUITE_ID_MAX_NBYTES 10
#define CCHPKE_INFO_MAX_SIZE 64
#define CCHPKE_PSK_MAX_SIZE 0
#define CCHPKE_PSK_ID_MAX_SIZE 0
#define CCHPKE_EXPORTER_CONTEXT_MAX_SIZE 64

/*!
 * Constants for HPKE KDF algorithms.
 * See https://tools.ietf.org/html/draft-irtf-cfrg-hpke-00#section-7.
 */
#define CCHPKE_KDF_ID_HKDF_SHA256 0x0001
#define CCHPKE_KDF_ID_HKDF_SHA512 0x0002

/*!
 * Constants for HPKE AEAD algorithms.
 * See https://tools.ietf.org/html/draft-irtf-cfrg-hpke-00#section-7.
 */
#define CCHPKE_AEAD_ID_AESGCM128 0x0001
#define CCHPKE_AEAD_ID_AESGCM256 0x0002
#define CCHPKE_AEAD_ID_CHACHA20POLY1305 0x0003

/*! @function cchpke_params_x25519_AESGCM128_HKDF_SHA256
@abstract Get parameter structure associated with KEM x25519, AEAD AESGCM128, and KDF HKDF-SHA256.

@return A constant `cchpke_const_params_t` structure pointer.
*/
CC_CONST cchpke_const_params_t cchpke_params_x25519_AESGCM128_HKDF_SHA256(void);

/*! @function cchpke_params_sizeof_kem_enc
@abstract Obtain the KEM encapsulated key size.

@param params A `cchpke_const_params_t` instance.

@return KEM encapsulate key size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_kem_enc(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_kem_shared_secret
@abstract Obtain the KEM shared secret size.

@param params A `cchpke_const_params_t` instance.

@return KEM shared secret size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_kem_shared_secret(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_kem_pk
@abstract Obtain the KEM public key size.

@param params A `cchpke_const_params_t` instance.

@return KEM public key size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_kem_pk(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_kem_pk_marshalled
@abstract Obtain the marshalled (encoded) KEM public key size.

@param params A `cchpke_const_params_t` instance.

@return Marshalled KEM public key size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_kem_pk_marshalled(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_kem_sk
@abstract Obtain the KEM private key size.

@param params A `cchpke_const_params_t` instance.

@return KEM private key size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_kem_sk(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_kdf_hash
@abstract Obtain the KDF hash function output size.

@param params A `cchpke_const_params_t` instance.

@return KDF hash function output size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_kdf_hash(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_aead_key
@abstract Obtain the AEAD key size.

@param params A `cchpke_const_params_t` instance.

@return AEAD key size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_aead_key(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_aead_nonce
@abstract Obtain the AEAD nonce size.

@param params A `cchpke_const_params_t` instance.

@return AEAD nonce size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_aead_nonce(cchpke_const_params_t params);

/*! @function cchpke_params_sizeof_aead_tag
@abstract Obtain the AEAD tag size.

@param params A `cchpke_const_params_t` instance.

@return AEAD tag size.
*/
CC_NONNULL_ALL
size_t cchpke_params_sizeof_aead_tag(cchpke_const_params_t params);

struct cchpke_context {
    uint8_t opaque[CCHPKE_AEAD_KEY_MAX_SIZE + CCHPKE_AEAD_NONCE_MAX_SIZE + CCHPKE_KDF_EXTRACT_MAX_SIZE + sizeof(uint64_t)];
};

struct cchpke_initiator {
    cchpke_const_params_t params;
    struct cchpke_context context;
};

typedef struct cchpke_initiator *cchpke_initiator_t;

struct cchpke_responder {
    cchpke_const_params_t params;
    struct cchpke_context context;
};

typedef struct cchpke_responder *cchpke_responder_t;

/*! @function cchpke_kem_generate_key_pair
@abstract Derive a public and private key pair associated with the given HPKE parameters.

@param params A `cchpke_const_params_t` instance.
@param rng A `ccrng`instance.
@param sk_nbytes Number of bytes in `sk` storage.
@param sk Private key storage.
@param pk_nbytes Number of bytes in `pk` storage.
@param pk Public key storage.

@return CCERR_OK on success, and non-zero on failure. See cc_error.h for more details.
*/
CC_NONNULL_ALL
int cchpke_kem_generate_key_pair(cchpke_const_params_t params,
                                 struct ccrng_state *rng,
                                 size_t sk_nbytes, uint8_t *sk,
                                 size_t pk_nbytes, uint8_t *pk);

/*! @function cchpke_initiator_seal
@abstract Encrypt plaintext `pt` with associated data `aad` to a recipient's public key `pkR`,
 using optional string `info`, and produce ciphertext `ct`, authentication tag `tag`, and encapsulated
 key `enc`.

 Note: This is a one-shot API.

@param params A `cchpke_const_params_t` instance.
@param rng A `ccrng` instance.
@param pkR_nbytes Number of bytes in public key buffer.
@param pkR Recipient public key buffer.
@param info_nbytes Number of bytes in `info` buffer.
@param info Optional info buffer.
@param aad_nbytes Number of additional data bytes.
@param aad Additional data buffer.
@param pt_nbytes Number of message plaintext bytes.
@param pt Message plaintext bytes buffer.
@param ct Output ciphertext storage.
@param tag_nbytes Number of bytes in `tag` storage.
@param tag Output encryption tag storage.
@param enc_nbytes Number of bytes in `enc` storage.
@param enc Output encapsulated key storage.

@return CCERR_OK on success, and non-zero on failure. See cc_error.h for more details.
*/
CC_NONNULL_ALL
int cchpke_initiator_seal(cchpke_const_params_t params, struct ccrng_state *rng,
                          size_t pkR_nbytes, const uint8_t *pkR,
                          size_t info_nbytes, const uint8_t *info,
                          size_t aad_nbytes, const uint8_t *aad,
                          size_t pt_nbytes, const uint8_t *pt,
                          uint8_t *ct, size_t tag_nbytes, uint8_t *tag,
                          size_t enc_nbytes, uint8_t *enc);

/*! @function cchpke_responder_open
@abstract Decrypt ciphertext `ct` (with authentication tag `tag`) and associated data `aad` using an
 encapsulated key `enc` and private key `skR`, using optional string `info`, to produce plaintext `pt`.

 Note: This is a one-shot API.

@param params A `cchpke_const_params_t` instance.
@param skR_nbytes Number of bytes in private key buffer.
@param skR Recipient private key buffer.
@param info_nbytes Number of bytes in `info` buffer.
@param info Optional info buffer.
@param aad_nbytes Number of additional data bytes.
@param aad Additional data buffer.
@param ct_nbytes Number of ciphertext bytes.
@param ct Ciphertext buffer.
@param tag_nbytes Number of bytes in `tag` storage.
@param tag Output encryption tag storage.
@param enc_nbytes Number of bytes in `enc` storage.
@param enc Encapsulated key storage.
@param pt Output plaintext storage.

@return CCERR_OK on success, and non-zero on failure. See cc_error.h for more details.
*/
CC_NONNULL_ALL
int cchpke_responder_open(cchpke_const_params_t params,
                          size_t skR_nbytes, const uint8_t *skR,
                          size_t info_nbytes, const uint8_t *info,
                          size_t aad_nbytes, const uint8_t *aad,
                          size_t ct_nbytes, const uint8_t *ct, size_t tag_nbytes, uint8_t *tag,
                          size_t enc_nbytes, uint8_t *enc,
                          uint8_t *pt);

/*! @function cchpke_initiator_setup
@abstract Setup a `cchpke_initiator_t` instance for multiple encryptions to recipient public
 key `pkR` using info string `info`.

@param initiator A `cchpke_initiator_t` instance.
@param params A `cchpke_const_params_t` instance.
@param rng A `ccrng` instance.
@param pkR_nbytes Number of bytes in public key buffer.
@param pkR Recipient public key buffer.
@param info_nbytes Number of bytes in `info` buffer.
@param info Optional info buffer.
@param enc_nbytes Number of bytes in `enc` storage.
@param enc Output encapsulated key storage.

@return CCERR_OK on success, and non-zero on failure. See cc_error.h for more details.
*/
CC_NONNULL_ALL
int cchpke_initiator_setup(cchpke_initiator_t initiator, cchpke_const_params_t params,
                           struct ccrng_state *rng,
                           size_t pkR_nbytes, const uint8_t *pkR,
                           size_t info_nbytes, const uint8_t *info,
                           size_t enc_nbytes, uint8_t *enc);

/*! @function cchpke_responder_setup
@abstract Setup a `cchpke_responder_t` instance for multiple decryptions using private
 key `skR` and encapsulated key `enc, using optional  info string `info`.

@param responder A `cchpke_initiator_t` instance.
@param params A `cchpke_const_params_t` instance.
@param skR_nbytes Number of bytes in private key buffer.
@param skR Private key buffer.
@param info_nbytes Number of bytes in `info` buffer.
@param info Optional info buffer.
@param enc_nbytes Number of bytes in `enc` storage.
@param enc Encapsulated key buffer.

@return CCERR_OK on success, and non-zero on failure. See cc_error.h for more details.
*/
CC_NONNULL_ALL
int cchpke_responder_setup(cchpke_responder_t responder, cchpke_const_params_t params,
                           size_t skR_nbytes, const uint8_t *skR,
                           size_t info_nbytes, const uint8_t *info,
                           size_t enc_nbytes, const uint8_t *enc);

/*! @function cchpke_initiator_encrypt
@abstract Encrypt a message `pt` with associated data `aad`, producing ciphertext `ct`
 and authentication tag `tag`. Update the internal context upon success.

@param initiator A `cchpke_initiator_t` instance.
@param aad_nbytes Number of additional data bytes.
@param aad Additional data buffer.
@param pt_nbytes Number of message plaintext bytes.
@param pt Message plaintext bytes buffer.
@param ct Output ciphertext storage of length |pt_nbytes|.
@param tag_nbytes Number of bytes in `tag` storage.
@param tag Output encryption tag storage.

@return CCERR_OK on success, and non-zero on failure. See cc_error.h for more details.
*/
CC_NONNULL_ALL
int cchpke_initiator_encrypt(cchpke_initiator_t initiator,
                             size_t aad_nbytes, const uint8_t *aad,
                             size_t pt_nbytes, const uint8_t *pt,
                             uint8_t *ct, size_t tag_nbytes, uint8_t *tag);

/*! @function cchpke_responder_decrypt
@abstract Decrypt ciphertext `ct` with associated data `aad` and authentication tag `tag`, producing
 plaintext `pt`. Update the internal context upon success.

@param responder A `cchpke_responder_t` instance.
@param aad_nbytes Number of additional data bytes.
@param aad Additional data buffer.
@param ct_nbytes Number of ciphertext bytes.
@param ct Ciphertext buffer.
@param tag_nbytes Number of bytes in `tag` storage.
@param tag Output encryption tag storage.
@param pt Output plaintext storage of length |ct_nbytes|.

@return CCERR_OK on success, and non-zero on failure. See cc_error.h for more details.
*/
CC_NONNULL_ALL
int cchpke_responder_decrypt(cchpke_responder_t responder,
                             size_t aad_nbytes, const uint8_t *aad,
                             size_t ct_nbytes, const uint8_t *ct, size_t tag_nbytes, uint8_t *tag,
                             uint8_t *pt);
/*! @function cchpke_responder_export
 @abstract Export a secret of size `exporter_secret_nbytes` bytes.
 
 @param responder A `cchpke_responder_t` instance.
 @param exporter_context_nbytes Number of exporter_context bytes.
 @param exporter_context A unique context for this exported secret.
 @param exporter_secret_nbytes The requested size of the exported secret (max size 255 * cchpke_params_sizeof_kdf_hash(params)).
 @param exporter_secret The output secret.
 */
CC_NONNULL_ALL
int cchpke_responder_export(cchpke_responder_t responder, size_t exporter_context_nbytes, const uint8_t *exporter_context, size_t exporter_secret_nbytes, uint8_t *exporter_secret);

/*! @function cchpke_initiator_export
 @abstract Export a secret of size `exporter_secret_nbytes` bytes.
 
 @param initiator A `cchpke_initiator_t` instance.
 @param exporter_context_nbytes Number of exporter_context bytes.
 @param exporter_context A unique context for this exported secret.
 @param exporter_secret_nbytes The requested size of the exported secret (max size 255 * cchpke_params_sizeof_kdf_hash(params)).
 @param exporter_secret The output secret.
 */
CC_NONNULL_ALL
int cchpke_initiator_export(cchpke_initiator_t initiator, size_t exporter_context_nbytes, const uint8_t *exporter_context, size_t exporter_secret_nbytes, uint8_t *exporter_secret);

#endif // _CORECRYPTO_CCHPKE_H_
