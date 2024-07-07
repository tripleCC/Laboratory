/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* Elliptic Curve Integrated Encryption Scheme implementation using AES-GCM for
 encryption/authentication.
 Terminology borrowed from http://www.secg.org/index.php?action=secg,docs_secg
   sharedinfo1 is diversifier for the KDF:
        In original design of DHIES, it needs to be set to the ephemeral public
            key to address malleability concerns, which are limited for ECIES.
        Even on ECIES, the mission of the public key appears to loosen the
        security bounds of certain security proofs (cf p28 http://shoup.net/papers/iso-2_1.pdf)
        Use option ECIES_EPH_PUBKEY_IN_SHAREDINFO1 to achieve this.
        Use options ECIES_EPH_PUBKEY_AND_SHAREDINFO1 to use the concatenation
        of the ephemeral public key and the data passed via the sharedinfo1
        parameter as the diversifier.
        Still considered optional per standards SEC1 and x9.63
   sharedinfo2 is diversifier for the MAC
        Potential security threat when attacker controled.

 */

#ifndef corecrypto_ccecies_h
#define corecrypto_ccecies_h

// bit mask
#define ECIES_EPH_PUBKEY_IN_SHAREDINFO1 1
#define ECIES_EXPORT_PUB_STANDARD 2
#define ECIES_EXPORT_PUB_COMPACT 4
//#define ECIES_EXPORT_PUB_COMPRESSES        8 // not supported
#define ECIES_LEGACY_IV 16
#define ECIES_EPH_PUBKEY_AND_SHAREDINFO1 32

#include <corecrypto/cc.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccmode.h>

typedef struct ccecies_gcm {
    const struct ccdigest_info *di;
    struct ccrng_state *rng;
    const struct ccmode_gcm *gcm;
    uint32_t key_length;
    uint32_t mac_length;
    uint32_t options; // bit mask
} * ccecies_gcm_t;

/*!
 @function   ccecies_encrypt_gcm_setup
 @abstract   Setup internal structure based on the configuration

 @param  ecies    Output: Internal structure aggregating config
 @param  di                     Input:  digest handle for KDF
 @param  rng                    Input:  rng handle for key generation and countermeasures
 @param  aes_gcm_enc            Input:  handle for GCM encryption
 @param  cipher_key_size        Input:  GCM key size
 @param  mac_tag_nbytes         Input:  MAC Tag, Must be >= 12
 @param  options                Input:  Bitmask options from ECIES_* macro list

 @return 0 if success, see cc_error.h otherwise
 */
CC_NONNULL((1, 2, 3, 4))
int ccecies_encrypt_gcm_setup(ccecies_gcm_t ecies,
                              const struct ccdigest_info *di,
                              struct ccrng_state *rng,
                              const struct ccmode_gcm *aes_gcm_enc,
                              uint32_t cipher_key_size,
                              uint32_t mac_tag_nbytes,
                              uint32_t options);

/*!
 @function   ccecies_encrypt_gcm_ciphertext_size
 @abstract   Compute the size of the encrypted blob with ciphertext

 @param  public_key             Input:  Destination Public key
 @param  ecies                  Input:  ECIES configurations
 @param  plaintext_nbytes       Input:  Size of the plaintext

 @return 0 if error or no ciphertext, encrypted blob byte size otherwise.
 */
CC_NONNULL((1, 2))
size_t ccecies_encrypt_gcm_ciphertext_size(ccec_pub_ctx_t public_key, ccecies_gcm_t ecies, size_t plaintext_nbytes);

/* Encrypt using the provided public key and elliptic curve info
 It requires ecies to have been initialized with the setup function.
 ciphertext_nbytes must be at least "ccecies_encrypt_gcm_cipher_size" bytes
 If ECIES_EPH_PUBKEY_IN_SHAREDINFO1 is set, sharedinfo1 MUST be NULL.
 If ECIES_EPH_PUBKEY_AND_SHAREDINFO1 is set, sharedinfo1 MUST NOT be NULL.
   The concatenation of the ephemeral public key and sharedinfo1 will be used
   as the diversifier.
 Setting both options is NOT supported and will return an error.

 Algorithm Description:
 1) Generate ephemeral key K = k.G
 2) Compute ECDH: SharedSecret = x(k.P) where P is public key to encrypt to and x() the X coordinate
 3) Compute concatenation of GCMKey:GCMIV = KDFx9.63(SharedSecret, [K || SharedInfo1])
         The use of K and/or SharedInfo1 depends on the configuration
         K is used in the KDF in its serialized representation (x9.63 or compact per configuration)
 4) Encrypt plaintext with GCM, using GCMKey and GCMIV
        Ciphertext = AES_GCM_Enc(GCMKey, GCMIV, [AAD=SharedInfo2], Data=Plaintext)
    The IV size is 16byte, in the Legacy case (not recommended, IV is all zero)
    The key size is configured in setup phase. It can be 16,24 or 32bytes.
    The integrity tag must be >=12 byte per GCM recommendations

    EncryptedBlob = <K> || <Ciphertext> || <Tag>

    K is encoded in EncryptedBlob with its serialized representation (x9.63 or compact per configuration)
 */
CC_NONNULL((1, 2, 4, 9, 10))
int ccecies_encrypt_gcm(ccec_pub_ctx_t public_key,
                        const ccecies_gcm_t ecies,
                        size_t plaintext_nbytes,
                        const uint8_t *plaintext,
                        size_t sharedinfo1_nbytes,
                        const void *sharedinfo1,
                        size_t sharedinfo2_nbytes,
                        const void *sharedinfo2,
                        size_t *encrypted_blob_nbytes,
                        uint8_t *encrypted_blob);

/*!
 @function   ccecies_encrypt_gcm_setup
 @abstract   Setup internal structure based on the configuration

 @param  ecies    Output: Internal structure aggregating config
 @param  di                     Input:  digest handle for KDF
 @param  aes_gcm_dec            Input:  handle for GCM decryption
 @param  cipher_key_nbytes        Input:  GCM key size
 @param  mac_tag_nbytes         Input:  MAC Tag, Must be >= 12
 @param  options                Input:  Bitmask options from ECIES_* macro list

 @return 0 if success, see cc_error.h otherwise
 */
CC_NONNULL((1, 2, 3))
int ccecies_decrypt_gcm_setup(ccecies_gcm_t ecies,
                              const struct ccdigest_info *di,
                              const struct ccmode_gcm *aes_gcm_dec,
                              uint32_t cipher_key_nbytes,
                              uint32_t mac_tag_nbytes,
                              uint32_t options);

/*!
 @function   ccecies_decrypt_gcm_plaintext_size
 @abstract   Compute the size of the output plaintext of ECIES

 @param  full_key               Input:  Private EC decryption key
 @param  ecies                  Input:  ECIES configurations
 @param  ciphertext_nbytes  Input:  Size of the encrypted blob with ciphertext

 @return 0 if error or no plaintext, plaintext byte size otherwise.
 */
CC_NONNULL((1, 2))
size_t ccecies_decrypt_gcm_plaintext_size(ccec_full_ctx_t full_key, ccecies_gcm_t ecies, size_t ciphertext_nbytes);

/* Decrypt using the provided private key and elliptic curve info
 It requires ecies to have been initialized with the setup function.
 ciphertext_nbytes must be at least "ccecies_encrypt_gcm_cipher_size" bytes
 If ECIES_EPH_PUBKEY_IN_SHAREDINFO1 is set, sharedinfo1_nbytes is ignored

 Algorithm Description:
 EncryptedBlob = <K> || <Ciphertext> || <Tag>

 1) Import the point K into a mathematical representation
 2) Compute SharedSecret = x(d.K) where d is <full_key> and x() the X coordinate (ECDH)
 3) Compute GCMKey:GCMIV = KDFx9.63(SharedSecret, [K || SharedInfo1])
        where the use of K and or SharedInfo1 depends on the configuration
        K is used in the KDF in its serialized representation (x9.63 or compact)
 4) Encrypt plaintext with GCM, using GCMKey and GCMIV
 Ciphertext = AES_GCM_Dec(GCMKey, GCMIV, [AAD=SharedInfo2], Data=Ciphertext)
 The IV size is 16byte, in the Legacy case (not recommended, IV is all zero)
 The key size is configured in setup phase. It can be 16,24 or 32bytes.
 The integrity tag must be >=12 byte per GCM recommendations

 */
CC_NONNULL((1, 2, 4, 9, 10))
int ccecies_decrypt_gcm(ccec_full_ctx_t full_key,
                        const ccecies_gcm_t ecies,
                        size_t encrypted_blob_nbytes,
                        const uint8_t *encrypted_blob,
                        size_t sharedinfo1_nbytes,
                        const void *sharedinfo1,
                        size_t sharedinfo2_nbytes,
                        const void *sharedinfo2,
                        size_t *plaintext_nbytes,
                        uint8_t *plaintext);

/*!
 @function   ccecies_pub_key_size
 @abstract   Compute the size of the serialize public key

 @param  public_key             Input:  Public key
 @param  ecies                  Input:  ECIES configurations

 @return 0 if error, key byte size otherwise.
 */
CC_NONNULL((1, 2))
size_t ccecies_pub_key_size(ccec_pub_ctx_t public_key, ccecies_gcm_t ecies);

/*!
 @function   ccecies_pub_key_size_cp
 @abstract   Compute the size of the serialize public key

 @param  cp                     Input:  Curve Parameters
 @param  ecies                  Input:  ECIES configurations

 @return 0 if error, key byte size otherwise.
 */
CC_NONNULL((1, 2))
size_t ccecies_pub_key_size_cp(ccec_const_cp_t cp, ccecies_gcm_t ecies);

/* Encrypt using the provided public key and elliptic curve info
 It requires ecies to have been initialized with the setup function.
 ciphertext_nbytes must be at least "ccecies_encrypt_gcm_cipher_size" bytes
 If ECIES_EPH_PUBKEY_IN_SHAREDINFO1 is set, sharedinfo1_nbytes is ignored
 Composite because ciphertext, mac and publickey are separate output */
CC_NONNULL((1, 2, 3, 4, 5, 7))
int ccecies_encrypt_gcm_composite(ccec_pub_ctx_t public_key,
                                  const ccecies_gcm_t ecies,
                                  uint8_t *exported_public_key, /* output - length from ccecies_pub_key_size */
                                  uint8_t *ciphertext,          /* output - length same as plaintext_nbytes */
                                  uint8_t *mac_tag,             /* output - length ecies->mac_length */
                                  size_t plaintext_nbytes,
                                  const uint8_t *plaintext,
                                  size_t sharedinfo1_nbytes,
                                  const void *sharedinfo1,
                                  size_t sharedinfo2_nbytes,
                                  const void *sharedinfo2);

/* Decrypt using the provided private key and elliptic curve info
 It requires ecies to have been initialized with the setup function.
 ciphertext_nbytes must be at least "ccecies_encrypt_gcm_cipher_size" bytes
 If ECIES_EPH_PUBKEY_IN_SHAREDINFO1 is set, sharedinfo1_nbytes is ignored
 Composite because ciphertext, mac and publickey are separate input */
CC_NONNULL((1, 2, 3, 10, 11))
int ccecies_decrypt_gcm_composite(ccec_full_ctx_t full_key,
                                  const ccecies_gcm_t ecies,
                                  uint8_t *plaintext, /* output - length same as ciphertext_nbytes */
                                  size_t sharedinfo1_nbytes,
                                  const void *sharedinfo1,
                                  size_t sharedinfo2_nbytes,
                                  const void *sharedinfo2,
                                  size_t ciphertext_nbytes,
                                  const uint8_t *ciphertext,
                                  const uint8_t *imported_public_key, /* expect length from ccecies_pub_key_size */
                                  const uint8_t *mac_tag              /* expect length ecies->mac_nbytesgth */
);

#endif
