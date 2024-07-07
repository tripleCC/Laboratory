/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCECIES_INTERNAL_H
#define _CORECRYPTO_CCECIES_INTERNAL_H

#include <corecrypto/ccecies.h>
#include "cc_memory.h"

#define CCECIES_CIPHERIV_NBYTES 16
#define CCECIES_CIPHER_TAG_MIN_NBYTES 12
#define CCECIES_CIPHER_TAG_MAX_NBYTES 16
#define CCECIES_CIPHER_KEY_MAX_NBYTES CCAES_KEY_SIZE_256
#define CC_DEBUG_ECIES (CORECRYPTO_DEBUG && 0)

/*!
 @function   ccecies_decrypt_gcm_plaintext_size_cp
 @abstract   Compute the size of the output plaintext of ECIES

 @param  cp                     Input:  Curve Parameters
 @param  ecies                  Input:  ECIES configurations
 @param  encrypted_blob_nbytes  Input:  Size of the encrypted blob with ciphertext

 @return 0 if error or no plaintext, plaintext byte size otherwise.
 */
CC_NONNULL((1, 2))
size_t ccecies_decrypt_gcm_plaintext_size_cp(ccec_const_cp_t cp, ccecies_gcm_t ecies, size_t encrypted_blob_nbytes);

/*!
 @function   ccecies_derive_gcm_key_iv
 @abstract   Derive the GCM key and IV from shared secret and contextual information

 @param  ecies                  Input:  ECIES configurations
 @param  shared_secret_nbytes   Input:  Length in bytes of shared secret
 @param  shared_secret          Input:  Pointer to shared secret
 @param  sharedinfo1_nbytes     Input:  Length in bytes of SharedInfo1
 @param  sharedinfo1            Input:  Pointer to SharedInfo1
 @param  exported_public_key_nbytes  Input:  Byte size of ephemeral public key in serialized format
 @param  exported_public_key    Input:  Ephemeral public key in serialized format
 @param  gcm_key_iv             Output: Key + IV buffer of size ecies->key_length + ECIES_CIPHERIV_NBYTES

 @return 0 if success, see cc_error.h otherwise
*/
CC_NONNULL((1, 3, 7, 8))
int ccecies_derive_gcm_key_iv(const ccecies_gcm_t ecies,
                              size_t shared_secret_nbytes,
                              const uint8_t *shared_secret,
                              size_t sharedinfo1_nbytes,
                              const void *sharedinfo1,
                              size_t exported_public_key_nbytes,
                              const uint8_t *exported_public_key,
                              uint8_t *gcm_key_iv); /* output */

/*!
 @function   ccecies_export_eph_pub
 @abstract   export the public key in the format specified in the ECIES setup phase

 @param  options                Input:  Export format bitmask (ECIES_EXPORT_*)
 @param  key                    Input:  Pointer to key structure
 @param  out                    Output: Pointer to the key buffer, of size >= ccecies_pub_key_size

 @return 0 if success, see cc_error.h otherwise
 */
CC_NONNULL((2, 3))
int ccecies_export_eph_pub(const uint32_t options, ccec_pub_ctx_t key, void *out);

/*!
 @function   ccecies_encrypt_gcm_encrypt
 @abstract   Perform the GCM encryption with shared info 2 as AAD

 @param  ecies                  Input:  ECIES configurations
 @param  gcm_key_iv             Input:  GCM key and IV concatenated, sizes inferred from ecies
 @param  sharedinfo2_nbytes     Input:  Length in bytes of SharedInfo2
 @param  sharedinfo2            Input:  Pointer to SharedInfo2
 @param  plaintext_nbytes       Input:  Length in bytes of the plaintext
 @param  plaintext              Input:  Pointer to plaintext
 @param  ciphertext             Output: Pointer to buffer for encrypted message of size plaintext_nbytes
 @param  mac_tag                Output:  integrity validation tag of length ecies->mac_length bytes

 @return 0 if success, see cc_error.h otherwise

 */
CC_NONNULL((1, 2, 6, 7, 8))
int ccecies_encrypt_gcm_encrypt(const ccecies_gcm_t ecies,
                                const uint8_t *gcm_key_iv,
                                size_t sharedinfo2_nbytes,
                                const void *sharedinfo2,
                                size_t plaintext_nbytes,
                                const uint8_t *plaintext,
                                uint8_t *ciphertext,
                                uint8_t *mac_tag);

/*!
 @function   ccecies_encrypt_gcm_from_shared_secret_composite
 @abstract   Perform the GCM encryption with shared info 1 for key derivation and shared info 2 for AAD
        The ECDH shared secret is provided by the caller.
        The ephemeral key used in ECDH *must* be fresh for every encryption

 @param  destination_public_key Input:  Public key to encrypt to
 @param  ecies                  Input:  ECIES configurations
 @param  ephemeral_public_key   Input:  Ephemeral public key involved in the ECDH for shared secret
 @param  shared_secret_nbytes   Input:  Length in bytes of shared secret
 @param  shared_secret          Input:  Pointer to shared secret
 @param  plaintext_nbytes       Input:  Length in bytes of the plaintext
 @param  plaintext              Input:  Pointer to plaintext
 @param  sharedinfo1_nbytes     Input:  Length in bytes of SharedInfo1
 @param  sharedinfo1            Input:  Pointer to SharedInfo1
 @param  sharedinfo2_nbytes     Input:  Length in bytes of SharedInfo2
 @param  sharedinfo2            Input:  Pointer to SharedInfo2
 @param  exported_public_key    Output: Pointer to buffer for serialized ephemeral public key
 @param  ciphertext             Output: Pointer to buffer for encrypted message of size plaintext_nbytes
 @param  mac_tag                Output: Pointer to buffer for integrity tag of length ecies->mac_length bytes

 @return 0 if success, see cc_error.h otherwise

 */
CC_NONNULL((1, 2, 3, 5, 7, 12, 13, 14))
int ccecies_encrypt_gcm_from_shared_secret_composite(
    ccec_pub_ctx_t destination_public_key,
    const ccecies_gcm_t ecies,
    ccec_pub_ctx_t ephemeral_public_key,
    size_t shared_secret_nbytes,
    const uint8_t *shared_secret,
    size_t plaintext_nbytes,
    const uint8_t *plaintext,
    size_t sharedinfo1_nbytes,
    const void *sharedinfo1,
    size_t sharedinfo2_nbytes,
    const void *sharedinfo2,
    uint8_t *exported_public_key, /* output - length from ccecies_pub_key_nbytes */
    uint8_t *ciphertext,          /* output - length same as plaintext_nbytes */
    uint8_t *mac_tag              /* output - length ecies->mac_length */
);

/*!
 @function   ccecies_decrypt_gcm_decrypt
 @abstract   Perform the GCM decryption with shared info 2 as AAD

 @param  ecies                  Input:  ECIES configurations
 @param  gcm_key_iv             Input:  GCM key and IV concatenated, sizes inferred from ecies
 @param  sharedinfo2_nbytes     Input:  Length in bytes of SharedInfo2
 @param  sharedinfo2           Input:  Pointer to SharedInfo2
 @param  ciphertext_nbytes      Input:  Length in bytes of the plaintext
 @param  ciphertext             Input:  Pointer to plaintext
 @param  received_tag                Input:  integrity validation tag of length ecies->mac_length bytes
 @param  decrypted_message      Output:  Pointer to buffer for decrypted message, size ciphertext_nbytes

 @return 0 if success, see cc_error.h otherwise

 */
CC_NONNULL((1, 2, 6, 7, 8))
int ccecies_decrypt_gcm_decrypt(const ccecies_gcm_t ecies,
                                const uint8_t *gcm_key_iv,
                                size_t sharedinfo2_nbytes,
                                const void *sharedinfo2,
                                size_t ciphertext_nbytes,
                                const uint8_t *ciphertext,
                                const uint8_t *received_tag,
                                uint8_t *decrypted_message);

/*!
 @function   ccecies_decrypt_gcm_from_shared_secret_composite
 @abstract   Perform the GCM decryption with shared info 1 for key derivation and shared info 2 for AAD
 The ECDH shared secret is provided by the caller.

 @param  cp                     Input:  Curve Parameters
 @param  ecies                  Input:  ECIES configurations
 @param  shared_secret_nbytes   Input:  Length in bytes of shared secret
 @param  shared_secret          Input:  Pointer to shared secret
 @param  ciphertext_nbytes      Input:  Length in bytes of the plaintext
 @param  serialized_public_key  Input:  Pointer to serialized ephemeral public key
 @param  ciphertext             Input:  Pointer to ciphertext of size ciphertext_nbytes
 @param  received_tag           Input:  Pointer to integrity tag of size ecies->mac_length bytes
 @param  sharedinfo1_nbytes     Input:  Length in bytes of SharedInfo1
 @param  sharedinfo1            Input:  Pointer to SharedInfo1
 @param  sharedinfo2_nbytes     Input:  Length in bytes of SharedInfo2
 @param  sharedinfo2            Input:  Pointer to SharedInfo2
 @param  plaintext              Output: Pointer to buffer of size ciphertext_nbytes bytes

 @return 0 if success, see cc_error.h otherwise

 */
CC_NONNULL((1, 2, 4, 6, 7, 8, 13))
int ccecies_decrypt_gcm_from_shared_secret_composite(
    ccec_const_cp_t cp,
    const ccecies_gcm_t ecies,
    size_t shared_secret_nbytes,
    const uint8_t *shared_secret,
    size_t ciphertext_nbytes,
    const uint8_t *serialized_public_key, /* expect length from ccecies_pub_key_size */
    const uint8_t *ciphertext,
    const uint8_t *received_tag, /* expect length ecies->mac_length */
    size_t sharedinfo1_nbytes,
    const void *sharedinfo1,
    size_t sharedinfo2_nbytes,
    const void *sharedinfo2,
    uint8_t *plaintext /* output */
);

/*!
 @function   ccecies_import_eph_pub_ws
 @abstract   import the ephemeral public key from serialized to our data structure

 @param  ws                     Input:  Workspace
 @param  cp                     Input:  Curve Parameters
 @param  ecies                  Input:  ECIES configurations
 @param  in_len                 Input:  Size of the encrypted buffer
 @param  in                     Input:  Pointer to the encrypted blob
 @param  key                    Output: Pointer to public key structure to be initialized

 @return 0 if success, see cc_error.h otherwise

 */
CC_NONNULL_ALL
int ccecies_import_eph_pub_ws(cc_ws_t ws,
                              ccec_const_cp_t cp,
                              const ccecies_gcm_t ecies,
                              size_t in_len,
                              const uint8_t *in,
                              ccec_pub_ctx_t key);

#endif // _CORECRYPTO_CCECIES_INTERNAL_H
