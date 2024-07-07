/* Copyright (c) (2014,2015,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCECIES_PRIV_H
#define _CORECRYPTO_CCECIES_PRIV_H

#include <corecrypto/ccecies.h>

/*!
 @function   ccecies_import_eph_pub
 @abstract   import the ephemeral public key from serialized to our data structure

 @param  cp                     Input:  Curve Parameters
 @param  ecies                  Input:  ECIES configurations
 @param  in_len                 Input:  Size of the encrypted buffer
 @param  in                     Input:  Pointer to the encrypted blob
 @param  key                    Output: Pointer to public key structure to be initialized

 @return 0 if success, see cc_error.h otherwise

 */
CC_NONNULL((1, 2, 4, 5))
int ccecies_import_eph_pub(ccec_const_cp_t cp, const ccecies_gcm_t ecies, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

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
 @function   ccecies_encrypt_gcm_from_shared_secret
 @abstract   Perform the GCM encryption with shared info 1 for key derivation and shared info 2 for AAD
 * Only to be used in SEP where ECDH is done in HW with HW derivation *
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
 @param  encrypted_blob_nbytes  Input/Output: Size of buffer for encrypted message. Update with exact size on output
 @param  encrypted_blob         Output: Pointer to buffer for encrypted message of ccecies_encrypt_gcm_ciphertext_size

 @return 0 if success, see cc_error.h otherwise

 */

CC_NONNULL((1, 2, 3, 5, 7, 12, 13))
int ccecies_encrypt_gcm_from_shared_secret(ccec_pub_ctx_t destination_public_key,
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
                                           size_t *encrypted_blob_nbytes,
                                           uint8_t *encrypted_blob /* output */
);

/*!
 @function   ccecies_decrypt_gcm_from_shared_secret
 @abstract   Perform the GCM decryption with shared info 1 for key derivation and shared info 2 for AAD
 The ECDH shared secret is provided by the caller.
  * Only to be used in SEP where ECDH is done in HW with HW derivation *

 @param  cp                     Input:  Curve Parameters
 @param  ecies                  Input:  ECIES configurations
 @param  shared_secret_nbytes   Input:  Length in bytes of shared secret
 @param  shared_secret          Input:  Pointer to shared secret
 @param  encrypted_blob_nbytes  Input:  Length in bytes of the encrypted blob containing ciphertext
 @param  encrypted_blob         Input:  Pointer to encrypted blob containing ciphertext
 @param  sharedinfo1_nbytes     Input:  Length in bytes of SharedInfo1
 @param  sharedinfo1            Input:  Pointer to SharedInfo1
 @param  sharedinfo2_nbytes     Input:  Length in bytes of SharedInfo2
 @param  sharedinfo2            Input:  Pointer to SharedInfo2
 @param  plaintext_nbytes       Input/Output: Size of buffer to store the plaintext
 @param  plaintext              Output: Pointer to buffer of size ccecies_decrypt_gcm_plaintext_size or
 ccecies_decrypt_gcm_plaintext_size_cp bytes

 @return 0 if success, see cc_error.h otherwise

 */

CC_NONNULL((1, 2, 4, 6, 11, 12))
int ccecies_decrypt_gcm_from_shared_secret(ccec_const_cp_t cp,
                                           const ccecies_gcm_t ecies,
                                           size_t shared_secret_nbytes,
                                           const uint8_t *shared_secret,
                                           size_t encrypted_blob_nbytes,
                                           const uint8_t *encrypted_blob,
                                           size_t sharedinfo1_nbytes,
                                           const void *sharedinfo1,
                                           size_t sharedinfo2_nbytes,
                                           const void *sharedinfo2,
                                           size_t *plaintext_nbytes,
                                           uint8_t *plaintext);

#endif // _CORECRYPTO_CCECIES_PRIV_H
