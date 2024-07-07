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

#include "cc_internal.h"
#include <corecrypto/ccecies.h>
#include <corecrypto/ccecies_priv.h>
#include "ccecies_internal.h"
#include "cc_macros.h"

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
)
{
    int status = CCERR_INTERNAL;

    // Buffer for key material
    uint8_t gcm_key_iv[CCECIES_CIPHER_KEY_MAX_NBYTES + CCECIES_CIPHERIV_NBYTES];
    size_t serialized_public_key_nbytes = ccecies_pub_key_size_cp(cp, ecies);

    // Key and IV derivation
    status = ccecies_derive_gcm_key_iv(ecies,
                                       shared_secret_nbytes,
                                       shared_secret,
                                       sharedinfo1_nbytes,
                                       sharedinfo1,
                                       serialized_public_key_nbytes,
                                       serialized_public_key,
                                       gcm_key_iv);
    cc_require(status == 0, errOut);

    // Symmetric Authenticated Decryption
    status = ccecies_decrypt_gcm_decrypt(
        ecies, gcm_key_iv, sharedinfo2_nbytes, sharedinfo2, ciphertext_nbytes, ciphertext, received_tag, plaintext);

errOut:
    if (status) {
        // On error, wipe the decrypted data
        cc_clear(ciphertext_nbytes, plaintext);
    }
    // Clear key material info
    cc_clear(sizeof(gcm_key_iv), gcm_key_iv);
    return status;
}

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
                                           uint8_t *plaintext /* output */
)
{
    CC_ENSURE_DIT_ENABLED

    int status = CCERR_INTERNAL;
    size_t serialized_public_key_nbytes = ccecies_pub_key_size_cp(cp, ecies);
    size_t output_nbytes = ccecies_decrypt_gcm_plaintext_size_cp(cp, ecies, encrypted_blob_nbytes);
    const uint8_t *serialized_public_key = encrypted_blob;
    const uint8_t *ciphertext =
        encrypted_blob + serialized_public_key_nbytes; // overflow validated in ccecies_decrypt_gcm_plaintext_size
    const uint8_t *received_tag = encrypted_blob + encrypted_blob_nbytes - ecies->mac_length; // overflow validated in

    // When shared_secret method is used, public key is required in the KDF
    cc_require_action(ecies->options & (ECIES_EPH_PUBKEY_IN_SHAREDINFO1 | ECIES_EPH_PUBKEY_AND_SHAREDINFO1),
                      errOut,
                      status = CCERR_CRYPTO_CONFIG);

    // Check input coherence
    cc_require_action((output_nbytes > 0) && (output_nbytes <= *plaintext_nbytes), errOut, status = CCERR_PARAMETER);

    status = ccecies_decrypt_gcm_from_shared_secret_composite(cp,
                                                              ecies,
                                                              shared_secret_nbytes,
                                                              shared_secret,
                                                              output_nbytes,
                                                              serialized_public_key,
                                                              ciphertext,
                                                              received_tag,
                                                              sharedinfo1_nbytes,
                                                              sharedinfo1,
                                                              sharedinfo2_nbytes,
                                                              sharedinfo2,
                                                              plaintext);
    cc_require(status == 0, errOut);
    *plaintext_nbytes = output_nbytes;

errOut:
    if (status) {
        cc_clear(*plaintext_nbytes, plaintext);
    }
    return status;
}
