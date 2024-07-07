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
#include "cc_macros.h"
#include "ccecies_internal.h"
#include "cc_debug.h"

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
)
{
    int status = CCERR_INTERNAL;
    size_t pub_key_size = ccecies_pub_key_size(ephemeral_public_key, ecies);
    uint8_t gcm_key_iv[CCECIES_CIPHER_KEY_MAX_NBYTES + CCECIES_CIPHERIV_NBYTES]; // [Key:IV]

    // Check that there is room for result and sanity
    cc_require_action(ccec_ctx_cp(destination_public_key) == ccec_ctx_cp(ephemeral_public_key), errOut, status = CCERR_PARAMETER);

    // Serialize public key
    status = ccecies_export_eph_pub(ecies->options, ephemeral_public_key, exported_public_key);
    cc_require(status == 0, errOut);

    // Key and IV derivation
    status = ccecies_derive_gcm_key_iv(ecies,
                                       shared_secret_nbytes,
                                       shared_secret,
                                       sharedinfo1_nbytes,
                                       sharedinfo1,
                                       pub_key_size,
                                       exported_public_key,
                                       gcm_key_iv);
    cc_require(status == 0, errOut);

    // Symmetric Authenticated Encryption
    status = ccecies_encrypt_gcm_encrypt(
        ecies, gcm_key_iv, sharedinfo2_nbytes, sharedinfo2, plaintext_nbytes, plaintext, ciphertext, mac_tag);

errOut:
    // Clear key material info
    cc_clear(sizeof(gcm_key_iv), gcm_key_iv);
    return status;
}

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
)
{
    CC_ENSURE_DIT_ENABLED

    int status = CCERR_INTERNAL;
    // Buffers for key material
    size_t pub_key_size = ccecies_pub_key_size(ephemeral_public_key, ecies);
    uint8_t *exported_public_key = encrypted_blob;
    uint8_t *ciphertext = encrypted_blob + pub_key_size;
    uint8_t *mac_tag = encrypted_blob + pub_key_size + plaintext_nbytes;

    // Compute output length
    size_t output_len = ccecies_encrypt_gcm_ciphertext_size(ephemeral_public_key, ecies, plaintext_nbytes);

    // When shared_secret method is used, public key is required in the KDF
    cc_require_action(ecies->options & (ECIES_EPH_PUBKEY_IN_SHAREDINFO1 | ECIES_EPH_PUBKEY_AND_SHAREDINFO1),
                      errOut,
                      status = CCERR_CRYPTO_CONFIG);

    // Check that there is room for result and sanity
    status = CCERR_PARAMETER;
    cc_require(output_len <= *encrypted_blob_nbytes, errOut);
    cc_require(ccec_ctx_cp(destination_public_key) == ccec_ctx_cp(ephemeral_public_key), errOut);

    // Serialize public key
    status =
        ccecies_encrypt_gcm_from_shared_secret_composite(destination_public_key,
                                                         ecies,
                                                         ephemeral_public_key,
                                                         shared_secret_nbytes,
                                                         shared_secret,
                                                         plaintext_nbytes,
                                                         plaintext,
                                                         sharedinfo1_nbytes,
                                                         sharedinfo1,
                                                         sharedinfo2_nbytes,
                                                         sharedinfo2,
                                                         exported_public_key, /* output - length from ccecies_pub_key_nbytes */
                                                         ciphertext,          /* output - length same as plaintext_nbytes */
                                                         mac_tag              /* output - length ecies->mac_length */
        );
    cc_require(status == 0, errOut);
    *encrypted_blob_nbytes = output_len;
errOut:
    if (status) {
        cc_clear(*encrypted_blob_nbytes, encrypted_blob);
    }
    return status;
}
