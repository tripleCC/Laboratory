/* Copyright (c) (2014-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccecies_priv.h>
#include "ccecies_internal.h"
#include "ccec_internal.h"
#include "cc_workspaces.h"
#include "cc_memory.h"
#include "cc_macros.h"

static int ccecies_decrypt_gcm_composite_ws(cc_ws_t ws,
                                            ccec_full_ctx_t full_key,
                                            const ccecies_gcm_t ecies,
                                            uint8_t *plaintext, /* output - expect length ccecies_decrypt_gcm_plaintext_size */
                                            size_t sharedinfo1_nbytes,
                                            const void *sharedinfo1,
                                            size_t sharedinfo2_nbytes,
                                            const void *sharedinfo2,
                                            size_t ciphertext_nbytes,
                                            const uint8_t *ciphertext,
                                            const uint8_t *serialized_public_key, /* expect length from ccecies_pub_key_size */
                                            const uint8_t *received_tag           /* expect length ecies->mac_length */
)
{
    int status = CCERR_INTERNAL;
    ccec_const_cp_t cp = ccec_ctx_cp(full_key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_pub_ctx_t pub = CCEC_ALLOC_PUB_WS(ws, n);

    // Buffer for key material
    uint8_t *shared_secret = (uint8_t *)CC_ALLOC_WS(ws, n);
    size_t shared_secret_nbytes = ccec_cp_prime_size(cp);

    size_t serialized_public_key_nbytes = ccecies_pub_key_size_cp(cp, ecies);

    // Import public key from ciphertext
    status = ccecies_import_eph_pub_ws(ws, cp, ecies, serialized_public_key_nbytes, serialized_public_key, pub);
    cc_require(status == CCERR_OK, errOut);

    // ECDH - Ephemeral-static
    status = ccecdh_compute_shared_secret_ws(ws, full_key, pub, &shared_secret_nbytes, shared_secret, ecies->rng);
    cc_require(status == CCERR_OK, errOut);

    status = ccecies_decrypt_gcm_from_shared_secret_composite(cp,
                                                              ecies,
                                                              shared_secret_nbytes,
                                                              shared_secret,
                                                              ciphertext_nbytes,
                                                              serialized_public_key, /* expect length from ccecies_pub_key_size */
                                                              ciphertext,
                                                              received_tag, /* expect length ecies->mac_length */
                                                              sharedinfo1_nbytes,
                                                              sharedinfo1,
                                                              sharedinfo2_nbytes,
                                                              sharedinfo2,
                                                              plaintext);

errOut:
    if (status) {
        // On error, wipe the decrypted data
        cc_clear(ciphertext_nbytes, plaintext);
    }

    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccecies_decrypt_gcm_composite(ccec_full_ctx_t full_key,
                                  const ccecies_gcm_t ecies,
                                  uint8_t *plaintext, /* output - expect length ccecies_decrypt_gcm_plaintext_size */
                                  size_t sharedinfo1_nbytes,
                                  const void *sharedinfo1,
                                  size_t sharedinfo2_nbytes,
                                  const void *sharedinfo2,
                                  size_t ciphertext_nbytes,
                                  const uint8_t *ciphertext,
                                  const uint8_t *serialized_public_key, /* expect length from ccecies_pub_key_size */
                                  const uint8_t *received_tag           /* expect length ecies->mac_length */
)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(full_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCECIES_DECRYPT_GCM_COMPOSITE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccecies_decrypt_gcm_composite_ws(ws, full_key, ecies,
                                              plaintext,
                                              sharedinfo1_nbytes, sharedinfo1,
                                              sharedinfo2_nbytes, sharedinfo2,
                                              ciphertext_nbytes, ciphertext,
                                              serialized_public_key,
                                              received_tag);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccecies_decrypt_gcm(ccec_full_ctx_t full_key,
                        const ccecies_gcm_t ecies,
                        size_t encrypted_blob_nbytes,
                        const uint8_t *encrypted_blob,
                        size_t sharedinfo1_byte_nbytes,
                        const void *sharedinfo1,
                        size_t sharedinfo2_byte_nbytes,
                        const void *sharedinfo2,
                        size_t *plaintext_nbytes,
                        uint8_t *plaintext /* output */
)
{
    CC_ENSURE_DIT_ENABLED

    int status = CCERR_INTERNAL;
    size_t output_nbytes;
    size_t pub_key_size = ccecies_pub_key_size(ccec_ctx_pub(full_key), ecies);

    // Check input coherence
    status = CCERR_PARAMETER;
    output_nbytes = ccecies_decrypt_gcm_plaintext_size(full_key, ecies, encrypted_blob_nbytes);
    cc_require(output_nbytes > 0, errOut);
    cc_require(output_nbytes <= *plaintext_nbytes, errOut);

    // Do it
    status = ccecies_decrypt_gcm_composite(full_key,
                                           ecies,
                                           plaintext,
                                           sharedinfo1_byte_nbytes,
                                           sharedinfo1,
                                           sharedinfo2_byte_nbytes,
                                           sharedinfo2,
                                           output_nbytes,
                                           encrypted_blob + pub_key_size,
                                           encrypted_blob,
                                           encrypted_blob + pub_key_size + output_nbytes);
    cc_require(status == 0, errOut);
    *plaintext_nbytes = output_nbytes;

errOut:
    if (status) {
        cc_clear(*plaintext_nbytes, plaintext);
    }
    return status;
}
