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
#include <corecrypto/ccecies.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccmode.h>
#include "ccansikdf_internal.h"
#include "ccecies_internal.h"
#include "ccec_internal.h"
#include "cc_workspaces.h"
#include "cc_memory.h"
#include "cc_macros.h"

static int ccecies_encrypt_gcm_composite_ws(cc_ws_t ws,
                                            ccec_pub_ctx_t public_key,
                                            const ccecies_gcm_t ecies,
                                            uint8_t *exported_public_key, /* output - length from ccecies_pub_key_nbytes */
                                            uint8_t *ciphertext,          /* output - length same as plaintext_nbytes */
                                            uint8_t *mac_tag,             /* output - length ecies->mac_nbytesgth */
                                            size_t plaintext_nbytes,
                                            const uint8_t *plaintext,
                                            size_t sharedinfo1_nbytes,
                                            const void *sharedinfo1,
                                            size_t sharedinfo2_nbytes,
                                            const void *sharedinfo2)
{
    cc_assert(ecies->rng != NULL);

    // ECDH - Ephemeral-static
    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);

    // Generate ephemeral EC key pair
    ccec_full_ctx_t ephemeral_key = CCEC_ALLOC_FULL_WS(ws, n);

    size_t shared_secret_nbytes = ccec_cp_prime_size(cp);
    uint8_t *shared_secret = (uint8_t *)CC_ALLOC_WS(ws, n);

    int status = ccecdh_generate_key_ws(ws, cp, ecies->rng, ephemeral_key);
    cc_require(status == CCERR_OK, errOut);

#if CC_DEBUG_ECIES
    ccec_print_full_key("Ephemeral key", ephemeral_key);
#endif

    // 2) ECDH with input public key
    status = ccecdh_compute_shared_secret_ws(ws, ephemeral_key, public_key, &shared_secret_nbytes, shared_secret, ecies->rng);
    cc_require(status == CCERR_OK, errOut);

    // Key derivation and symmetric encryption
    status = ccecies_encrypt_gcm_from_shared_secret_composite(public_key,
                                                              ecies,
                                                              ccec_ctx_pub(ephemeral_key),
                                                              shared_secret_nbytes,
                                                              shared_secret,
                                                              plaintext_nbytes,
                                                              plaintext,
                                                              sharedinfo1_nbytes,
                                                              sharedinfo1,
                                                              sharedinfo2_nbytes,
                                                              sharedinfo2,
                                                              exported_public_key,
                                                              ciphertext,
                                                              mac_tag);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccecies_encrypt_gcm_composite(ccec_pub_ctx_t public_key,
                                  const ccecies_gcm_t ecies,
                                  uint8_t *exported_public_key,
                                  uint8_t *ciphertext,
                                  uint8_t *mac_tag,
                                  size_t plaintext_nbytes,
                                  const uint8_t *plaintext,
                                  size_t sharedinfo1_nbytes,
                                  const void *sharedinfo1,
                                  size_t sharedinfo2_nbytes,
                                  const void *sharedinfo2)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCECIES_ENCRYPT_GCM_COMPOSITE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccecies_encrypt_gcm_composite_ws(ws,
                                              public_key,
                                              ecies,
                                              exported_public_key,
                                              ciphertext,
                                              mac_tag,
                                              plaintext_nbytes,
                                              plaintext,
                                              sharedinfo1_nbytes,
                                              sharedinfo1,
                                              sharedinfo2_nbytes,
                                              sharedinfo2);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccecies_encrypt_gcm(ccec_pub_ctx_t public_key,
                        const ccecies_gcm_t ecies,
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
    size_t pub_key_size = ccecies_pub_key_size(public_key, ecies);
    size_t output_nbytes = ccecies_encrypt_gcm_ciphertext_size(public_key, ecies, plaintext_nbytes);

    // Check there is room for result
    cc_require_action(output_nbytes <= *encrypted_blob_nbytes, errOut, status = CCERR_PARAMETER);

    // Do it
    status = ccecies_encrypt_gcm_composite(public_key,
                                           ecies,
                                           encrypted_blob,
                                           encrypted_blob + pub_key_size,
                                           encrypted_blob + pub_key_size + plaintext_nbytes,
                                           plaintext_nbytes,
                                           plaintext,
                                           sharedinfo1_nbytes,
                                           sharedinfo1,
                                           sharedinfo2_nbytes,
                                           sharedinfo2);
    cc_require(status == 0, errOut);
    *encrypted_blob_nbytes = output_nbytes;
errOut:
    if (status) {
        cc_clear(*encrypted_blob_nbytes, encrypted_blob);
    }
    return status;
}
