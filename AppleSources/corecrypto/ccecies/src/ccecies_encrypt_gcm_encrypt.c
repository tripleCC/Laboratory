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

#include <corecrypto/ccecies.h>
#include "ccecies_internal.h"
#include "cc_debug.h"
#include "cc_macros.h"

int ccecies_encrypt_gcm_encrypt(const ccecies_gcm_t ecies,
                                const uint8_t *gcm_key_iv,
                                size_t sharedinfo2_nbytes,
                                const void *sharedinfo2,
                                size_t plaintext_nbytes,
                                const uint8_t *plaintext,
                                uint8_t *ciphertext,
                                uint8_t *mac_tag)
{
    int status;
    const struct ccmode_gcm *gcm_encrypt = ecies->gcm;
    const uint8_t *ecies_iv_data = &gcm_key_iv[ecies->key_length];

    cc_require_or_return(gcm_encrypt->encdec == CCMODE_GCM_ENCRYPTOR, CCERR_CRYPTO_CONFIG);

    ccgcm_ctx_decl(gcm_encrypt->size, gcm_ctx);
    status = ccgcm_init(gcm_encrypt, gcm_ctx, ecies->key_length, gcm_key_iv);
    status |= ccgcm_set_iv(gcm_encrypt, gcm_ctx, CCECIES_CIPHERIV_NBYTES, ecies_iv_data);
    if ((sharedinfo2 != NULL) && (sharedinfo2_nbytes > 0)) {
        status |= ccgcm_aad(gcm_encrypt, gcm_ctx, sharedinfo2_nbytes, sharedinfo2);
    }
    status |= ccgcm_update(gcm_encrypt, gcm_ctx, plaintext_nbytes, plaintext, ciphertext);
    cc_require(status == CCERR_OK, errOut);

#if CC_DEBUG_ECIES
    cc_print("Plaintext message", plaintext_nbytes, plaintext);
    cc_print("Encrypted message", plaintext_nbytes, ciphertext);
#endif

    // Mac (with SharedInfo 2)
    // sec1, p51: recommended: SharedInfo2 ended in a counter giving its length.
    status = ccgcm_finalize(gcm_encrypt, gcm_ctx, ecies->mac_length, mac_tag);
#if CC_DEBUG_ECIES
    cc_print("Mac Tag", ecies->mac_length, mac_tag);
#endif

    // Success
errOut:
    ccgcm_ctx_clear(gcm_encrypt->size, gcm_ctx);
    return status;
}
