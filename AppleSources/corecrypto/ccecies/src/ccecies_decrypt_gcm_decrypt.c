/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccecies.h>
#include "ccecies_internal.h"
#include "cc_macros.h"

int ccecies_decrypt_gcm_decrypt(const ccecies_gcm_t ecies,
                                const uint8_t *gcm_key_iv,
                                size_t sharedinfo2_nbytes,
                                const void *sharedinfo2,
                                size_t ciphertext_nbytes,
                                const uint8_t *ciphertext,
                                const uint8_t *received_tag,
                                uint8_t *decrypted_message)
{
    int status = CCERR_INTERNAL;
    const struct ccmode_gcm *gcm_decrypt = ecies->gcm;
    const uint8_t *ecies_iv_data = &gcm_key_iv[ecies->key_length];
    ccgcm_ctx_decl(gcm_decrypt->size, gcm_ctx);
    uint8_t computed_tag[CCECIES_CIPHER_TAG_MAX_NBYTES];

    cc_require_or_return(gcm_decrypt->encdec == CCMODE_GCM_DECRYPTOR, CCERR_CRYPTO_CONFIG);

    status = ccgcm_init(gcm_decrypt, gcm_ctx, ecies->key_length, gcm_key_iv);
    status |= ccgcm_set_iv(gcm_decrypt, gcm_ctx, CCECIES_CIPHERIV_NBYTES, ecies_iv_data);
    if ((sharedinfo2 != NULL) && (sharedinfo2_nbytes > 0)) {
        status |= ccgcm_aad(gcm_decrypt, gcm_ctx, sharedinfo2_nbytes, sharedinfo2);
    }
    status |= ccgcm_update(gcm_decrypt, gcm_ctx, ciphertext_nbytes, ciphertext, decrypted_message);
    cc_require(status == CCERR_OK, errOut);

#if CC_DEBUG_ECIES
    cc_print("Encrypted message", ciphertext_nbytes, ciphertext);
    cc_print("Decrypted message", ciphertext_nbytes, decrypted_message);
#endif

    // Mac (with SharedInfo 2)
    // sec1, p51: recommended: SharedInfo2 ended in a counter giving its length.
    cc_memcpy(computed_tag, received_tag, ecies->mac_length);
    status = ccgcm_finalize(gcm_decrypt, gcm_ctx, ecies->mac_length, computed_tag);

errOut:
    ccgcm_ctx_clear(gcm_decrypt->size, gcm_ctx);
    return status;
}
