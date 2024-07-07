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

#include <corecrypto/ccecies.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccmode.h>
#include "ccansikdf_internal.h"
#include "ccecies_internal.h"
#include "cc_macros.h"

int ccecies_derive_gcm_key_iv(const ccecies_gcm_t ecies,
                              size_t shared_secret_nbytes,
                              const uint8_t *shared_secret,
                              size_t sharedinfo1_nbytes,
                              const void *sharedinfo1,
                              size_t exported_public_key_nbytes,
                              const uint8_t *exported_public_key,
                              uint8_t *gcm_key_iv /* output */
)
{
    size_t gcm_key_iv_nbytes = ecies->key_length + CCECIES_CIPHERIV_NBYTES;
    int status = CCERR_PARAMETER;

    // use ephemeral public key as shared info 1
    bool pubk_only = ecies->options & ECIES_EPH_PUBKEY_IN_SHAREDINFO1;
    // append shared info 1 to the public key
    bool pubk_then_s1 = ecies->options & ECIES_EPH_PUBKEY_AND_SHAREDINFO1;
    // don't allow both options to be set
    cc_require((pubk_only && pubk_then_s1) == false, errOut);
    // ECIES_EPH_PUBKEY_IN_SHAREDINFO1 ignores sharedinfo1
    cc_require(!pubk_only || sharedinfo1_nbytes == 0, errOut);
    // ECIES_EPH_PUBKEY_AND_SHAREDINFO1 wants sharedinfo1 too
    cc_require(!pubk_then_s1 || sharedinfo1_nbytes > 0, errOut);

#if CC_DEBUG_ECIES
    cc_print("Shared secret key", shared_secret_nbytes, shared_secret);
#endif

    // 4) Derive Enc / Mac key
    // Hash(shared_secret|00000001|sharedinfo1)
    if (ECIES_LEGACY_IV == (ecies->options & ECIES_LEGACY_IV)) {
        // Legacy path where IV is all zeroes
        cc_require(ecies->key_length < gcm_key_iv_nbytes, errOut);
        gcm_key_iv_nbytes = ecies->key_length;
        cc_memset(&gcm_key_iv[ecies->key_length], 0x0, CCECIES_CIPHERIV_NBYTES);
    }
    
    cc_iovec_t shared_data[2] = { 0 };
    
    unsigned int shared_data_index = 0;
    if (pubk_only || pubk_then_s1) {
        shared_data[shared_data_index].base = exported_public_key;
        shared_data[shared_data_index].nbytes = exported_public_key_nbytes;
        shared_data_index += 1;
    }
    
    if (!pubk_only || pubk_then_s1) {
        shared_data[shared_data_index].base = sharedinfo1;
        shared_data[shared_data_index].nbytes = sharedinfo1_nbytes;
        shared_data_index += 1;
    }
    
    status = ccansikdf_x963_iovec(ecies->di, shared_secret_nbytes, shared_secret, shared_data_index, shared_data, gcm_key_iv_nbytes, gcm_key_iv);
    
#if CC_DEBUG_ECIES
    cc_print("Cipher key", ecies->key_length, gcm_key_iv);
    cc_print("Cipher IV", ECIES_CIPHERIV_NBYTES, &gcm_key_iv[ecies->key_length]);
#endif
errOut:
    return status;
}
