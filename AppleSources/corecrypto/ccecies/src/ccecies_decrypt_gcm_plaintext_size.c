/* Copyright (c) (2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
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
#include "ccecies_internal.h"
#include "cc_macros.h"
#include "cc_debug.h"

size_t ccecies_decrypt_gcm_plaintext_size(ccec_full_ctx_t full_key, ccecies_gcm_t ecies, size_t ciphertext_len)
{
    CC_ENSURE_DIT_ENABLED

    return ccecies_decrypt_gcm_plaintext_size_cp(ccec_ctx_cp(full_key), ecies, ciphertext_len);
}

size_t ccecies_decrypt_gcm_plaintext_size_cp(ccec_const_cp_t cp, ccecies_gcm_t ecies, size_t ciphertext_len)
{
    CC_ENSURE_DIT_ENABLED

    size_t public_key_size = 0;
    public_key_size = ccecies_pub_key_size_cp(cp, ecies);
    cc_require(public_key_size > 0, errOut);
    cc_require(ciphertext_len >= public_key_size, errOut);
    cc_require(ciphertext_len >= (public_key_size + ecies->mac_length), errOut);
    return ciphertext_len - ecies->mac_length - public_key_size;

errOut:
    return 0; // error
}
