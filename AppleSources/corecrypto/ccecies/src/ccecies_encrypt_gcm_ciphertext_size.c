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

CC_NONNULL((1, 2))
static size_t ccecies_encrypt_gcm_ciphertext_size_cp(ccec_const_cp_t cp, ccecies_gcm_t ecies, size_t plaintext_len)
{
    size_t public_key_size = 0;
    public_key_size = ccecies_pub_key_size_cp(cp, ecies);
    cc_require(public_key_size > 0, errOut);
    return public_key_size + ecies->mac_length + plaintext_len;

errOut:
    return 0; // error
}

size_t ccecies_encrypt_gcm_ciphertext_size(ccec_pub_ctx_t public_key, ccecies_gcm_t ecies, size_t plaintext_len)
{
    CC_ENSURE_DIT_ENABLED

    return ccecies_encrypt_gcm_ciphertext_size_cp(ccec_ctx_cp(public_key), ecies, plaintext_len);
}
