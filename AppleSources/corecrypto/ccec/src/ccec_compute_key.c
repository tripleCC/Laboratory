/* Copyright (c) (2010,2011,2013-2016,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "cc_macros.h"
#include "cc_debug.h"

/* Compute an ECC shared secret between private_key and public_key. Return
   the result in computed_key (Conforms to EC-DH from ANSI X9.63) and the
   length of the result in bytes in *computed_key_len.  Return 0 iff
   successful.
 DEPRECATED: use ccecdh_compute_shared_secret WITH a valid RNG */
int ccec_compute_key(ccec_full_ctx_t private_key, ccec_pub_ctx_t public_key,
                     size_t *computed_key_len, uint8_t *computed_key) {
    CC_ENSURE_DIT_ENABLED


    return ccecdh_compute_shared_secret(private_key,public_key,
                                        computed_key_len,computed_key,
                                        NULL);
}
