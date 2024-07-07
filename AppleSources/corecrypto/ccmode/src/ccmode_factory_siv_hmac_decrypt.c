/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccmode_siv_hmac.h>
#include "ccmode_siv_hmac_internal.h"
#include <corecrypto/ccdigest.h>

void ccmode_factory_siv_hmac_decrypt(struct ccmode_siv_hmac *siv_hmac,
                                     const struct ccdigest_info *digest,
                                     const struct ccmode_ctr *ctr)
{
    struct ccmode_siv_hmac siv_hmac_decrypt = {
        .size = sizeof(struct _ccmode_siv_hmac_ctx),
        .block_size = 1,        // The number of bytes for the smallest processing block for the mode (NOT: BlockCipher size)
        .init = ccmode_siv_hmac_init,
        .set_nonce = ccmode_siv_hmac_nonce,
        .auth = ccmode_siv_hmac_auth,
        .crypt = ccmode_siv_hmac_decrypt,
        .reset = ccmode_siv_hmac_reset,
        .hmac_digest = digest,
        .ctr = ctr };
    *siv_hmac = siv_hmac_decrypt;     // Copy by value
}
