/* Copyright (c) (2015,2017-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccmode_siv_priv.h>
#include "ccmode_siv_internal.h"

void ccmode_factory_siv_encrypt(struct ccmode_siv *siv,
                                const struct ccmode_cbc *cbc,
                                const struct ccmode_ctr *ctr)
{
    CC_ENSURE_DIT_ENABLED

    struct ccmode_siv siv_encrypt = {
        .size = sizeof(struct _ccmode_siv_ctx),
        .block_size = 1,
        .init = ccmode_siv_init,
        .set_nonce = ccmode_siv_auth,
        .auth = ccmode_siv_auth,
        .crypt = ccmode_siv_encrypt,
        .reset = ccmode_siv_reset,
        .cbc = cbc,
        .ctr = ctr,
    };
    *siv = siv_encrypt;
}
