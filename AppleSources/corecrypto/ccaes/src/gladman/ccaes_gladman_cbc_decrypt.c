/* Copyright (c) (2011-2013,2015-2017,2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_error.h>
#include "cc_macros.h"
#include "ccaes_internal.h"


#if !CC_KERNEL || !CC_USE_ASM

#include "gladman_aes.h"

static int ccaes_gladman_cbc_decrypt_init(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                                          size_t rawkey_len, const void *rawkey)
{
    int rc = ccaes_key_length_validation(rawkey_len);
    cc_require_or_return(rc == CCERR_OK, rc);
    ccaes_gladman_decrypt_ctx *ctx = (ccaes_gladman_decrypt_ctx *)key;
    rc = ccaes_gladman_decrypt_key(rawkey, rawkey_len, ctx);
    ctx->cbcEnable=1;
    return rc;
}

static int ccaes_gladman_cbc_decrypt(const cccbc_ctx *ctx, cccbc_iv *iv, size_t num_blks,
                                     const void *in, void *out)
{
    return ccaes_gladman_decrypt(ctx, iv, num_blks, in, out);
}

const struct ccmode_cbc ccaes_gladman_cbc_decrypt_mode = {
    .size = sizeof(ccaes_gladman_decrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_gladman_cbc_decrypt_init,
    .cbc = ccaes_gladman_cbc_decrypt,
    .custom = NULL,
};

#endif
