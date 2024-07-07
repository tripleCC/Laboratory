/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include <corecrypto/ccmode.h>

#include "ccaes_internal.h"

int ccaes_unwind_with_ecb(const struct ccmode_ecb *aesecb, size_t key_nbytes, const void *key, void *out)
{
    int ret = CCMODE_NOT_SUPPORTED;
    ccecb_ctx_decl(aesecb->size, ctx);

    cc_require(key_nbytes == CCAES_KEY_SIZE_256, out);
    cc_require(aesecb->roundkey != NULL, out);

    ret = ccecb_init(aesecb, ctx, key_nbytes, key);
    cc_require(ret == CCERR_OK, out);

    uint8_t *out_bytes = out;
    aesecb->roundkey(ctx, CCAES_NROUNDS_256, out_bytes);
    aesecb->roundkey(ctx, CCAES_NROUNDS_256 - 1, out_bytes + CCAES_ROUNDKEY_SIZE);

 out:
    cc_clear(sizeof(ctx), ctx);
    return ret;
}

int ccaes_unwind(size_t key_nbytes, const void *key, void *out)
{
    CC_ENSURE_DIT_ENABLED

    return ccaes_unwind_with_ecb(&ccaes_ltc_ecb_encrypt_mode, key_nbytes, key, out);
}
