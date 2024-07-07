/* Copyright (c) (2012,2014-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccwrap.h>
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccwrap_internal.h"

int ccwrap_auth_decrypt(const struct ccmode_ecb *ecb_mode,
                        ccecb_ctx *ecb_key,
                        size_t nbytes,
                        const void *in,
                        size_t *obytes,
                        void *out)
{
    CC_ENSURE_DIT_ENABLED

    uint64_t iv = CCWRAP_IV;
    return ccwrap_auth_decrypt_withiv(ecb_mode,
                                      ecb_key,
                                      nbytes,
                                      in,
                                      obytes,
                                      out,
                                      &iv);
}
