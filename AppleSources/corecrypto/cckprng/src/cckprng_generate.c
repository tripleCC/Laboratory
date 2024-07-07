/* Copyright (c) (2018-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/cc.h>
#include "cc_macros.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include "ccmode_internal.h"
#include "cckprng_internal.h"

#include <stdatomic.h>

void cckprng_generate(struct cckprng_ctx *ctx, CC_UNUSED unsigned gen_idx, size_t nbytes, void *out)
{
    int err = ccrng_generate(&ctx->rng_ctx, nbytes, out);
    cc_abort_if(err != CCERR_OK, "cckprng_generate");
}
