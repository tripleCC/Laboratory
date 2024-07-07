/* Copyright (c) (2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdatomic.h>

#include <corecrypto/cc_priv.h>
#include "cckprng_internal.h"
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include "ccmode_internal.h"

void cckprng_initgen(CC_UNUSED struct cckprng_ctx *ctx, CC_UNUSED unsigned gen_idx)
{

}
