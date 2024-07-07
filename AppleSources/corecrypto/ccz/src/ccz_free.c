/* Copyright (c) (2012,2015,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccz_priv.h>

void ccz_free(ccz *r) {
    CC_ENSURE_DIT_ENABLED

    if (r->isa && r->isa->ccz_free && ccz_capacity(r))
        r->isa->ccz_free(r->isa->ctx, ccz_capacity(r), r->u);
}
