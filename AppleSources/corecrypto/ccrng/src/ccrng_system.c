/* Copyright (c) (2010,2012-2016,2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng_system.h>
#include <corecrypto/ccrng.h>

// initialize ccrng
int ccrng_system_init(struct ccrng_system_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    struct ccrng_state *r = ccrng(&rc);
    if (r != NULL) {
        rng->generate = r->generate;
    }

    return rc;
}

void ccrng_system_done(struct ccrng_system_state *rng) {
    CC_ENSURE_DIT_ENABLED

    (void)rng;
}

