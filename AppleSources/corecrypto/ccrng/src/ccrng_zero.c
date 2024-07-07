/* Copyright (c) (2022) Apple Inc. All rights reserved.
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
#include "ccrng_zero.h"

static
int ccrng_zero_generate(CC_UNUSED struct ccrng_state *rng, size_t rand_nbytes, void *rand)
{
    cc_memset(rand, 0, rand_nbytes);
    return CCERR_OK;
}

struct ccrng_state ccrng_zero = {
    .generate = ccrng_zero_generate
};
