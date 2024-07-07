/* Copyright (c) (2018,2019,2021,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include <corecrypto/ccrng.h>

int ccrng_uniform(struct ccrng_state *rng, uint64_t bound, uint64_t *rand)
{
    CC_ENSURE_DIT_ENABLED

    uint64_t mask;
    int err = CCERR_PARAMETER;

    cc_require(bound > 0, out);

    mask = UINT64_MAX >> cc_clz64(bound);

    for (;;) {
        err = ccrng_generate(rng, sizeof(*rand), rand);
        cc_require(err == CCERR_OK, out);

        *rand &= mask;
        if (*rand < bound) {
            err = CCERR_OK;
            break;
        }
    }

 out:
    if (err != CCERR_OK) {
        cc_clear(sizeof(*rand), rand);
    }

    return err;
}
