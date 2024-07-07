/* Copyright (c) (2021) Apple Inc. All rights reserved.
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
#include "ccrng_getentropy.h"

#if CC_GETENTROPY_SUPPORTED
#include <sys/random.h>

#define GETENTROPY_MAX_NBYTES (256U)

static
int ccrng_getentropy_generate(CC_UNUSED struct ccrng_state *rng, size_t rand_nbytes, void *rand)
{
    uint8_t *chunk = rand;

    while (rand_nbytes > 0) {
        size_t chunk_nbytes = CC_MIN_EVAL(rand_nbytes, GETENTROPY_MAX_NBYTES);

        int err = getentropy(chunk, chunk_nbytes);

        cc_abort_if(err == -1, "getentropy");

        chunk += chunk_nbytes;
        rand_nbytes -= chunk_nbytes;
    }

    return CCERR_OK;
}

struct ccrng_state ccrng_getentropy = {
    .generate = ccrng_getentropy_generate
};

#endif /* CC_GETENTROPY_SUPPORTED */
