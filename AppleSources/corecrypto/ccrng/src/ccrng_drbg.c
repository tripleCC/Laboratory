/* Copyright (c) (2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* This is a RNG that is deterministic from the entropy giving during init */
/* Usage is for asymmetric key generation derived from HW secret */
#include "cc_internal.h"
#include <corecrypto/ccrng_drbg.h>

int ccrng_drbg_init(struct ccrng_drbg_state *rng,
                    const struct ccdrbg_info *drbg_info,
                    struct ccdrbg_state *drbg_state,
                    size_t length,
                    const void *seed)
{
    CC_ENSURE_DIT_ENABLED

    static const char const_seed[] = "corecrypto drbg based rng";

    int err = ccdrbg_init(drbg_info, drbg_state, length, seed, length, seed, sizeof(const_seed), const_seed);
    if (err != CCERR_OK) {
        return err;
    }

    return ccrng_drbg_init_withdrbg(rng, drbg_info, drbg_state);
}

int ccrng_drbg_reseed(struct ccrng_drbg_state *rng, size_t entropylen, const void *entropy, size_t inlen, const void *in)
{
    CC_ENSURE_DIT_ENABLED

    return ccdrbg_reseed(rng->drbg_info, rng->drbg_state, entropylen, entropy, inlen, in);
}

void ccrng_drbg_done(struct ccrng_drbg_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccdrbg_done(rng->drbg_info, rng->drbg_state);
    rng->drbg_state = NULL;
}

static int generate(struct ccrng_state *rng, size_t nbytes, void *bytes)
{
    struct ccrng_drbg_state *rng_drbg = (struct ccrng_drbg_state *)rng;
    return ccdrbg_generate(rng_drbg->drbg_info, rng_drbg->drbg_state, nbytes, bytes, 0, NULL);
}

int ccrng_drbg_init_withdrbg(struct ccrng_drbg_state *rng, const struct ccdrbg_info *drbg_info, struct ccdrbg_state *drbg_state)
{
    CC_ENSURE_DIT_ENABLED

    rng->generate = generate;
    rng->drbg_info = drbg_info;
    rng->drbg_state = drbg_state;

    return CCERR_OK;
}
