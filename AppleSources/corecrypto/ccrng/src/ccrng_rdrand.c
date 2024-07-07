/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
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
#include "ccrng_rdrand.h"

#if defined(__x86_64__)

static
int ccrng_rdrand_generate(CC_UNUSED struct ccrng_state *rng, size_t rand_nbytes, void *rand)
{
    uint64_t r;
    uint8_t *p = rand;

    if (CC_UNLIKELY(!CC_HAS_RDRAND())) {
        cc_clear(rand_nbytes, rand);
        return CCERR_NOT_SUPPORTED;
    }

    while (rand_nbytes > 0) {
        __asm__ __volatile__("1: rdrand %0; jnc 1b" : "=r"(r) :: "cc");

        size_t nbytes = CC_MIN_EVAL(rand_nbytes, sizeof(r));
        cc_memcpy(p, &r, nbytes);
        rand_nbytes -= nbytes;
        p += nbytes;
    }

    return CCERR_OK;
}

#else

static
int ccrng_rdrand_generate(CC_UNUSED struct ccrng_state *rng, size_t rand_nbytes, void *rand)
{
    cc_clear(rand_nbytes, rand);
    return CCERR_NOT_SUPPORTED;
}

#endif

struct ccrng_state ccrng_rdrand = {
    .generate = ccrng_rdrand_generate
};
