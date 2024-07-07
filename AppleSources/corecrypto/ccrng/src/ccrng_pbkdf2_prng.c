/* Copyright (c) (2013-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng_pbkdf2_prng.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_priv.h>

static int ccrng_pbkdf2_prng_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_pbkdf2_prng_state *thisrng = (struct ccrng_pbkdf2_prng_state *)rng;
    if ((entropy_size)>thisrng->random_buffer_size)
    {
        return CCERR_OUT_OF_ENTROPY; // Out of random.
    }
    cc_memcpy(entropy, &thisrng->random_buffer[sizeof(thisrng->random_buffer)-thisrng->random_buffer_size], entropy_size);
    thisrng->random_buffer_size-=entropy_size;
    return 0;
}

// Remaining random data is rng->random_buffer_size" from the *end* of the buffer.
int ccrng_pbkdf2_prng_init(struct ccrng_pbkdf2_prng_state *rng, size_t maxbytes,
                           size_t passwordLen, const void *password,
                           size_t saltLen, const void *salt,
                           size_t iterations) {
    CC_ENSURE_DIT_ENABLED

    if (maxbytes>sizeof(rng->random_buffer)) {
        rng->random_buffer_size=0;
        return CCERR_PARAMETER; // Invalid parameter.
    }
    rng->random_buffer_size = maxbytes;
    rng->generate=ccrng_pbkdf2_prng_generate;
    return ccpbkdf2_hmac(ccsha256_di(), passwordLen, password, saltLen, salt,
                         iterations,
                         rng->random_buffer_size,
                         &rng->random_buffer[sizeof(rng->random_buffer)-rng->random_buffer_size]);
}

