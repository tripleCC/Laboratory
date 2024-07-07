/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
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
#include "cc_macros.h"
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include "cc_absolute_time.h"

#include "cckprng_internal.h"

uint64_t (*cckprng_reseed_get_nonce_mock)(void);

// Get a nonce. NIST recommends using the time it's called as a
// nonce. We use timing information from the OS as additional Input.
static uint64_t cckprng_reseed_get_nonce(void)
{
#if CC_BUILT_FOR_TESTING
    if (cckprng_reseed_get_nonce_mock) {
        return cckprng_reseed_get_nonce_mock();
    }
#endif

    return cc_absolute_time();
}

void cckprng_reseed(struct cckprng_ctx *ctx, size_t nbytes, const void *seed)
{
    uint64_t nonce = cckprng_reseed_get_nonce();

    int err = ccrng_crypto_reseed(&ctx->rng_ctx, nbytes, seed, sizeof(nonce), &nonce);

    cc_abort_if(err != CCERR_OK, "Error reseeding kernel rng");
}
