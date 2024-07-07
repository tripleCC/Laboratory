/* Copyright (c) (2014-2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccn.h>
#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_rsafips_test.h>

static
int ccrng_rsafips_test_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_rsafips_test_state *thisrng = (struct ccrng_rsafips_test_state *)rng;
    const cc_unit* u= NULL;
    cc_size  n;
    cc_size  n_bytes;

    switch (thisrng->index)
    {
        case 0:
            u=thisrng->r1;
            n=thisrng->r1Len;
            break;
        case 1:
            u=thisrng->r2;
            n=thisrng->r2Len;
            break;
        case 2:
            u=thisrng->X;
            n=thisrng->XLen;
            break;
        default:
            n=0;            // It's ok
            u=thisrng->X;   // Non NULL
    }

    if (n == 0 && thisrng->next) {
        return ccrng_rsafips_test_generate((struct ccrng_state *)thisrng->next, entropy_size, entropy);
    }

    n_bytes=CC_BITLEN_TO_BYTELEN(ccn_bitlen(n, u));
    if (entropy_size<n_bytes)
    {
        return CCERR_CRYPTO_CONFIG; // Algorithm did not ask for expected length
    }
    cc_memcpy(entropy, u, n_bytes);
    cc_clear(entropy_size-n_bytes, (uint8_t *)entropy + n_bytes);
    thisrng->index++;
    return 0;
}

int
ccrng_rsafips_test_init(struct ccrng_rsafips_test_state *rng,
                      const cc_size r1Len, const cc_unit *r1,
                      const cc_size r2Len, const cc_unit *r2,
                      const cc_size XLen,  const cc_unit *X)
{
    CC_ENSURE_DIT_ENABLED

    rng->generate=ccrng_rsafips_test_generate;
    rng->index=0;
    rng->next = NULL;
    rng->r1Len=r1Len;
    rng->r1=r1;
    rng->r2Len=r2Len;
    rng->r2=r2;
    rng->XLen=XLen;
    rng->X=X;
    return 0;
}

void
ccrng_rsafips_test_set_next(struct ccrng_rsafips_test_state *rng,
                            struct ccrng_rsafips_test_state *next)
{
    CC_ENSURE_DIT_ENABLED

    rng->next = next;
}
