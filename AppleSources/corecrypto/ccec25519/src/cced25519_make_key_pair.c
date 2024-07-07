/* Copyright (c) (2014-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*
    Based on reference code from <http://ed25519.cr.yp.to/> and <http://bench.cr.yp.to/supercop.html>.
*/

#include "cc_internal.h"
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccec25519_priv.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include "ccrng_internal.h"
#include "cced25519_internal.h"

CC_NONNULL_ALL CC_WARN_RESULT
static int cced25519_make_pub_internal(const struct ccdigest_info *di, struct ccrng_state *rng, ccec25519pubkey pk, const ccec25519secretkey sk)
{
    cc_require_or_return(di->output_size == 64, CCERR_PARAMETER);

    uint8_t h[64];
    ccdigest(di, sizeof(ccec25519key), sk, h);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    ge_p3 A;
    ge_scalarmult_base_masked(&A, h, rng);
    ge_p3_tobytes(pk, &A);
    cc_clear(sizeof(h), h);

    return CCERR_OK;
}

int cced25519_make_pub(const struct ccdigest_info *di, ccec25519pubkey pk, const ccec25519secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    struct ccrng_state *rng = ccrng(NULL);
    cc_require_or_return(rng, CCERR_INTERNAL);

    return cced25519_make_pub_internal(di, rng, pk, sk);
}

int cced25519_make_pub_with_rng(const struct ccdigest_info *di, struct ccrng_state *rng, ccec25519pubkey pk, const ccec25519secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    return cced25519_make_pub_internal(di, rng, pk, sk);
}

int cced25519_make_key_pair(const struct ccdigest_info *di, struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk)
{
    CC_ENSURE_DIT_ENABLED

    int rv = ccrng_generate_fips(rng, sizeof(ccec25519key), sk);
    cc_require_or_return(rv == CCERR_OK, rv);

    return cced25519_make_pub_internal(di, rng, pk, sk);
}
