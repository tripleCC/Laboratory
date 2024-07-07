/* Copyright (c) (2012,2015,2017-2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccz_priv.h>
#include <corecrypto/ccrng.h>
#include "ccprime_internal.h"

bool ccz_is_prime(const ccz *s, unsigned depth)
{
    CC_ENSURE_DIT_ENABLED

    struct ccrng_state *rng = ccrng(NULL);
    return (rng != NULL && ccprime_rabin_miller(ccz_n(s), s->u, depth, rng) == 1);
}
