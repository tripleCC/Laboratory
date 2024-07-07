/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_SHARED25519_INTERNAL_H_
#define _CORECRYPTO_SHARED25519_INTERNAL_H_

#include <corecrypto/ccrng.h>

/*!
    @function   frandom / fe_random
    @abstract   Picks a random element in Z/(p).

    @param      lambda  Output for the random field element.
    @param      rng     RNG to generate random bytes.

    @return     0 for success, CCERR_INTERNAL if no random field element
                could be computed (this should really never happen).
 */
CC_NONNULL_ALL int frandom(uint8_t *lambda, struct ccrng_state *rng);

CC_INLINE
CC_NONNULL_ALL
// Copy for Ed25519's fe_* function name convention.
int fe_random(uint8_t *lambda, struct ccrng_state *rng) {
    return frandom(lambda, rng);
}

#endif /* _CORECRYPTO_SHARED25519_INTERNAL_H_ */
