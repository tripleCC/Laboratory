/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCEC448_PRIV_H_
#define _CORECRYPTO_CCEC448_PRIV_H_

#include <corecrypto/ccec448.h>

/*! @function cced448_make_pub
 @abstract Creates an Ed448 public key from a private key.

 @param rng An initialized RNG.
 @param pk Output 57-byte public key.
 @param sk Input 57-byte secret key.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_make_pub(struct ccrng_state *rng, cced448pubkey pk, const cced448secretkey sk);

#endif /* _CORECRYPTO_CCEC448_PRIV_H_ */
