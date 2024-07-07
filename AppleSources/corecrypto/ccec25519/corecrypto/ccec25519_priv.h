/* Copyright (c) (2017-2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCEC25519_PRIV_H_
#define _CORECRYPTO_CCEC25519_PRIV_H_

#include <corecrypto/ccec25519.h>

/*!
 @function    cced25519_make_pub
 @abstract    Creates an Ed25519 public key from a private key.

 @param      di    A 512-bit hash function.
 @param      pk    Output 32-byte public key.
 @param      sk    Input 32-byte secret key.


 @discussion Not safe for general use.
     - Public key must be stored along side the private key,
       private key should not be stored alone.
     - It may be unsafe to use a same private key with different digests
 */
CC_NONNULL_ALL
int cced25519_make_pub(const struct ccdigest_info *di, ccec25519pubkey pk, const ccec25519secretkey sk);

/*!
 @function    cced25519_make_pub_with_rng
 @abstract    Creates an Ed25519 public key from a private key.

 @param      di    A 512-bit hash function.
 @param      rng   RNG.
 @param      pk    Output 32-byte public key.
 @param      sk    Input 32-byte secret key.

 @discussion Not safe for general use.
     - Public key must be stored along side the private key,
       private key should not be stored alone.
     - It may be unsafe to use a same private key with different digests
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cced25519_make_pub_with_rng(const struct ccdigest_info *di, struct ccrng_state *rng, ccec25519pubkey pk, const ccec25519secretkey sk);

#endif /* _CORECRYPTO_CCEC25519_PRIV_H_ */
