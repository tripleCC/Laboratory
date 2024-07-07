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

#ifndef _CORECRYPTO_CCEC448_H_
#define _CORECRYPTO_CCEC448_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccdigest.h>

CC_PTRCHECK_CAPABLE_HEADER()

typedef uint8_t ccec448key[56];
typedef ccec448key ccec448secretkey;
typedef ccec448key ccec448pubkey;
typedef ccec448key ccec448base;

typedef uint8_t cced448key[57];
typedef cced448key cced448secretkey;
typedef cced448key cced448pubkey;
typedef uint8_t cced448signature[114];

/*! @function cccurve448
 @abstract Perform X448 (ECDH).

 @param rng  An initialized RNG.
 @param out  Output shared secret or public key.
 @param sk   Input secret key.
 @param base Input basepoint.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cccurve448(struct ccrng_state *rng, ccec448key out, const ccec448secretkey sk, const ccec448base base);

/*! @function cccurve448_make_priv
 @abstract Generates a random X448 private key.

 @param rng An initialized RNG.
 @param sk  Receives a 56-byte secret key.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cccurve448_make_priv(struct ccrng_state *rng, ccec448secretkey sk);

/*! @function cccurve448_make_pub
 @abstract Creates an X448 public key from a private key.

 @param rng An initialized RNG.
 @param pk  Receives a 56-byte public key.
 @param sk  Receives a 56-byte secret key.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cccurve448_make_pub(struct ccrng_state *rng, ccec448pubkey pk, const ccec448secretkey sk);

/*! @function cccurve448_make_key_pair
 @abstract Generates a random X448 key pair.

 @param rng An initialized RNG.
 @param pk  Receives a 56-byte public key.
 @param sk  Receives a 56-byte secret key.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cccurve448_make_key_pair(struct ccrng_state *rng, ccec448pubkey pk, ccec448secretkey sk);

/*! @function cced448_make_key_pair
 @abstract Generates a random, Ed448 key pair.

 @param rng An initialized RNG.
 @param pk  Receives 57-byte public key.
 @param sk  Receives 57-byte secret key.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_make_key_pair(struct ccrng_state *rng, cced448pubkey pk, cced448secretkey sk);

/*! @function cced448_sign
 @abstract Generates a randomized Ed448 signature.

 @param rng        An initialized RNG.
 @param sig        The 114-byte signature.
 @param msg_nbytes Length of msg in bytes.
 @param msg        Data to sign.
 @param pk         57-byte public key.
 @param sk         57-byte secret key.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_sign(struct ccrng_state *rng,
                 cced448signature sig,
                 size_t msg_nbytes,
                 const uint8_t *cc_sized_by(msg_nbytes) msg,
                 const cced448pubkey pk,
                 const cced448secretkey sk);

/*! @function cced448_verify
 @abstract Verifies an Ed448 signature.

 @param msg_nbytes Length of msg in bytes.
 @param msg        Signed data to verify.
 @param sig        The 114-byte signature.
 @param pk         57-byte public key.
*/
CC_NONNULL_ALL CC_WARN_RESULT
int cced448_verify(size_t msg_nbytes,
                   const uint8_t *cc_sized_by(msg_nbytes) msg,
                   const cced448signature sig,
                   const cced448pubkey pk);

#endif /* _CORECRYPTO_CCEC448_H_ */
