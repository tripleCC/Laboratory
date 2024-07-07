/* Copyright (c) (2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCVRF_H_
#define _CORECRYPTO_CCVRF_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccrng.h>

/*!
 * Verifiable Random Function (VRF) SPI.
 *
 * A VRF is a tuple of three algorithms, `prove`, `verify`, and `proof_to_hash`, that work
 * as follows:
 *
 *   - prove: Given secret key `sk` and message `m`, compute a `proof` of `m` using `sk`.
 *
 *   - verify: Given public key `pk`, message `m`, and proof `pi`, verify that `pi` is a valid
 *     proof for `m`, i.e., that it was computed using the holder of the private key associated
 *     with `pk`.
 *
 *   - proof_to_hash: Convert a VRF proof `pi` to an output (or hash), which is the output value
 *     of the VRF computation.
 *
 * Typical use of a VRF is to deterministically compute a PRF output (hash) of a given message, 
 * along with proof of validity. 
 */

struct ccvrf;
typedef struct ccvrf *ccvrf_t;

/*!
 * Structure that stores VRF parameter information. Clients MUST NOT
 * initialize these directly. Use one of the provided constructors below, e.g.,
 * |ccvrf_initialize_default|.
 */
struct ccvrf {
    size_t publickey_nbytes;
    size_t secretkey_nbytes;
    size_t proof_nbytes;
    size_t hash_nbytes;
    size_t group_nbytes;
    const struct ccdigest_info *di;
    const void *custom; // Opaque context for algorithm-specific data.

    /*! @function derive_public_key
        Derive a VRF public key from the secret key.
     @param context     A `ccvrf` instance.
     @param secret_key  Secret key from which to derive the public key, of length `secretkey_nbytes`.
     @param public_key  Buffer to store a public key, of size `publickey_nbytes`
     @return 0 if successful, non-zero otherwise.
     */
    int (*CC_SPTR(ccvrf, derive_public_key))(const ccvrf_t context, const uint8_t *secret_key, uint8_t *public_key);

    /*! @function prove
        Compute a VRF proof of a given message.
     @param context         A `ccvrf` instance.
     @param secret_key      VRF secret key.
     @param message         Input message for which to compute the VRF.
     @param message_nbytes  Input message length in bytes.
     @param proof           Output buffer into which the proof is stored, of size `proof_nbytes`.
     @return 0 if successful, non-zero otherwise.
     */
    int (*CC_SPTR(ccvrf, prove))(const ccvrf_t context, const uint8_t *secret_key, const uint8_t *message, size_t message_nbytes, uint8_t *proof);

    /*! @function verify
        Verify a VRF proof of a given message.
     @param context         A `ccvrf` instance.
     @param public_key      VRF public key.
     @param message         Input message for which to verify the VRF proof.
     @param message_nbytes  Input message length in bytes.
     @param proof           Message VRF proof, of size `proof_nbytes`.
     @return 0 if successful, non-zero otherwise.
     */
    int (*CC_SPTR(ccvrf, verify))(const ccvrf_t context, const uint8_t *public_key, const uint8_t *message, size_t message_nbytes, const uint8_t *proof);

    /*! @function proof_to_hash
        Compute the VRF output from a proof.
     @param context         A `ccvrf` instance.
     @param proof           Message VRF proof, of size `proof_nbytes`.
     @param hash            Message VRF output (proof hash), of size `hash_nbytes`.
     @return 0 if successful, non-zero otherwise.
     */
    int (*CC_SPTR(ccvrf, proof_to_hash))(const ccvrf_t context, const uint8_t *proof, uint8_t *hash);
};

/*!
 * @function ccvrf_factory_irtfdraft03_default
 * @abstract Initialize a |ccvrf_t| instance with the parameters and
 *    configuration for https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/.
 *
 * @param context   A `ccvrf_t` instance.
 */
CC_NONNULL((1))
void ccvrf_factory_irtfdraft03_default(ccvrf_t context);

/*!
 * @function ccvrf_factory_irtfdraft03
 * @abstract Initialize a |ccvrf_t| instance with the parameters and
 *    configuration for https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/,
 *    using a custom SHA512 implementation.
 *
 * @param context   A `ccvrf_t` instance.
 * @param di        A `struct ccdigest_info *` instance for SHA512.
 */
CC_NONNULL((1))
void ccvrf_factory_irtfdraft03(ccvrf_t context, const struct ccdigest_info *di);

/*!
 * @function ccvrf_sizeof_proof
 * @abstract Get the proof size for a given VRF, in bytes.
 *
 * @param vrf   A `ccvrf_t` instance.
 * @return The size of a serialized proof.
 */
CC_NONNULL((1))
size_t ccvrf_sizeof_proof(const ccvrf_t vrf);

/*!
 * @function ccvrf_sizeof_hash
 * @abstract Get the hash size for a given VRF, in bytes.
 *
 * @param vrf   A `ccvrf_t` instance.
 * @return The size of a hashed proof.
 */
CC_NONNULL((1))
size_t ccvrf_sizeof_hash(const ccvrf_t vrf);

/*!
 * @function ccvrf_sizeof_public_key
 * @abstract Get the public key size for a given VRF, in bytes.
 *
 * @param vrf   A `ccvrf_t` instance.
 * @return The size of a VRF public key.
 */
CC_NONNULL((1))
size_t ccvrf_sizeof_public_key(const ccvrf_t vrf);

/*!
 * @function ccvrf_sizeof_secret_key
 * @abstract Get the secret key size for a given VRF, in bytes.
 *
 * @param vrf   A `ccvrf_t` instance.
 * @return The size of a VRF secret key.
 */
CC_NONNULL((1))
size_t ccvrf_sizeof_secret_key(const ccvrf_t vrf);

/*!
 @function   ccvrf_derive_public_key
 @abstract   Derive a VRF public key from the secret key.
 @param vrf                 VRF context.
 @param secret_key_nbytes   VRF secret key length, which MUST be at least |ccvrf_sizeof_secret_key| bytes
 @param secret_key          VRF secret key buffer.
 @param public_key_nbytes   Output VRF public key length, which MUST be at least |ccvrf_sizeof_secret_key| bytes
 @param public_key          Output VRF public key buffer.
 @return 0 if no error, an error code otherwise.
 */
CC_NONNULL((1,3,5))
int ccvrf_derive_public_key(const ccvrf_t vrf, size_t secret_key_nbytes, const uint8_t *secret_key, size_t public_key_nbytes, uint8_t *public_key);

/*!
 @function   ccvrf_prove
 @abstract   Compute y = VRF(x, m), where x is derived from `secret`.
 @param vrf                 VRF context.
 @param secret_key_nbytes   VRF secret key length, which MUST be |ccvrf_sizeof_secret_key| bytes.
 @param secret_key          VRF secret key.
 @param message_nbytes      Input message length in bytes.
 @param message             Input message for which to compute the VRF.
 @param proof_nbytes        Output proof length, which MUST be |ccvrf_sizeof_proof| bytes.
 @param proof               Output proof buffer.
 @return 0 if no error, an error code otherwise.
 */
CC_NONNULL((1,3,5,7))
int ccvrf_prove(const ccvrf_t vrf, size_t secret_key_nbytes, const uint8_t *secret_key,
                size_t message_nbytes, const uint8_t *message, size_t proof_nbytes, uint8_t *proof);

/*!
 @function   ccvrf_proof_to_hash
 @abstract   Convert a VRF proof to a hash, i.e., compute the actual VRF output.
 @param vrf            VRF context.
 @param proof_nbytes   Encoded proof length, which MUST be |ccvrf_sizeof_proof| bytes.
 @param proof          Encoded proof which is to be hashed.
 @param hash_nbytes    Output hash buffer length, which MUST be at least |ccvrf_sizeof_hash| bytes.
 @param hash           Output hash buffer.
 @return 0 if no error, an error code otherwise.
 */
CC_NONNULL((1,3,5))
int ccvrf_proof_to_hash(const ccvrf_t vrf, size_t proof_nbytes, const uint8_t *proof,
                        size_t hash_nbytes, uint8_t *hash);

/*!
 @function   ccvrf_verify
 @abstract   Verify the VRF proof of a given message.
 @param vrf                 VRF context.
 @param public_key_nbytes   VRF public key length, which MUST be at least |ccvrf_sizeof_public_key| bytes.
 @param public_key          VRF public key.
 @param message_nbytes      Input message length in bytes.
 @param message             Input message for which to compute the VRF.
 @param proof_nbytes        Output proof buffer length, which MUST be at least |ccvrf_sizeof_proof|.
 @param proof               Output proof buffer.
 @return 0 if no error, an error code otherwise.
 */
CC_NONNULL((1,3,5,7))
int ccvrf_verify(const ccvrf_t vrf, size_t public_key_nbytes, const uint8_t *public_key, size_t message_nbytes,
                 const uint8_t *message, size_t proof_nbytes, const uint8_t *proof);

#endif /* _CORECRYPTO_CCVRF_H_ */
