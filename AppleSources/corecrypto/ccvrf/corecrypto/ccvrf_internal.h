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

#ifndef _CORECRYPTO_CCVRF_INTERNAL_H_
#define _CORECRYPTO_CCVRF_INTERNAL_H_

#include <corecrypto/ccvrf.h>

#include "cced25519_internal.h"
#include "ccec_internal.h"

/*
 * Constants defined in https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03.
 */
#define CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN 32
#define CCVRF_IRTF_ED25519_PUBLICKEY_LEN 32
#define CCVRF_IRTF_ED25519_SECRETKEY_LEN 32
#define CCVRF_IRTF_ED25519_SEED_LEN 32
#define CCVRF_IRTF_ED25519_PROOF_LEN 80
#define CCVRF_IRTF_ED25519_HASH_LEN 64
#define CCVRF_IRTF_ED25519_GROUP_LEN 32
#define CCVRF_IRTF_ED25519_SUITE 0x04
#define CCVRF_IRTF_ED25519_ONE 0x01
#define CCVRF_IRTF_ED25519_TWO 0x02
#define CCVRF_IRTF_ED25519_THREE 0x03

/*!
 @function   ccvrf_irtf_ed25519_decode_proof
 @abstract   ECVRF_decode_proof(pi_string), as specified in https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03#section-5.4.4.
 @param pi          Input proof to decode.
 @param Gamma       Output point.
 @param c           Output scalar of length `group_nbytes/2`.
 @param s           Output scalar of length `group_nbytes`.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3, 4))
int ccvrf_irtf_ed25519_decode_proof(const uint8_t *pi, ge_p3 *Gamma, uint8_t *c, uint8_t *s);

/*!
 @function   ccvrf_irtf_ed25519_decode_proof
 @abstract   Encode a VRF proof as a `proof_nbyte` string, which reverses the decoding step as
             specified in https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03#section-5.4.4.
 @param Gamma       Input point.
 @param c           Scalar of length `group_nbytes/2`.
 @param s           Scalar of length `group_nbytes`.
 @param pi          Output buffer into which the encoded proof is written, of length `proof_nbytes`.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3, 4))
int ccvrf_irtf_ed25519_encode_proof(const ge_p3 *Gamma, const uint8_t *c, const uint8_t *s, uint8_t *pi);

/*!
 @function   ccvrf_irtf_ed25519_decode_proof
 @abstract   Decode a string of length CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN to a point, as specified in https://tools.ietf.org/html/rfc8032#section-5.1.3.
 @param point       Input point.
 @param string      Output string of length `CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN`.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2))
int ccvrf_irtf_ed25519_string_to_point(ge_p3 *point, const uint8_t *string);

/*!
 @function   ccvrf_irtf_ed25519_decode_proof
 @abstract   Encode a point in a string of length CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN, as specified in https://tools.ietf.org/html/rfc8032#section-5.1.2.
 @param string      Input string of length `CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN`.
 @param point       Output point.
 */
CC_NONNULL((1, 2))
void ccvrf_irtf_ed25519_point_to_string(uint8_t *string, const ge_p3 *point);

/*!
 @function   ccvrf_irtf_ed25519_hash2curve_elligator2
 @abstract   ECVRF_hash_to_curve_elligator2_25519(suite_string, Y, alpha_string), as specified in https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03#section-5.4.1.2.
 @param di              Hash function digest info. This MUST be SHA512.
 @param Y               Public key used to bind the hash2curve computation to a single VRF signer.
 @param message         Input message to hash to the curve.
 @param message_nbytes  Length of input message.
 @param H_string        Encoded point on the curve.
 */
CC_NONNULL((1, 2, 3, 5))
void ccvrf_irtf_ed25519_hash2curve_elligator2(const struct ccdigest_info *di, const ge_p3 *Y, const uint8_t *message, const size_t message_nbytes, uint8_t *H_string);

/*!
 @function   ccvrf_irtf_ed25519_hash_points
 @abstract   ECVRF_hash_points(P1, P2, ..., PM), as specified in https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03#section-5.4.3.
 @param vrf             VRF context.
 @param points          Pointer to array of points.
 @param points_len      Length of the points array.
 @param c_out           Output buffer where the hash value is stored, of length `group_nbytes/2`.
 */
CC_NONNULL((1, 2, 4))
void ccvrf_irtf_ed25519_hash_points(const ccvrf_t vrf, const ge_p3 **points, size_t points_len, uint8_t *c_out);

/*!
 @function   ccvrf_irtf_ed25519_derive_scalar_internal
 @abstract   Derive the secret scalar used to compute the VRF computation, according to https://tools.ietf.org/html/rfc8032#section-5.1.6.
 @param vrf             VRF context.
 @param secret          VRF secret.
 @param scalar          Output buffer for the secret scalar, of length 32B.
 @param truncated_hash  Output buffer to store the 32B trailing bytes of the `secret` hash.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3, 4))
int ccvrf_irtf_ed25519_derive_scalar_internal(const ccvrf_t vrf, const uint8_t *secret, uint8_t *scalar, uint8_t *truncated_hash);

/*!
 @function   ccvrf_irtf_ed25519_derive_public_key_internal
 @abstract   Derive the public VRF key from the corresponding secret key, according to https://tools.ietf.org/html/rfc8032#section-5.1.6.
 @param vrf             VRF context.
 @param secret          VRF secret.
 @param Y               Output public key (point).
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3))
int ccvrf_irtf_ed25519_derive_public_key_internal(const ccvrf_t vrf, const uint8_t *secret, ge_p3 *Y);

/*!
 @function   ccvrf_irtf_ed25519_derive_public_key
 @abstract   Derive a VRF public key from the secret key, according to https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03.
 @param vrf            VRF context.
 @param secret         VRF secret.
 @param public_key     VRF public key.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3))
int ccvrf_irtf_ed25519_derive_public_key(const ccvrf_t vrf, const uint8_t *secret, uint8_t *public_key);

/*!
 @function   ccvrf_irtf_ed25519_prove
 @abstract   Compute y = VRF(x, m), where x is derived from `secret`, according to https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03.
 @param vrf             VRF context.
 @param secret          VRF secret.
 @param message         Input message for which to compute the VRF.
 @param message_nbytes  Input message length in bytes.
 @param proof           Output proof buffer of length `proof_nbytes`.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3, 5))
int ccvrf_irtf_ed25519_prove(const ccvrf_t vrf, const uint8_t *secret, const uint8_t *message, size_t message_nbytes, uint8_t *proof);

/*!
 @function   ccvrf_irtf_ed25519_proof_to_hash
 @abstract   Convert a VRF proof to a hash, i.e., compute the actual VRF output, according to https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03.
 @param      vrf            VRF context.
 @param      proof          Encoded proof which is to be hashed.
 @param      beta_string    Pointer to where the hash is stored, which must be of length |ccvrf_sizeof_hash|.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3))
int ccvrf_irtf_ed25519_proof_to_hash(const ccvrf_t vrf, const uint8_t *proof, uint8_t *beta_string);

/*!
 @function   ccvrf_irtf_ed25519_verify
 @abstract   Verify the VRF proof of a given message, according to https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03.
 @param vrf             VRF context.
 @param public_key      VRF public key.
 @param message         Input message for which to compute the VRF.
 @param message_nbytes  Input message length in bytes.
 @param proof           Output proof buffer of length `proof_nbytes`.
 @return     0 if no error, an error code otherwise.
 */
CC_NONNULL((1, 2, 3, 5))
int ccvrf_irtf_ed25519_verify(const ccvrf_t vrf, const uint8_t *public_key, const uint8_t *message, size_t message_nbytes, const uint8_t *proof);

#endif /* _CORECRYPTO_CCVRF_INTERNAL_H_ */
