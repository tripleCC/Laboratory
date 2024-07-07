/* Copyright (c) (2020,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc.h>
#include <corecrypto/ccrsa.h>

#pragma mark Ciphersuites
// 2048-bit RSA with SHA-384 as RSA-PSS Mask Generation Function and Message Hashing
extern const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa2048_sha384;
// 3072-bit RSA with SHA-384 as RSA-PSS Mask Generation Function and Message Hashing
extern const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa3072_sha384;
// 4096-bit RSA with SHA-384 as RSA-PSS Mask Generation Function and Message Hashing
extern const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa4096_sha384;

#pragma mark Signer Functions

/// Signs a blinded message.
/// @param ciphersuite The ciphersuite defining the security parameters.
/// @param key The full key used for signing.
/// @param blinded_message The blinded message to sign.
/// @param blinded_message_nbytes The length of the blinded message. This is expected to be the size in bytes of the modulus of the key.
/// @param signature The resulting blind signature.
/// @param signature_nbytes A pointer to store the resulting signature. This is expected to be the size in bytes of the modulus of the key.
/// @param blinding_rng The RNG for the blinding of the signing operations.
CC_NONNULL_ALL
int ccrsabssa_sign_blinded_message(const struct ccrsabssa_ciphersuite *ciphersuite,
                                   const ccrsa_full_ctx_t key,
                                   const uint8_t * blinded_message, const size_t blinded_message_nbytes,
                                   uint8_t *signature, const size_t signature_nbytes,
                                   struct ccrng_state *blinding_rng);

#pragma mark Blinding Functions
/// Blinds the message.
/// @param ciphersuite The ciphersuite defining the security parameters.
/// @param key The public key of the signer.
/// @param msg The message to be blinded.
/// @param msg_nbytes The length of the message to be blinded.
/// @param blinding_inverse A pointer to store the inverse of the blinding factor to unblind the signature.
/// @param blinding_inverse_nbytes The length of the blinding inverse. This is expected to be the size in bytes of the modulus of the key.
/// @param blinded_msg A pointer to store the blinded message.
/// @param blinded_msg_nbytes The length of the blinded message. This is expected to be the size in bytes of the modulus of the key.
/// @param rng The RNG to produce the blinding factor.
CC_NONNULL_ALL
int ccrsabssa_blind_message(const struct ccrsabssa_ciphersuite *ciphersuite,
                            const ccrsa_pub_ctx_t key,
                            const uint8_t *msg, const size_t msg_nbytes,
                            uint8_t *blinding_inverse, size_t blinding_inverse_nbytes,
                            uint8_t *blinded_msg, size_t blinded_msg_nbytes,
                            struct ccrng_state *rng);

/// Unblinds the signature.
/// @param ciphersuite The ciphersuite defining the security parameters.
/// @param key The public key of the signer.
/// @param blind_signature The blind signature produced by the signer.
/// @param blind_signature_nbytes The length of the blind signature. This is expected to be the size in bytes of the modulus of the key.
/// @param blinding_inverse The inverse of the blinding used for blinding the message to the signer.
/// @param blinding_inverse_nbytes The length of the blinding inverse. This is expected to be the size in bytes of the modulus of the key.
/// @param msg The message that was blindly signed.
/// @param msg_nbytes The length of the message that was blindly signed.
/// @param unblinded_signature A pointer to store the resulting unblinded signature.
/// @param unblinded_signature_nbytes This is expected to be the size in bytes of the modulus of the key.
CC_NONNULL_ALL
int ccrsabssa_unblind_signature(const struct ccrsabssa_ciphersuite *ciphersuite,
                                const ccrsa_pub_ctx_t key,
                                const uint8_t* blind_signature, const size_t blind_signature_nbytes,
                                const uint8_t* blinding_inverse, const size_t blinding_inverse_nbytes,
                                const uint8_t* msg, const size_t msg_nbytes,
                                uint8_t *unblinded_signature, const size_t unblinded_signature_nbytes);
