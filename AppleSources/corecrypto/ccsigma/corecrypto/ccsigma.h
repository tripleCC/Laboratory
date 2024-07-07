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

#ifndef _CORECRYPTO_CCSIGMA_H_
#define _CORECRYPTO_CCSIGMA_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>

// This module is a framework for implementing SIGMA protocols as
// described in "SIGMA: the 'SIGn-and-MAc' Approach to Authenticated
// Diffie-Hellman and its Use in the IKE Protocols".
//
// There are several different flavors of SIGMA. This implementation
// is intended primarily for use in SIGMA-I "sign-the-MAC" protocols.
//
// Because SIGMA is abstract, this module is abstract. To instantiate
// a concrete version, the user must provide an implementation of a
// particular protocol. This entails filling in many fields and
// function pointers in an instance of the info structure below.
//
// SIGMA is a protocol between two parties: an initiator and a
// responder. While the low-level details will differ between
// instantiations of SIGMA, the basic flow of the protocol will remain
// the same.
//
// For the initiator, the call sequence will look like:
//
//   ccsigma_init(..., CCSIGMA_ROLE_INIT, ...);
//   ccsigma_export_key_share(...);
//   ...
//   ccsigma_import_peer_key_share(...);
//   ccsigma_derive_session_keys(...);
//   ccsigma_import_peer_verification_key(...);
//   ccsigma_verify(...);
//   ccsigma_set_signing_function(...);
//   ccsigma_sign(...);
//   ...
//
// For the responder, the call sequence will look like:
//
//   ccsigma_init(..., CCSIGMA_ROLE_RESP, ...);
//   ccsigma_import_peer_key_share(...);
//   ccsigma_derive_session_keys(...);
//   ccsigma_set_signing_function(...);
//   ccsigma_sign(...);
//   ccsigma_export_key_share(...);
//   ...
//   ccsigma_import_peer_verification_key(...);
//   ccsigma_verify(...);
//   ...
//
// After deriving session keys, parties may encrypt and decrypt
// messages with the ccsigma_seal() and ccsigma_open() functions. (In
// SIGMA-I protocols, all messages apart from the public key shares
// are typically encrypted.)

// An enumeration of roles for use in SIGMA protocols.
typedef enum {
    // The SIGMA initiator.
    CCSIGMA_ROLE_INIT,

    // The SIGMA responder.
    CCSIGMA_ROLE_RESP,

    // The count of roles; this element must be last in the
    // enumeration.
    CCSIGMA_ROLE_COUNT
} ccsigma_role_t;

struct ccsigma_ctx;

// Parameters defining an instantiation of a SIGMA protocol. Note that
// any function pointers listed here should not be called directly by
// users.
struct ccsigma_info {
    // Parameters for the SIGMA key exchange; there is an implicit
    // assumption that the key exchange is based on ECDH.
    struct {
        // The elliptic curve for use in ECDH.
        ccec_const_cp_t curve_params;

        // An accessor for the local ECDH private key.
        ccec_full_ctx_t (*ctx)(struct ccsigma_ctx *ctx);

        // An accessor for the remote peer's ECDH public key.
        ccec_pub_ctx_t (*peer_ctx)(struct ccsigma_ctx *ctx);
    } key_exchange;

    // Parameters for the SIGMA signature; there is an implicit assumption
    // that the signature is based on ECDSA.
    struct {
        // The elliptic curve for use in ECDSA.
        ccec_const_cp_t curve_params;

        // The digest function for use in ECDSA.
        const struct ccdigest_info *digest_info;

        // The size (in bytes) of the ECDSA signature.
        size_t signature_size;

        // An accessor for the local ECDSA signing key.
        ccec_full_ctx_t (*ctx)(struct ccsigma_ctx *ctx);

        // An accessor for the remote peer's ECDSA verification key.
        ccec_pub_ctx_t (*peer_ctx)(struct ccsigma_ctx *ctx);
    } signature;

    // Parameters for the derivation and storage of session key
    // material. This includes initialization vectors (IVs) and may
    // include other derived fields. There is an implicit assumption
    // that all session keys are to be derived at once and stored in
    // one contiguous buffer.
    struct {
        // The count of session keys to be derived; this field
        // corresponds to the length of the below array of sizes.
        size_t count;

        // An array of sizes; the elements of this array describe the
        // subdivisions of the session key buffer. The sum of the
        // elements of this array should match the size of the buffer.
        const size_t *info;

        // The size (in bytes) of the session key buffer.
        size_t buffer_size;

        // An accessor for the session key buffer.
        void *(*buffer)(struct ccsigma_ctx *ctx);

        // A function to derive session keys given the shared secret
        // and some additional data (e.g. the session transcript).
        int (*derive)(struct ccsigma_ctx *ctx,
                      size_t shared_secret_size,
                      const void *shared_secret,
                      size_t add_data_size,
                      const void *add_data);
    } session_keys;

    // Parameters for the SIGMA MAC function.
    struct {
        // The size (in bytes) of the MAC tag.
        size_t tag_size;

        // A function to compute the MAC.
        int (*compute)(struct ccsigma_ctx *ctx,
                       size_t key_size,
                       const void *key,
                       size_t data_size,
                       const void *data,
                       void *tag);
    } mac;

    // Miscellaneous parameters for computing the SIGMA MAC and
    // signature.
    struct {
        // Indices into the session keys buffer corresponding to the
        // SIGMA handshake MAC keys. This array has two entries
        // corresponding to the two SIGMA roles.
        size_t mac_key_indices[CCSIGMA_ROLE_COUNT];

        // This API assumes a "sign-the-MAC" flavor of SIGMA. This
        // function should compute the MAC tag and a digest that
        // includes it.
        int (*compute_mac_and_digest)(struct ccsigma_ctx *ctx,
                                      ccsigma_role_t role,
                                      size_t identity_size,
                                      const void *identity,
                                      void *digest);
    } sigma;

    // Parameters for an AEAD to be used in message encryption.
    struct {
        // The size (in bytes) of the AEAD tag.
        size_t tag_size;

        // A function computing AEAD authenticated encryption.
        int (*seal)(struct ccsigma_ctx *ctx,
                    size_t key_size,
                    const void *key,
                    size_t iv_size,
                    const void *iv,
                    size_t add_data_size,
                    const void *add_data,
                    size_t ptext_size,
                    const void *ptext,
                    void *ctext,
                    void *tag);

        // A function computing AEAD authenticated decryption.
        int (*open)(struct ccsigma_ctx *ctx,
                    size_t key_size,
                    const void *key,
                    size_t iv_size,
                    const void *iv,
                    size_t add_data_size,
                    const void *add_data,
                    size_t ctext_size,
                    const void *ctext,
                    void *ptext,
                    void *tag);

        // A function to advance an IV to the next value (e.g. by
        // incrementing it).
        void (*next_iv)(size_t iv_size,
                        void *iv);
    } aead;

    // A function to erase sensitive bits of the session context.
    void (*clear)(struct ccsigma_ctx *ctx);
};

// An interface for an abstract signing implementation. This is
// provided by the user and invoked in the course of the SIGMA
// handshake.
//
// See ccsigma_set_signing_function and ccsigma_sign for full
// discussion.
typedef int (*ccsigma_sign_fn_t)(void *sign_ctx,
                                 size_t digest_nbytes,
                                 const void *digest,
                                 size_t *signature_nbytes,
                                 void *signature,
                                 struct ccrng_state *rng);

// A structure holding context for a single SIGMA session
// instance. Users typically will not instantiate this structure
// directly; instead, they will instantiate some protocol-specific
// structure that embeds this one.
struct ccsigma_ctx {
    // Parameters for the SIGMA protocol instantiation.
    const struct ccsigma_info *info;

    // The role of the local SIGMA participant.
    ccsigma_role_t role;

    // A signing implementation provided by the user.
    ccsigma_sign_fn_t sign_fn;

    // Arbitrary context for the signing implementation.
    void *sign_ctx;
};

/*!
  @function ccsigma_init
  @abstract Initialize a SIGMA session.

  @param info The SIGMA protocol parameters.
  @param ctx The context for the local session state.
  @param role The local SIGMA participant's role.
  @param rng A random number generator for use in key generation.

  @discussion This function generates its ephemeral key share eagerly.
*/
int ccsigma_init(const struct ccsigma_info *info,
                 struct ccsigma_ctx *ctx,
                 ccsigma_role_t role,
                 struct ccrng_state *rng);

/*!
  @function ccsigma_import_signing_key
  @abstract Import the SIGMA signing key

  @param ctx The context for the local session state.
  @param signing_key_size The size (in bytes) of the signing key to be imported.
  @param signing_key The local SIGMA participant's signing key to import.
*/
int ccsigma_import_signing_key(struct ccsigma_ctx *ctx,
                               size_t signing_key_size,
                               const void *signing_key);

/*!
  @function ccsigma_set_signing_function
  @abstract Set a function pointer as the signature provider

  @param ctx The context for the local session state.
  @param sign_fn A function pointer to be called to generate signatures.
  @param sign_ctx Arbitrary state that will be passed back to the signing function in each call.

  @discussion See the type definition for the expected signature of the signing function.
*/
int ccsigma_set_signing_function(struct ccsigma_ctx *ctx,
                                 ccsigma_sign_fn_t sign_fn,
                                 void *sign_ctx);

/*!
  @function ccsigma_import_peer_verification_key
  @abstract Import the SIGMA peer's verification key

  @param ctx The context for the local session state.
  @param peer_verification_key_size The size (in bytes) of the verification key to be imported.
  @param peer_verification_key The remote SIGMA peer's verification key to import.
*/
int ccsigma_import_peer_verification_key(struct ccsigma_ctx *ctx,
                                         size_t peer_verification_key_size,
                                         const void *peer_verification_key);

/*!
  @function ccsigma_export_key_share
  @abstract Export the public part of the local key share for delivery to the peer.

  @param ctx The context for the local session state.
  @param key_share_size The size (in bytes) of the exported key share.
  @param key_share The exported key share.

  @discussion The @p key_share_size parameter should be initialized with the available size of the @p key_share buffer. It will reset to the actual size of the exported key share.
*/
int ccsigma_export_key_share(struct ccsigma_ctx *ctx,
                             size_t *key_share_size,
                             void *key_share);

/*!
  @function ccsigma_import_peer_key_share
  @abstract Import the key share for the peer.

  @param ctx The context for the local session state.
  @param peer_key_share_size The size (in bytes) of the key share.
  @param peer_key_share The remote peer's key share to import.
*/
int ccsigma_import_peer_key_share(struct ccsigma_ctx *ctx,
                                  size_t peer_key_share_size,
                                  void *peer_key_share);

/*!
  @function ccsigma_derive_session_keys
  @abstract Derive session keys for use in the SIGMA protocol.

  @param ctx The context for the local session state.
  @param add_data_size The size (in bytes) of any additional data to be used in the derivation.
  @param add_data Additional data (e.g. a session transcript) to be used in the derivation.
  @param rng A random number generator to mask the key exchange.
*/
int ccsigma_derive_session_keys(struct ccsigma_ctx *ctx,
                                size_t add_data_size,
                                const void *add_data,
                                struct ccrng_state *rng);

/*!
  @function ccsigma_sign
  @abstract Generate the SIGMA signature.

  @param ctx The context for the local session state.
  @param signature The computed signature.
  @param identity_size The size (in bytes) of the local identity.
  @param identity The local identity to be included under the signature.
  @param rng A random number generator used to compute the signature.

  @discussion This function calls the user-provided signing function internally. It will pass in a message digest and expect a signature in return. Additionally, it will pass in a user-provided context argument and a handle to a random number generator; either or both of these may be ignored depending on the implementation. The implementation should check that the signature buffer is large enough to hold the generated signature, and it should resize it if the signature is smaller than expected. The implementation should return zero on success and negative on error.
*/
int ccsigma_sign(struct ccsigma_ctx *ctx,
                 void *signature,
                 size_t identity_size,
                 const void *identity,
                 struct ccrng_state *rng);

/*!
  @function ccsigma_verify
  @abstract Verify the peer's SIGMA signature.

  @param ctx The context for the local session state.
  @param signature The peer's signature to verify.
  @param peer_identity_size The size (in bytes) of the remote peer's identity.
  @param peer_identity The remote peer's identity included under the signature.
*/
int ccsigma_verify(struct ccsigma_ctx *ctx,
                   const void *signature,
                   size_t peer_identity_size,
                   const void *peer_identity);

/*!
  @function ccsigma_seal
  @abstract Encrypt a message using a session key.

  @param ctx The context for the local session state.
  @param key_index The index into the session keys buffer of the AEAD key.
  @param iv_index The index into the session keys buffer of the AEAD IV.
  @param add_data_size The size (in bytes) of the additional data.
  @param add_data Additional data to authenticate.
  @param ptext_size The size (in bytes) of the plaintext.
  @param ptext The plaintext to be encrypted.
  @param ctext The output ciphertext.
  @param tag The authentication tag.
*/
int ccsigma_seal(struct ccsigma_ctx *ctx,
                 size_t key_index,
                 size_t iv_index,
                 size_t add_data_size,
                 const void *add_data,
                 size_t ptext_size,
                 const void *ptext,
                 void *ctext,
                 void *tag);

/*!
  @function ccsigma_open
  @abstract Decrypt a message using a session key.

  @param ctx The context for the local session state.
  @param key_index The index into the session keys buffer of the AEAD key.
  @param iv_index The index into the session keys buffer of the AEAD IV.
  @param add_data_size The size (in bytes) of the additional data.
  @param add_data Additional data to authenticate.
  @param ctext_size The size (in bytes) of the ciphertext.
  @param ctext The ciphertext to be decrypted.
  @param ptext The output plaintext.
  @param tag The authentication tag to be verified.
*/
int ccsigma_open(struct ccsigma_ctx *ctx,
                 size_t key_index,
                 size_t iv_index,
                 size_t add_data_size,
                 const void *add_data,
                 size_t ctext_size,
                 const void *ctext,
                 void *ptext,
                 const void *tag);


/*!
  @function ccsigma_clear_key
  @abstract Clear a session key after it is no longer needed.

  @param ctx The context for the local session state.
  @param key_index The index of the key to clear.
*/
int ccsigma_clear_key(struct ccsigma_ctx *ctx,
                      size_t key_index);

/*!
  @function ccsigma_clear
  @abstract Clear the sensitive bits of a session.

  @param ctx The context for the local session state.
*/
void ccsigma_clear(struct ccsigma_ctx *ctx);

#endif /* _CORECRYPTO_CCSIGMA_H_ */
